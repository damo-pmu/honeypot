"""RabbitMQ messaging layer for resilient event processing"""
import os
import json
import asyncio
import logging
from typing import Optional, Callable, Any
from contextlib import asynccontextmanager

import aio_pika
from aio_pika import ExchangeType, Queue, Message, DeliveryMode

logger = logging.getLogger(__name__)

# Connection singleton
_connection: Optional[aio_pika.RobustConnection] = None
_channel: Optional[aio_pika.RobustChannel] = None


def get_rabbitmq_url() -> str:
    """Get RabbitMQ connection URL from environment"""
    return os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")


async def connect() -> aio_pika.RobustChannel:
    """Establish resilient RabbitMQ connection with auto-reconnect"""
    global _connection, _channel
    
    if _channel and not _channel.is_closed:
        return _channel
    
    _connection = aio_pika.RobustConnection.from_url(
        get_rabbitmq_url(),
        reconnect_interval=5,
        heartbeat=30,
    )
    
    _channel = await _connection.channel()
    await _channel.set_qos(prefetch_count=10)  # Backpressure control
    
    return _channel


async def close():
    """Gracefully close RabbitMQ connection"""
    global _connection, _channel
    
    if _channel and not _channel.is_closed:
        await _channel.close()
    if _connection and not _connection.is_closed:
        await _connection.close()


async def setup_exchange_and_queues(channel: aio_pika.RobustChannel) -> aio_pika.RobustExchange:
    """Create durable exchange and queues with DLQ"""
    # Topic exchange for event routing
    exchange = await channel.declare_exchange(
        "cowrie.events",
        ExchangeType.TOPIC,
        durable=True,
    )
    
    # Dead letter exchange
    dlq = await channel.declare_queue("cowrie.dlq", durable=True)
    
    # Main queues with DLQ configured
    queues = {
        "sessions": await channel.declare_queue(
            "cowrie.sessions",
            durable=True,
            arguments={
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": "cowrie.dlq",
            },
        ),
        "auth": await channel.declare_queue(
            "cowrie.auth",
            durable=True,
            arguments={
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": "cowrie.dlq",
            },
        ),
        "commands": await channel.declare_queue(
            "cowrie.commands",
            durable=True,
            arguments={
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": "cowrie.dlq",
            },
        ),
    }
    
    return exchange, queues, dlq


async def publish_event(event_type: str, routing_key: str, data: dict, max_retries: int = 3):
    """Publish event to RabbitMQ with persistence and retries"""
    channel = await connect()
    exchange = channel.get_exchange("cowrie.events")
    
    body = json.dumps(data).encode()
    
    for attempt in range(max_retries):
        try:
            await exchange.publish(
                Message(
                    body=body,
                    delivery_mode=DeliveryMode.PERSISTENT,
                    content_type="application/json",
                    headers={"x-event-type": event_type},
                ),
                routing_key=routing_key,
            )
            logger.debug(f"Published event to {routing_key}")
            return True
        except Exception as e:
            logger.warning(f"Publish attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
    
    logger.error(f"Failed to publish event after {max_retries} attempts: {routing_key}")
    return False


async def consume_events(
    queue_name: str,
    handler: Callable[[dict], Any],
    max_retries: int = 3,
    retry_delay_base: float = 2.0,
):
    """Consume events with manual ack/reject and retry logic"""
    channel = await connect()
    queue = channel.get_queue(queue_name)
    
    async def process_message(message: aio_pika.IncomingMessage):
        async with message.process(requeue=False):
            try:
                data = json.loads(message.body.decode())
                await handler(data)
                logger.info(f"Processed message from {queue_name}")
                
            except Exception as e:
                logger.error(f"Handler failed for {queue_name}: {e}")
                headers = message.headers or {}
                retry_count = headers.get("x-retry-count", 0)
                
                if retry_count < max_retries:
                    # Reject and requeue with incremented retry count
                    await message.nack(requeue=True)
                    logger.warning(f"Requeuing message, retry {retry_count + 1}/{max_retries}")
                else:
                    # Dead letter - move to DLQ
                    await message.reject(requeue=False)
                    logger.error(f"Message dead-lettered to cowrie.dlq")
    
    await queue.consume(process_message)
    logger.info(f"Started consuming from {queue_name}")


@asynccontextmanager
async def get_connection():
    """Context manager for RabbitMQ connection"""
    channel = await connect()
    try:
        yield channel
    finally:
        await close()