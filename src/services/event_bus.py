"""Event bus for real-time notifications - pure event plumbing, no business logic"""
import asyncio
from typing import Dict, List, Callable, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import uuid


@dataclass
class Event:
    """Event envelope - contains only notification data"""
    type: str
    event_id: str
    timestamp: str
    # Reference to DB record - frontend will fetch details
    reference_id: str = None
    session_id: str = None


class RealtimeEventBus:
    """
    Decoupled event bus for SSE notifications.
    
    SSE sends ONLY notifications, never full data payloads.
    Frontend subscribes to event types and fetches data from APIs.
    """
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[Event], None]]] = {}
        self._queue: asyncio.Queue = None
    
    def subscribe(self, event_type: str, callback: Callable[[Event], None]) -> None:
        """Subscribe to event type - callback receives Event objects"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
    
    def unsubscribe(self, event_type: str, callback: Callable[[Event], None]) -> None:
        """Unsubscribe from event type"""
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                c for c in self._subscribers[event_type] 
                if c != callback
            ]
    
    def publish(self, event_type: str, reference_id: str = None, 
                session_id: str = None) -> str:
        """
        Publish event - returns event_id
        No DB access, no business logic
        """
        event = Event(
            type=event_type,
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            reference_id=reference_id,
            session_id=session_id
        )
        
        # Notify sync subscribers
        if event_type in self._subscribers:
            for callback in self._subscribers[event_type]:
                try:
                    callback(event)
                except Exception:
                    pass  # Don't break other subscribers
        
        # Queue for async/SSE distribution
        if self._queue:
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                pass
        
        return event.event_id
    
    def set_queue(self, queue: asyncio.Queue) -> None:
        """Set the async queue for SSE distribution"""
        self._queue = queue


# Global singleton for the application
event_bus = RealtimeEventBus()