"""Behavior analysis API endpoints"""
from fastapi import APIRouter
from typing import List
from pydantic import BaseModel
from src.detection.behavior import classify_behavior

router = APIRouter(prefix="/behavior", tags=["detection"])

class BehaviorRequest(BaseModel):
    commands: List[str]
    latencies: List[float]

@router.post("/classify")
def classify(request: BehaviorRequest):
    """Classify attacker behavior"""
    return classify_behavior(request.commands, request.latencies)