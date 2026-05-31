"""
VSOS Guard — Web API Integration Example
How to protect a FastAPI/Flask endpoint with VSOS Guard.
"""

from vsos_guard import VSOSGuard
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()
guard = VSOSGuard(mode="standard", log_file="guard_audit.log")


class ChatRequest(BaseModel):
    message: str
    user_id: str = "anonymous"


class ChatResponse(BaseModel):
    safe: bool
    message: str = ""
    reason: str = ""
    suggestion: str = ""


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Protected chat endpoint — VSOS Guard checks input first."""
    result = guard.check(request.message)

    if not result.safe:
        return ChatResponse(
            safe=False,
            reason=result.reason,
            suggestion=result.suggestion or "",
        )

    # Input is safe — forward to your LLM / agent
    return ChatResponse(
        safe=True,
        message=f"[LLM would process: {request.message}]",
    )
