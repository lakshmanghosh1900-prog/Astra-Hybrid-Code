"""FastAPI task API with typed control routes and replayable SSE events."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import load_settings
from .persistence import StateStore
from .policy import Actor, PolicyConfig, PolicyEngine
from .runtime import Task
from .service import ServiceError, SubmitRequest, TaskService


class DenyRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2_000)


def create_service() -> TaskService:
    settings = load_settings()
    store = StateStore(settings.database_url)
    policy = PolicyEngine(PolicyConfig())
    return TaskService(store, policy)


def create_app(service: TaskService | None = None) -> FastAPI:
    task_service = service or create_service()
    api = FastAPI(title="Astra Coder", version=__version__)

    def actor_from_headers(actor_id: str | None, role: str | None) -> Actor:
        return Actor(actor_id=actor_id or "local-user", role=role or "developer")

    def handle_error(exc: ServiceError) -> HTTPException:
        status = 404 if str(exc) == "task not found" else 403
        return HTTPException(status_code=status, detail=str(exc))

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @api.post("/tasks", response_model=Task, status_code=201)
    def submit(
        request: SubmitRequest,
        x_astra_actor: str | None = Header(default=None),
        x_astra_role: str | None = Header(default=None),
    ) -> Task:
        try:
            return task_service.submit(actor_from_headers(x_astra_actor, x_astra_role), request)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.get("/tasks/{task_id}", response_model=Task)
    def status(task_id: UUID) -> Task:
        try:
            return task_service.get(task_id)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.get("/tasks/{task_id}/diff")
    def diff(task_id: UUID) -> dict[str, str]:
        try:
            return {"task_id": str(task_id), "diff": task_service.diff(task_id)}
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/tasks/{task_id}/approve", response_model=Task)
    def approve(
        task_id: UUID,
        x_astra_actor: str | None = Header(default=None),
        x_astra_role: str | None = Header(default="reviewer"),
    ) -> Task:
        try:
            return task_service.approve(actor_from_headers(x_astra_actor, x_astra_role), task_id)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/tasks/{task_id}/deny", response_model=Task)
    def deny(
        task_id: UUID,
        request: DenyRequest,
        x_astra_actor: str | None = Header(default=None),
        x_astra_role: str | None = Header(default="reviewer"),
    ) -> Task:
        try:
            return task_service.deny(
                actor_from_headers(x_astra_actor, x_astra_role), task_id, request.reason
            )
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/tasks/{task_id}/cancel", response_model=Task)
    def cancel(
        task_id: UUID,
        x_astra_actor: str | None = Header(default=None),
        x_astra_role: str | None = Header(default=None),
    ) -> Task:
        try:
            return task_service.cancel(actor_from_headers(x_astra_actor, x_astra_role), task_id)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.get("/tasks/{task_id}/events")
    async def events(task_id: UUID, after: int = Query(default=0, ge=0)) -> StreamingResponse:
        try:
            events = [event for event in task_service.events(task_id) if event.sequence > after]
        except ServiceError as exc:
            raise handle_error(exc) from exc

        async def stream() -> AsyncIterator[str]:
            for event in events:
                payload = json.dumps(event.model_dump(mode="json"), sort_keys=True)
                yield f"id: {event.sequence}\nevent: audit\ndata: {payload}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream")

    return api


app = create_app()
