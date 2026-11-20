"""FastAPI task API with typed control routes and replayable SSE events."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import __version__
from .auth import AuthenticationError, PrincipalResolver, load_principal_resolver
from .config import Settings, load_settings
from .free_cascade import build_free_cascade_gateway
from .persistence import AuditLog, StateStore
from .policy import Actor, PolicyConfig, PolicyEngine
from .runtime import Task
from .service import ServiceError, SubmitRequest, TaskService


class DenyRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2_000)


class KillSwitchControl(BaseModel):
    enabled: bool = Field(strict=True)


def create_service(settings: Settings | None = None) -> TaskService:
    settings = settings or load_settings()
    store = StateStore(settings.database_url)
    audit = AuditLog(store)
    # Only standalone interrupted tasks belong to API startup recovery.
    # Dedicated workers recover their own running requests explicitly.
    store.recover_after_restart(audit)
    policy = PolicyEngine(PolicyConfig(repo_root=settings.repo_root))
    gateway = build_free_cascade_gateway(settings)
    return TaskService(store, policy, audit, gateway=gateway)


def create_app(
    service: TaskService | None = None,
    principal_resolver: PrincipalResolver | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    app_settings = settings or load_settings()
    task_service = service or create_service(app_settings)
    resolver = principal_resolver or load_principal_resolver(app_settings)
    api = FastAPI(title="Astra Coder", version=__version__)
    api.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001",
        ],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "Authorization",
        ],
    )

    def actor_from_authorization(authorization: str | None) -> Actor:
        try:
            return resolver.resolve(authorization)
        except AuthenticationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def handle_error(exc: ServiceError) -> HTTPException:
        message = str(exc)
        if message == "task not found":
            status = 404
        elif (
            message == "task worktree is unavailable" or "terminal" in message or "state" in message
        ):
            status = 409
        elif "authentication" in message:
            status = 401
        else:
            status = 403
        return HTTPException(status_code=status, detail=str(exc))

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @api.get("/controls/kill-switch", response_model=KillSwitchControl)
    def get_kill_switch(authorization: str | None = Header(default=None)) -> KillSwitchControl:
        try:
            return KillSwitchControl(
                enabled=task_service.get_kill_switch(actor_from_authorization(authorization))
            )
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/controls/kill-switch", response_model=KillSwitchControl)
    def set_kill_switch(
        request: KillSwitchControl, authorization: str | None = Header(default=None)
    ) -> KillSwitchControl:
        try:
            return KillSwitchControl(
                enabled=task_service.set_kill_switch(
                    actor_from_authorization(authorization), request.enabled
                )
            )
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/tasks", response_model=Task, status_code=201)
    def submit(
        request: SubmitRequest,
        authorization: str | None = Header(default=None),
    ) -> Task:
        try:
            return task_service.submit(actor_from_authorization(authorization), request)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.get("/tasks", response_model=list[Task])
    def list_tasks(authorization: str | None = Header(default=None)) -> list[Task]:
        return list(task_service.list(actor_from_authorization(authorization)))

    @api.get("/tasks/{task_id}", response_model=Task)
    def status(task_id: UUID, authorization: str | None = Header(default=None)) -> Task:
        try:
            return task_service.get(actor_from_authorization(authorization), task_id)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.get("/tasks/{task_id}/diff")
    def diff(task_id: UUID, authorization: str | None = Header(default=None)) -> dict[str, str]:
        try:
            return {
                "task_id": str(task_id),
                "diff": task_service.diff(actor_from_authorization(authorization), task_id),
            }
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/tasks/{task_id}/approve", response_model=Task)
    def approve(
        task_id: UUID,
        authorization: str | None = Header(default=None),
    ) -> Task:
        try:
            return task_service.approve(actor_from_authorization(authorization), task_id)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/tasks/{task_id}/execute", response_model=Task, status_code=202)
    def execute(
        task_id: UUID,
        authorization: str | None = Header(default=None),
    ) -> Task:
        try:
            return task_service.request_execution(actor_from_authorization(authorization), task_id)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.get("/tasks/{task_id}/result")
    def execution_result(
        task_id: UUID, authorization: str | None = Header(default=None)
    ) -> dict[str, object]:
        try:
            return task_service.execution_result(actor_from_authorization(authorization), task_id)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/tasks/{task_id}/deny", response_model=Task)
    def deny(
        task_id: UUID,
        request: DenyRequest,
        authorization: str | None = Header(default=None),
    ) -> Task:
        try:
            return task_service.deny(
                actor_from_authorization(authorization), task_id, request.reason
            )
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.post("/tasks/{task_id}/cancel", response_model=Task)
    def cancel(
        task_id: UUID,
        authorization: str | None = Header(default=None),
    ) -> Task:
        try:
            return task_service.cancel(actor_from_authorization(authorization), task_id)
        except ServiceError as exc:
            raise handle_error(exc) from exc

    @api.get("/tasks/{task_id}/events")
    async def events(
        task_id: UUID,
        after: int = Query(default=0, ge=0),
        authorization: str | None = Header(default=None),
    ) -> StreamingResponse:
        try:
            events = [
                event
                for event in task_service.events(actor_from_authorization(authorization), task_id)
                if event.sequence > after
            ]
        except ServiceError as exc:
            raise handle_error(exc) from exc

        async def stream() -> AsyncIterator[str]:
            for event in events:
                payload = json.dumps(event.model_dump(mode="json"), sort_keys=True)
                yield f"id: {event.sequence}\nevent: audit\ndata: {payload}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream")

    return api


app = create_app()
