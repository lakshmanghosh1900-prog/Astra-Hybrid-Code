import { parseEventStream, type EventBatch } from "./events";

export type TaskState =
  | "received" | "policy_checked" | "awaiting_approval" | "context_built"
  | "planned" | "editing" | "observing" | "verifying" | "reviewing"
  | "repairing" | "succeeded" | "failed" | "cancelled" | "blocked";

export type TaskLifecycleState = "pending" | "running" | "succeeded" | "failed" | "cancelled";

export type Task = {
  id: string;
  prompt: string;
  repo_path: string;
  state: TaskState;
  risk: "T0" | "T1" | "T2" | "T3" | "T4";
  steps: number;
  tokens: number;
  repairs: number;
  failure_reason?: string | null;
};

export type AuditEvent = {
  sequence: number;
  action: string;
  decision: string;
  target: string;
  occurred_at: string;
  metadata: Record<string, unknown>;
};

export type TaskDiff = {
  task_id: string;
  diff: string;
};

export type ApiErrorKind = "auth" | "config" | "http" | "invalid" | "offline";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status?: number;

  constructor(message: string, kind: ApiErrorKind, status?: number) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

const DASHBOARD_API_PATH = "/api/proxy";

export function taskLifecycleState(state: TaskState): TaskLifecycleState {
  if (state === "succeeded") return "succeeded";
  if (state === "failed" || state === "blocked") return "failed";
  if (state === "cancelled") return "cancelled";
  if (state === "received" || state === "policy_checked" || state === "awaiting_approval") {
    return "pending";
  }
  return "running";
}

export function isTerminalTask(task: Task): boolean {
  return taskLifecycleState(task.state) === "succeeded"
    || taskLifecycleState(task.state) === "failed"
    || taskLifecycleState(task.state) === "cancelled";
}

function csrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  const prefix = "astra_dashboard_csrf=";
  const value = document.cookie
    .split(";")
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(prefix))
    ?.slice(prefix.length);
  return value ? decodeURIComponent(value) : undefined;
}

function explainApiFailure(status: number, detail: string): ApiError {
  const suffix = detail ? `: ${detail}` : "";
  if (status === 401 || status === 403) {
    return new ApiError(
      `Astra API authorization/session error (${status})${suffix}. Sign in again if the session expired.`,
      "auth",
      status,
    );
  }
  return new ApiError(`Astra API request failed (${status})${suffix}`, "http", status);
}

async function responseDetail(response: Response): Promise<string> {
  try {
    const body = JSON.parse(await response.text()) as { detail?: unknown };
    return typeof body.detail === "string" ? body.detail : "";
  } catch {
    return "";
  }
}

async function requestText(path: string, options: RequestInit = {}): Promise<string> {
  const headers = new Headers(options.headers);
  if (options.method?.toUpperCase() === "POST") {
    const token = csrfToken();
    if (token) headers.set("X-Astra-CSRF", token);
  }
  let response: Response;
  try {
    response = await fetch(`${DASHBOARD_API_PATH}${path}`, {
      cache: "no-store",
      credentials: "same-origin",
      ...options,
      headers,
    });
  } catch {
    throw new ApiError(
      "Astra API is offline or unreachable. Check the API URL and network connection.",
      "offline",
    );
  }

  if (!response.ok) {
    throw explainApiFailure(response.status, await responseDetail(response));
  }
  return response.text();
}

async function requestJson<T>(path: string, options: RequestInit = {}): Promise<T> {
  const text = await requestText(path, options);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError("Astra API returned invalid JSON.", "invalid");
  }
}

export function errorMessage(reason: unknown): string {
  return reason instanceof Error ? reason.message : "The Astra API request failed.";
}

export function isOfflineError(reason: unknown): boolean {
  return reason instanceof ApiError && reason.kind === "offline";
}

export async function listTasks(): Promise<Task[]> {
  return requestJson<Task[]>("/tasks");
}

export async function getTaskDiff(id: string): Promise<TaskDiff> {
  return requestJson<TaskDiff>(`/tasks/${encodeURIComponent(id)}/diff`);
}

export async function approveTask(id: string): Promise<Task> {
  return requestJson<Task>(`/tasks/${encodeURIComponent(id)}/approve`, { method: "POST" });
}

export async function denyTask(id: string, reason: string): Promise<Task> {
  return requestJson<Task>(`/tasks/${encodeURIComponent(id)}/deny`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
}

export async function cancelTask(id: string): Promise<Task> {
  return requestJson<Task>(`/tasks/${encodeURIComponent(id)}/cancel`, { method: "POST" });
}

export async function loadEvents(id: string, after = 0): Promise<EventBatch> {
  const text = await requestText(
    `/tasks/${encodeURIComponent(id)}/events?after=${encodeURIComponent(String(after))}`,
    { headers: { Accept: "text/event-stream" } },
  );
  return parseEventStream(text, after);
}
