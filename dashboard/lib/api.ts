export type TaskState =
  | "received" | "policy_checked" | "awaiting_approval" | "context_built"
  | "planned" | "editing" | "observing" | "verifying" | "reviewing"
  | "repairing" | "succeeded" | "failed" | "cancelled" | "blocked";

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

const baseUrl = process.env.NEXT_PUBLIC_ASTRA_API_URL ?? "http://127.0.0.1:8000";

export async function listTasks(): Promise<Task[]> {
  const response = await fetch(`${baseUrl}/tasks`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Task list failed (${response.status})`);
  return response.json() as Promise<Task[]>;
}

export async function approveTask(id: string): Promise<Task> {
  const response = await fetch(`${baseUrl}/tasks/${id}/approve`, {
    method: "POST",
    headers: { "X-Astra-Role": "reviewer" },
  });
  if (!response.ok) throw new Error(`Approval failed (${response.status})`);
  return response.json() as Promise<Task>;
}

export async function loadEvents(id: string): Promise<AuditEvent[]> {
  const response = await fetch(`${baseUrl}/tasks/${id}/events`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Events failed (${response.status})`);
  const text = await response.text();
  return text.split("\n\n").filter(Boolean).map((block) => {
    const data = block.split("\n").find((line) => line.startsWith("data: "))?.slice(6) ?? "{}";
    return JSON.parse(data) as AuditEvent;
  });
}
