"use client";

import { useCallback, useEffect, useState } from "react";
import {
  approveTask,
  cancelTask,
  denyTask,
  errorMessage,
  getTaskDiff,
  isOfflineError,
  isTerminalTask,
  listTasks,
  loadEvents,
  type AuditEvent,
  type Task,
} from "../lib/api";
import { mergeEvents, reconnectDelay } from "../lib/events";
import { ApprovalInbox, type PendingAction } from "./ApprovalInbox";
import { CostDashboard } from "./CostDashboard";
import { DiffViewer } from "./DiffViewer";
import { EventStream } from "./EventStream";
import { TaskList } from "./TaskList";

type TaskLoadState = "loading" | "ready" | "error";
type DiffState = "loading" | "ready" | "error";
type EventState = "loading" | "snapshot" | "reconnecting" | "offline";
type TaskOperation = PendingAction["operation"];

const EVENT_POLL_INTERVAL = 5_000;

export function Dashboard() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [taskLoadState, setTaskLoadState] = useState<TaskLoadState>("loading");
  const [selectedId, setSelectedId] = useState<string>();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [eventState, setEventState] = useState<EventState>("loading");
  const [eventError, setEventError] = useState<string>();
  const [diff, setDiff] = useState<string>();
  const [diffState, setDiffState] = useState<DiffState>("loading");
  const [diffError, setDiffError] = useState<string>();
  const [error, setError] = useState<string>();
  const [offline, setOffline] = useState(false);
  const [pendingAction, setPendingAction] = useState<PendingAction>();
  const [selectedDenyReason, setSelectedDenyReason] = useState("");
  const selected = tasks.find((task) => task.id === selectedId);

  const refreshTasks = useCallback(async () => {
    setTaskLoadState("loading");
    try {
      setTasks(await listTasks());
      setTaskLoadState("ready");
      setError(undefined);
      setOffline(false);
    } catch (reason) {
      setTaskLoadState("error");
      setError(errorMessage(reason));
      setOffline(isOfflineError(reason));
    }
  }, []);

  useEffect(() => {
    void refreshTasks();
  }, [refreshTasks]);

  useEffect(() => {
    const markOnline = () => setOffline(false);
    const markOffline = () => setOffline(true);
    if (typeof navigator !== "undefined" && !navigator.onLine) setOffline(true);
    window.addEventListener("online", markOnline);
    window.addEventListener("offline", markOffline);
    return () => {
      window.removeEventListener("online", markOnline);
      window.removeEventListener("offline", markOffline);
    };
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    let active = true;
    let cursor = 0;
    let retryAttempt = 0;
    let firstEventRequest = true;
    let timer: ReturnType<typeof setTimeout> | undefined;

    setDiff(undefined);
    setDiffState("loading");
    setDiffError(undefined);
    setEvents([]);
    setEventState("loading");
    setEventError(undefined);

    void getTaskDiff(selectedId).then((result) => {
      if (!active) return;
      setDiff(result.diff);
      setDiffState("ready");
      setOffline(false);
    }).catch((reason: unknown) => {
      if (!active) return;
      const message = errorMessage(reason);
      setDiffState("error");
      setDiffError(message);
      setError(message);
      setOffline(isOfflineError(reason));
    });

    const pollEvents = async (): Promise<void> => {
      if (!active) return;
      if (!firstEventRequest) setEventState("reconnecting");
      try {
        const batch = await loadEvents(selectedId, cursor);
        if (!active) return;
        setEvents((current) => mergeEvents(current, batch.events));
        cursor = Math.max(cursor, batch.cursor);
        retryAttempt = 0;
        firstEventRequest = false;
        setEventState("snapshot");
        setEventError(undefined);
        setOffline(false);
        timer = setTimeout(() => void pollEvents(), EVENT_POLL_INTERVAL);
      } catch (reason) {
        if (!active) return;
        const message = errorMessage(reason);
        retryAttempt += 1;
        firstEventRequest = false;
        setEventError(message);
        setEventState(isOfflineError(reason) ? "offline" : "reconnecting");
        setError(message);
        setOffline(isOfflineError(reason));
        timer = setTimeout(() => void pollEvents(), reconnectDelay(retryAttempt));
      }
    };

    void pollEvents();
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [selectedId]);

  const runTaskOperation = useCallback(async (operation: TaskOperation, task: Task, reason = "") => {
    if (operation === "deny" && !reason.trim()) {
      setError("A denial reason is required.");
      return;
    }
    setPendingAction({ taskId: task.id, operation });
    try {
      const updated = operation === "approve"
        ? await approveTask(task.id)
        : operation === "deny"
          ? await denyTask(task.id, reason.trim())
          : await cancelTask(task.id);
      setTasks((items) => items.map((item) => item.id === updated.id ? updated : item));
      setSelectedId(updated.id);
      setSelectedDenyReason("");
      setError(undefined);
      setOffline(false);
    } catch (failure) {
      setError(errorMessage(failure));
      setOffline(isOfflineError(failure));
    } finally {
      setPendingAction(undefined);
    }
  }, []);

  return <main className="mx-auto min-h-screen max-w-7xl px-6 py-8">
    <header className="mb-8"><p className="text-sm uppercase tracking-[0.3em] text-sky-400">Astra Coder</p><h1 className="mt-2 text-3xl font-bold">Evidence-first engineering control plane</h1><p className="mt-2 text-slate-400">Review bounded work, policy decisions, diffs, and independent evidence.</p></header>
    {offline && <p role="status" className="mb-4 rounded border border-amber-700 bg-amber-950/40 p-3 text-amber-200">The Astra API is offline. Snapshot requests will retry automatically.</p>}
    {error && <p role="alert" className="mb-4 rounded border border-rose-700 bg-rose-950/40 p-3 text-rose-200">{error}{taskLoadState === "error" && <button onClick={() => void refreshTasks()} className="ml-3 underline">Retry</button>}</p>}
    {taskLoadState === "loading" && <p role="status" className="mb-4 rounded border border-slate-800 p-4 text-slate-400">Loading tasks…</p>}
    <div className="grid gap-6 lg:grid-cols-[1fr_1.5fr]">
      <div className="space-y-6">
        <ApprovalInbox
          tasks={tasks}
          onApprove={(task) => void runTaskOperation("approve", task)}
          onDeny={(task, reason) => void runTaskOperation("deny", task, reason)}
          pendingAction={pendingAction}
        />
        <CostDashboard tasks={tasks} />
        {taskLoadState !== "loading" && <TaskList tasks={tasks} selected={selectedId} onSelect={(task) => setSelectedId(task.id)} />}
      </div>
      <div className="space-y-6">
        {selected ? <>
          <section className="rounded-xl border border-slate-800 bg-slate-900 p-5"><p className="text-xs text-slate-500">Selected task</p><h2 className="mt-1 text-xl font-semibold">{selected.prompt}</h2><p className="mt-2 text-sm text-slate-400">{selected.repo_path}</p>{selected.failure_reason && <p className="mt-2 text-sm text-rose-300">{selected.failure_reason}</p>}
            <div className="mt-4 flex flex-wrap items-center gap-2">
              {selected.state === "awaiting_approval" && <><input aria-label="Selected task denial reason" value={selectedDenyReason} onChange={(event) => setSelectedDenyReason(event.target.value)} placeholder="Reason for denial" className="min-w-56 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm" /><button disabled={!selectedDenyReason.trim() || Boolean(pendingAction)} onClick={() => void runTaskOperation("deny", selected, selectedDenyReason)} className="rounded-md border border-rose-700 px-3 py-2 text-sm text-rose-200 hover:bg-rose-950/50 disabled:cursor-not-allowed disabled:opacity-60">{pendingAction?.operation === "deny" ? "Denying…" : "Deny"}</button></>}
              {!isTerminalTask(selected) && <button disabled={Boolean(pendingAction)} onClick={() => void runTaskOperation("cancel", selected)} className="rounded-md border border-slate-600 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:cursor-wait disabled:opacity-60">{pendingAction?.operation === "cancel" ? "Cancelling…" : "Cancel task"}</button>}
            </div>
          </section>
          <DiffViewer diff={diff} state={diffState} error={diffError} />
          <EventStream events={events} state={eventState} error={eventError} />
        </> : <section className="rounded-xl border border-dashed border-slate-700 p-12 text-center text-slate-400">Select a task to inspect evidence.</section>}
      </div>
    </div>
  </main>;
}
