"use client";

import { useEffect, useState } from "react";
import { approveTask, listTasks, loadEvents, type AuditEvent, type Task } from "../lib/api";
import { ApprovalInbox } from "./ApprovalInbox";
import { CostDashboard } from "./CostDashboard";
import { DiffViewer } from "./DiffViewer";
import { EventStream } from "./EventStream";
import { TaskList } from "./TaskList";

export function Dashboard() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [selected, setSelected] = useState<Task | undefined>();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string>();
  useEffect(() => { listTasks().then(setTasks).catch((reason: Error) => setError(reason.message)); }, []);
  useEffect(() => { if (selected) loadEvents(selected.id).then(setEvents).catch((reason: Error) => setError(reason.message)); }, [selected]);
  async function approve(task: Task) {
    try { const updated = await approveTask(task.id); setTasks((items) => items.map((item) => item.id === updated.id ? updated : item)); setSelected(updated); }
    catch (reason) { setError((reason as Error).message); }
  }
  return <main className="mx-auto min-h-screen max-w-7xl px-6 py-8"><header className="mb-8"><p className="text-sm uppercase tracking-[0.3em] text-sky-400">Astra Coder</p><h1 className="mt-2 text-3xl font-bold">Evidence-first engineering control plane</h1><p className="mt-2 text-slate-400">Review bounded work, policy decisions, diffs, and independent evidence.</p></header>
    {error && <p role="alert" className="mb-4 rounded border border-rose-700 bg-rose-950/40 p-3 text-rose-200">{error}</p>}
    <div className="grid gap-6 lg:grid-cols-[1fr_1.5fr]"><div className="space-y-6"><ApprovalInbox tasks={tasks} onApprove={approve} /><CostDashboard tasks={tasks} /><TaskList tasks={tasks} selected={selected?.id} onSelect={setSelected} /></div><div className="space-y-6">{selected ? <><section className="rounded-xl border border-slate-800 bg-slate-900 p-5"><p className="text-xs text-slate-500">Selected task</p><h2 className="mt-1 text-xl font-semibold">{selected.prompt}</h2><p className="mt-2 text-sm text-slate-400">{selected.repo_path}</p></section><DiffViewer diff="Diff is available from the task API." /><EventStream events={events} /></> : <section className="rounded-xl border border-dashed border-slate-700 p-12 text-center text-slate-400">Select a task to inspect evidence.</section>}</div></div>
  </main>;
}
