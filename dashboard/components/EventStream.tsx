import type { AuditEvent } from "../lib/api";

type EventStreamProps = {
  events: AuditEvent[];
  state: "loading" | "snapshot" | "reconnecting" | "offline" | "error";
  error?: string;
};

export function EventStream({ events, state, error }: EventStreamProps) {
  const status = state === "loading" ? "Loading finite evidence snapshot…"
    : state === "snapshot" ? "Finite snapshot loaded · checking for new evidence"
    : state === "reconnecting" ? "Snapshot request failed · reconnecting"
    : state === "offline" ? "API offline · will retry the snapshot request"
    : error || "Evidence snapshot failed";
  return <section className="rounded-xl border border-slate-800 bg-slate-900 p-5"><div className="flex items-center justify-between gap-3"><h2 className="font-semibold">Evidence stream</h2><span className="text-xs text-slate-500">{state}</span></div>
    <p role={state === "error" ? "alert" : "status"} className={`mt-3 text-sm ${state === "error" || state === "offline" ? "text-rose-300" : "text-slate-400"}`}>{status}</p>
    {events.length === 0 ? <p className="mt-3 text-sm text-slate-400">No events recorded.</p> : <ol className="mt-3 space-y-2">{events.map((event) => <li key={event.sequence} className="border-l border-sky-500 pl-3 text-sm"><span className="text-slate-500">#{event.sequence}</span> {event.action} · <span className="text-sky-300">{event.decision}</span></li>)}</ol>}
  </section>;
}
