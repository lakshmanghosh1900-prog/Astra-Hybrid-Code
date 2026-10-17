import type { AuditEvent } from "../lib/api";

export function EventStream({ events }: { events: AuditEvent[] }) {
  return <section className="rounded-xl border border-slate-800 bg-slate-900 p-5"><h2 className="font-semibold">Evidence stream</h2>
    {events.length === 0 ? <p className="mt-3 text-sm text-slate-400">No events recorded.</p> : <ol className="mt-3 space-y-2">{events.map((event) => <li key={event.sequence} className="border-l border-sky-500 pl-3 text-sm"><span className="text-slate-500">#{event.sequence}</span> {event.action} · <span className="text-sky-300">{event.decision}</span></li>)}</ol>}
  </section>;
}
