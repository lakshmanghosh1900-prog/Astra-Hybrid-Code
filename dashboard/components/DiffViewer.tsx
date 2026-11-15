type DiffViewerProps = {
  diff?: string;
  state: "loading" | "ready" | "error";
  error?: string;
};

export function DiffViewer({ diff, state, error }: DiffViewerProps) {
  return <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
    <h2 className="font-semibold">Diff / workspace status</h2>
    {state === "loading" && <p role="status" className="mt-3 text-sm text-slate-400">Loading task diff…</p>}
    {state === "error" && <p role="alert" className="mt-3 text-sm text-rose-300">{error}</p>}
    {state === "ready" && <pre className="mt-3 max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-300">{diff || "No diff evidence available."}</pre>}
  </section>;
}
