import { afterEach, describe, expect, it, vi } from "vitest";
import { approveTask, listTasks } from "../lib/api";

afterEach(() => {
  document.cookie = "astra_dashboard_csrf=; Max-Age=0; Path=/";
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("dashboard same-origin API proxy", () => {
  it("uses the server-side proxy without a browser bearer token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, text: async () => "[]" });
    vi.stubGlobal("fetch", fetchMock);

    await expect(listTasks()).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/proxy/tasks",
      expect.objectContaining({
        credentials: "same-origin",
      }),
    );
    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(new Headers(options.headers).get("authorization")).toBeNull();
  });

  it("sends the CSRF cookie value for mutation requests", async () => {
    document.cookie = "astra_dashboard_csrf=csrf-value; Path=/";
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, text: async () => "{}" });
    vi.stubGlobal("fetch", fetchMock);

    await expect(approveTask("task-1")).resolves.toEqual({});
    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(new Headers(options.headers).get("x-astra-csrf")).toBe("csrf-value");
  });
});
