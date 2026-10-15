/** Taking a snapshot: stop the rig, pack it, record what happened. */
import { EventEmitter } from "node:events";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startCapture, type CaptureDeps } from "./snapshots.js";
import { openSnapshotStore, type SnapshotStore } from "./snapshot-store.js";
import { RuntimeError, type MachineInfo } from "./machine-runtime.js";
import type { Spawn } from "./daemon.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const MACHINE: MachineInfo = {
  name: "rig-1",
  image: "ghcr.io/gofixpoint/amika-coder:latest",
  state: "running",
  cpus: 2,
  memoryMb: 2048,
  ports: [],
};

/**
 * A `smolvm pack create` that writes the artifact the real one would and
 * exits with `code`. `writes: false` stands in for a pack that died before
 * producing anything; `manual` holds it open until `release()`, so a test
 * can act while it runs.
 */
function fakePack({
  code = 0,
  output = "",
  writes = true,
  manual = false,
  pid,
}: {
  code?: number;
  output?: string;
  writes?: boolean;
  manual?: boolean;
  pid?: number;
} = {}) {
  const calls: { command: string; args: readonly string[] }[] = [];
  const finish: (() => void)[] = [];
  let started: () => void;
  const spawned = new Promise<void>((resolve) => (started = resolve));
  const spawn: Spawn = (command, args) => {
    calls.push({ command, args });
    const child = new EventEmitter() as ReturnType<Spawn>;
    Object.assign(child, {
      stdout: null,
      stderr: Object.assign(new EventEmitter(), {}),
      kill: vi.fn(),
      ...(pid === undefined ? {} : { pid }),
    });
    const done = () => {
      if (output) child.stderr?.emit("data", output);
      if (writes && code === 0) {
        const stub = args[args.indexOf("-o") + 1];
        writeFileSync(`${stub}.smolmachine`, "packed bytes");
      }
      child.emit("close", code, null);
    };
    if (manual) finish.push(done);
    else queueMicrotask(done);
    started();
    return child;
  };
  return {
    spawn,
    calls,
    spawned,
    release: () => finish.splice(0).forEach((done) => done()),
  };
}

function harness(pack = fakePack()) {
  const root = mkdtempSync(path.join(tmpdir(), "amika-hostd-capture-"));
  roots.push(root);
  const store: SnapshotStore = openSnapshotStore({
    directory: path.join(root, "snapshots"),
    indexFile: path.join(root, "snapshots.json"),
  });
  const runtime = {
    get: vi.fn(async (_name: string) => MACHINE),
    stop: vi.fn(async (_name: string) => ({ ...MACHINE, state: "stopped" })),
  };
  const err = vi.fn();
  const deps: CaptureDeps = {
    runtime,
    store,
    smolvm: "/usr/local/bin/smolvm",
    env: { PATH: "/usr/bin" },
    spawn: pack.spawn,
    err,
  };
  return { deps, store, runtime, err, pack, root };
}

describe("startCapture", () => {
  it("stops the rig, packs it, and keeps the artifact", async () => {
    const { deps, store, runtime, pack } = harness();

    const { done } = await startCapture(
      { rig: "rig-1", name: "org/sandbox/nightly" },
      deps,
    );
    // The name is held before the route answers, so a second capture under
    // it is refused while this one runs.
    expect(store.get("org/sandbox/nightly")).toMatchObject({
      state: "capturing",
      sourceRig: "rig-1",
      image: "ghcr.io/gofixpoint/amika-coder:latest",
    });
    await done;

    expect(runtime.stop).toHaveBeenCalledWith("rig-1");
    expect(pack.calls).toEqual([
      {
        command: "/usr/local/bin/smolvm",
        args: [
          "pack",
          "create",
          "--from-vm",
          "rig-1",
          "-o",
          expect.stringContaining("pack"),
        ],
      },
    ]);
    expect(store.get("org/sandbox/nightly")).toMatchObject({
      state: "active",
      sizeBytes: "packed bytes".length,
    });
    expect(store.artifact("org/sandbox/nightly")).toBeDefined();
  });

  it("stops the rig before packing, which smolvm requires", async () => {
    const order: string[] = [];
    const { deps, runtime, pack } = harness();
    runtime.stop.mockImplementation(async () => {
      order.push("stop");
      return { ...MACHINE, state: "stopped" };
    });
    const spawn = pack.spawn;
    deps.spawn = (...args: Parameters<Spawn>) => {
      order.push("pack");
      return spawn(...args);
    };

    await (
      await startCapture({ rig: "rig-1", name: "org/sandbox/a" }, deps)
    ).done;
    expect(order).toEqual(["stop", "pack"]);
  });

  it("never reaches the store for a rig that is not there", async () => {
    const { deps, store, runtime } = harness();
    runtime.get.mockRejectedValue(new RuntimeError(404, "no such machine"));

    await expect(
      startCapture({ rig: "ghost", name: "org/sandbox/a" }, deps),
    ).rejects.toMatchObject({ status: 404 });
    expect(store.get("org/sandbox/a")).toBeUndefined();
  });

  it("records why a pack failed instead of throwing at nobody", async () => {
    const { deps, store, err } = harness(
      fakePack({ code: 1, output: "resize2fs not found\n" }),
    );

    // The route answered long ago, so the failure has to land on the
    // snapshot the control plane polls.
    await (
      await startCapture({ rig: "rig-1", name: "org/sandbox/a" }, deps)
    ).done;
    expect(store.get("org/sandbox/a")).toMatchObject({
      state: "failed",
      errorReason: expect.stringContaining("resize2fs not found"),
    });
    expect(store.artifact("org/sandbox/a")).toBeUndefined();
    expect(err).toHaveBeenCalledWith(
      expect.stringContaining("could not take snapshot org/sandbox/a"),
    );
  });

  it("records a rig that could not be stopped", async () => {
    const { deps, store, runtime, pack } = harness();
    runtime.stop.mockRejectedValue(
      new RuntimeError(500, "stop failed", "the guest did not confirm"),
    );

    await (
      await startCapture({ rig: "rig-1", name: "org/sandbox/a" }, deps)
    ).done;
    expect(store.get("org/sandbox/a")).toMatchObject({
      state: "failed",
      errorReason: "the guest did not confirm",
    });
    // Nothing was packed from a rig still running.
    expect(pack.calls).toEqual([]);
  });

  it("clears staging whether the pack worked or not", async () => {
    const { deps, root } = harness(fakePack({ code: 1 }));
    await (
      await startCapture({ rig: "rig-1", name: "org/sandbox/a" }, deps)
    ).done;
    expect(existsSync(path.join(root, "snapshots", ".staging"))).toBe(true);
    expect(readdirSync(path.join(root, "snapshots", ".staging"))).toEqual([]);
  });

  it("runs one capture of a rig at a time", async () => {
    const running: number[] = [];
    let peak = 0;
    const { deps, store } = harness();
    const base = deps.spawn as Spawn;
    deps.spawn = (...args: Parameters<Spawn>) => {
      running.push(1);
      peak = Math.max(peak, running.length);
      const child = base(...args);
      child.once("close", () => running.pop());
      return child;
    };

    // Two packs of one rig would race each other's stop and pack; smolvm's
    // own per-machine lock does not cover a pack hostd runs itself.
    const first = await startCapture(
      { rig: "rig-1", name: "org/sandbox/a" },
      deps,
    );
    const second = await startCapture(
      { rig: "rig-1", name: "org/sandbox/b" },
      deps,
    );
    await Promise.all([first.done, second.done]);
    expect(peak).toBe(1);
    expect(store.get("org/sandbox/a")).toMatchObject({ state: "active" });
    expect(store.get("org/sandbox/b")).toMatchObject({ state: "active" });
  });

  it("survives a failure it cannot even record", async () => {
    const { deps, store, err } = harness(fakePack({ code: 1 }));
    // A pack that fills the disk fails the index write that records it, and
    // nothing awaits a capture: a rejection here would be an unhandled one,
    // which ends the daemon.
    vi.spyOn(store, "fail").mockImplementation(() => {
      throw new Error("ENOSPC: no space left on device");
    });

    await expect(
      (await startCapture({ rig: "rig-1", name: "org/sandbox/a" }, deps)).done,
    ).resolves.toBeUndefined();
    expect(err).toHaveBeenCalledWith(
      expect.stringContaining("and so did recording it"),
    );
  });

  it("signals the pack's whole process group, not just its leader", async () => {
    // A pack boots a helper VM to read the rig's disks. Killing the leader
    // alone leaves that helper holding them and holding the pipe `close`
    // waits on, so the capture would never settle.
    const killed: number[] = [];
    const kill = vi.spyOn(process, "kill").mockImplementation((pid: number) => {
      killed.push(pid);
      return true;
    });
    try {
      const abort = new AbortController();
      const pack = fakePack({ manual: true, pid: 4242 });
      const { deps } = harness(pack);
      deps.signal = abort.signal;
      const { done } = await startCapture(
        { rig: "rig-1", name: "org/sandbox/a" },
        deps,
      );
      await pack.spawned;
      abort.abort();
      expect(killed).toEqual([-4242]);
      pack.release();
      await done;
    } finally {
      kill.mockRestore();
    }
  });

  it("never hands the pack the daemon's keys", async () => {
    const seen: NodeJS.ProcessEnv[] = [];
    const { deps } = harness();
    const base = deps.spawn as Spawn;
    deps.spawn = (command, args, options) => {
      seen.push(options.env ?? {});
      return base(command, args, options);
    };

    await (
      await startCapture({ rig: "rig-1", name: "org/sandbox/a" }, deps)
    ).done;
    // The caller hands over an environment already stripped of them; this
    // asserts nothing here puts one back.
    expect(seen[0]).toEqual({ PATH: "/usr/bin", NO_COLOR: "1" });
  });
});
