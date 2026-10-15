/**
 * Taking a snapshot of a rig: stop it, pack its disks, keep the artifact.
 *
 * smolvm has no one operation that stops and packs, and `pack create
 * --from-vm` refuses a running machine, so the daemon owns the sequence and
 * holds the stop and the pack together for one rig (`perRig`). That lock
 * serializes captures and nothing else: the pack is a separate process, so
 * smolvm's own lifecycle lock is not held across it, and the daemon's
 * `start`, `stop`, `delete`, `exec` and file routes reach the runtime during
 * a pack without taking it. The pack is a subprocess of the `smolvm` binary
 * this host already runs: the HTTP API's only export pushes to a registry,
 * and a snapshot here never leaves the host.
 *
 * What a pack carries is the rig's disks, never its RAM, which is what makes
 * it the right artifact for Amika's snapshots: the control plane scrubs the
 * rig's credentials over `exec` before calling this, and a disk-only capture
 * is what lets that scrub mean something. Note the window it leaves: the
 * rig's agent is still running during the scrub and through the graceful
 * shutdown below, so it can write a file back after the scrub verified it
 * gone. That window exists on every provider Amika supports (none of them
 * stops the agent before capturing); it is wider here because stopping a VM
 * flushes the guest rather than freezing it.
 *
 * A capture is slow (gigabytes) and so runs in the background: the route
 * answers `202` once the name is reserved, and the store carries the
 * `capturing` → `active`/`failed` transition the control plane polls for.
 */
import { spawn as nodeSpawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { rmSync } from "node:fs";
import { RuntimeError, surfaceable } from "./machine-runtime.js";
import type { MachineRuntime } from "./machine-runtime.js";
import type { SnapshotStore } from "./snapshot-store.js";
import type { Spawn } from "./daemon.js";

export interface CaptureDeps {
  runtime: Pick<MachineRuntime, "get" | "stop">;
  store: SnapshotStore;
  /** The `smolvm` binary, which packs through the same on-disk state. */
  smolvm: string;
  /** The environment smolvm runs with; never carries the daemon's keys. */
  env: NodeJS.ProcessEnv;
  spawn?: Spawn;
  /** Reports a capture that failed after the route already answered. */
  err?: (line: string) => void;
  /** Abandons a capture once the daemon is stopping. */
  signal?: AbortSignal;
}

export interface CaptureRequest {
  /** The rig to capture. */
  rig: string;
  /** The org-scoped snapshot name, which may contain slashes. */
  name: string;
}

/**
 * Reserve the snapshot's name and start the capture. Resolves once the name
 * is held and the work is under way (which is all the route waits for),
 * handing back a `done` that settles when the capture itself has, for tests
 * and for a caller that wants to wait.
 */
export async function startCapture(
  { rig, name }: CaptureRequest,
  deps: CaptureDeps,
): Promise<{ done: Promise<void> }> {
  // Resolve the rig first, so an unknown one is a 404 before a name is taken.
  const machine = await deps.runtime.get(rig);
  const image = typeof machine.image === "string" ? machine.image : undefined;
  deps.store.reserve({ name, sourceRig: rig, image });
  return { done: perRig(rig, () => capture(rig, name, deps)) };
}

/**
 * How long one pack may take. A multi-gigabyte rig boots a helper VM, reads
 * its disks and writes a compressed artifact, so this is generous; the
 * daemon stopping cuts it short either way.
 */
export const CAPTURE_TIMEOUT_MS = 60 * 60 * 1000;

/**
 * Stop the rig, pack it, and adopt the artifact.
 *
 * Nothing awaits this: the route answered at `202` and `done` is dropped, so
 * a rejection here would be an unhandled one, which ends the process. It
 * therefore has to be total, not merely to record its own failures, because
 * recording one is disk work that fails for the same reasons the pack does
 * (a full disk fails the pack and the index write alike).
 */
async function capture(
  rig: string,
  name: string,
  deps: CaptureDeps,
): Promise<void> {
  try {
    await runCapture(rig, name, deps);
  } catch (error) {
    log(
      deps,
      `amika-hostd: snapshot ${name} failed, and so did recording it: ${failureReason(error)}`,
    );
  }
}

/**
 * The capture itself. A failure is recorded on the snapshot (which the
 * control plane reads) and logged, since the route that started this has
 * long since answered; only a failure to record one reaches `capture`.
 */
async function runCapture(
  rig: string,
  name: string,
  deps: CaptureDeps,
): Promise<void> {
  const staging = deps.store.staging();
  try {
    // `pack create -o X` writes an executable stub at X and the artifact at
    // X.smolmachine, and refuses an `-o` that already ends in `.smolmachine`.
    const stub = path.join(staging, "pack");
    await deps.runtime.stop(rig);
    await runPack(rig, stub, deps);
    deps.store.activate(name, `${stub}.smolmachine`);
  } catch (error) {
    const reason = failureReason(error);
    deps.store.fail(name, reason);
    log(deps, `amika-hostd: could not take snapshot ${name}: ${reason}`);
  } finally {
    // Best effort: the artifact is adopted by now, and a staging directory
    // that will not go away must not replace the failure just recorded.
    try {
      rmSync(staging, { recursive: true, force: true });
    } catch (error) {
      log(
        deps,
        `amika-hostd: could not clear snapshot staging: ${failureReason(error)}`,
      );
    }
  }
}

/** Log a line, never minding a logger that throws at a caller with no caller. */
function log(deps: CaptureDeps, line: string): void {
  try {
    deps.err?.(line);
  } catch {
    // A capture must not be able to take the daemon down with it.
  }
}

/**
 * Run `smolvm pack create --from-vm`, resolving when it exits cleanly. Its
 * output is captured rather than inherited: the exit status alone does not
 * say why a pack failed, and an operator reading the snapshot's
 * `errorReason` has no other way to find out.
 */
function runPack(
  rig: string,
  stub: string,
  { smolvm, env, spawn = nodeSpawn, signal }: CaptureDeps,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      smolvm,
      ["pack", "create", "--from-vm", rig, "-o", stub],
      {
        stdio: ["ignore", "pipe", "pipe"],
        // No color codes in the reason, and its own group so the daemon's
        // Ctrl-C does not reach it mid-write.
        env: { ...env, NO_COLOR: "1" },
        detached: true,
      },
    );
    let output = "";
    const keep = (chunk: Buffer | string) => {
      // Bounded: a pack prints progress, and only the tail says why it died.
      output = `${output}${chunk}`.slice(-MAX_OUTPUT_CHARS);
    };
    child.stdout?.on("data", keep);
    child.stderr?.on("data", keep);
    const timer = setTimeout(
      () => stopPack(child, "SIGKILL"),
      CAPTURE_TIMEOUT_MS,
    );
    const abort = () => stopPack(child, "SIGTERM");
    signal?.addEventListener("abort", abort, { once: true });
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    };
    child.once("error", (error) => {
      done();
      reject(new Error(`could not run ${smolvm}: ${error.message}`));
    });
    child.once("close", (code, stoppedBy) => {
      done();
      if (code === 0) return resolve();
      reject(
        new Error(
          stoppedBy
            ? `smolvm pack create was stopped (${stoppedBy})`
            : `smolvm pack create exited ${code}: ${output.trim()}`,
        ),
      );
    });
  });
}

/** The tail of a pack's output kept for a failure reason. */
const MAX_OUTPUT_CHARS = 4_000;

/**
 * Signal a pack. It runs in its own process group, so the group is signalled
 * rather than its leader alone: a pack boots a helper VM to read the rig's
 * disks, and killing only the leader leaves that helper holding them, and
 * holding the pipe `close` waits on, so the capture would never settle.
 */
function stopPack(child: ChildProcess, signal: NodeJS.Signals): void {
  try {
    if (child.pid === undefined) child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch {
    // Already gone, or never started: `close` settles the pack either way.
  }
}

/**
 * A capture failure as the snapshot records it: one line, capped, and never
 * a command or an environment value: a pack is given neither.
 */
function failureReason(error: unknown): string {
  if (error instanceof RuntimeError) {
    return (
      error.reason ?? `the rig could not be stopped (HTTP ${error.status})`
    );
  }
  const message = error instanceof Error ? error.message : String(error);
  return surfaceable(message, []) ?? "the snapshot could not be taken";
}

/**
 * One capture at a time per rig. Two captures of one rig would race each
 * other's stop and pack, and smolvm's own per-machine lock does not cover a
 * pack hostd runs itself.
 */
const inFlight = new Map<string, Promise<void>>();

function perRig(rig: string, work: () => Promise<void>): Promise<void> {
  const previous = inFlight.get(rig) ?? Promise.resolve();
  const next = previous.then(work, work);
  inFlight.set(rig, next);
  // Leave the map empty once the last capture of this rig settles, so it
  // does not grow with every rig the host has ever had. `catch` before
  // `finally`, because `finally` derives a promise that carries the same
  // rejection: nobody holds that one, and an unhandled rejection ends the
  // process. The `catch` also stands in for the caller, which drops `done`.
  void next
    .catch(() => {})
    .finally(() => {
      if (inFlight.get(rig) === next) inFlight.delete(rig);
    });
  return next;
}
