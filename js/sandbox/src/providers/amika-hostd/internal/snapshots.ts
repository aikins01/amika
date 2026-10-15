/**
 * Snapshots of rigs on an Amika host.
 *
 * hostd keeps them on the host's own disk as `.smolmachine` packs and boots a
 * rig from one by name, so this provider addresses them by name alone and
 * never carries a provider-side id (`providerSnapshotId: null`, as Daytona
 * does). Creating a rig from one needs nothing here: the control plane sends
 * the snapshot's name as the rig's image and hostd resolves it against its
 * own store (`js/amika-hostd/src/internal/requests.ts`).
 *
 * A capture is a pack of several gigabytes, far longer than any HTTP
 * deadline, so `POST /v0beta1/rigs/<rig>/snapshots` answers `202` as soon as
 * the name is taken and the snapshot carries the progress: `capturing` until
 * the artifact is on disk, then `active` or `failed`.
 */
import { z } from "zod";
import {
  SandboxProviderUnsupportedError,
  type CapturedSnapshot,
  type ProviderSnapshot,
} from "../../provider";
import {
  SmolApiError,
  machinePath,
  type SmolClient,
} from "../../smol/provider";
import { HOSTD_API_VERSION } from "./services";

/** Where a host's snapshots live, as a collection of the host rather than a rig. */
export const HOSTD_SNAPSHOTS_PATH = `/${HOSTD_API_VERSION}/snapshots`;

/**
 * A snapshot as hostd reports it, validated for the fields this reads and
 * otherwise passed through, as the machine routes do. `state` is checked
 * rather than trusted: `waitForSnapshotActive` branches on it, so a value it
 * does not know would be polled until the deadline instead of failing now.
 */
const snapshotSchema = z
  .object({
    name: z.string().min(1),
    state: z.enum(["capturing", "active", "failed"]),
    sourceRig: z.string().optional(),
    image: z.string().optional(),
    sizeBytes: z.number().optional(),
    createdAt: z.string().optional(),
    updatedAt: z.string().optional(),
    errorReason: z.string().optional(),
  })
  .loose();

type HostdSnapshot = z.infer<typeof snapshotSchema>;

export interface HostdSnapshotDeps {
  /** Addresses `/v0beta1/rigs`, for the capture that starts on a rig. */
  rigs: SmolClient;
  /** Addresses `/v0beta1/snapshots`, the host's own collection. */
  snapshots: SmolClient;
  /** Overridable so tests need not wait out a real poll. */
  pollIntervalMs?: number;
  activeTimeoutMs?: number;
}

/**
 * How long to wait for a capture to land before giving up on it. The control
 * plane treats a snapshot row untouched for 30 minutes as abandoned, so this
 * stays under that: a wait that outlived it would report success on a row
 * already reclaimed. A pack slower than this parks the control plane's row in
 * `finalizing` (not `failed`) with the source rig kept, so a later read
 * reconciles it to `active` once the artifact lands; the name is not reusable
 * in the meantime.
 */
const ACTIVE_TIMEOUT_MS = 20 * 60 * 1000;

/** Slow enough not to hammer a host that is busy packing gigabytes. */
const POLL_INTERVAL_MS = 5_000;

export function hostdSnapshots({
  rigs,
  snapshots,
  pollIntervalMs = POLL_INTERVAL_MS,
  activeTimeoutMs = ACTIVE_TIMEOUT_MS,
}: HostdSnapshotDeps) {
  const read = async (name: string): Promise<HostdSnapshot | null> => {
    try {
      return await snapshots.json(snapshotPath(name), snapshotSchema);
    } catch (error) {
      if (error instanceof SmolApiError && error.status === 404) return null;
      throw error;
    }
  };

  return {
    getSnapshot: async (name: string) => toProviderSnapshot(await read(name)),
    // hostd takes the name the moment a capture starts, so a plain read
    // already sees one that is still registering; the default
    // `findSnapshot` → `getSnapshot` fallback is right.
    deleteSnapshot: async (name: string) => {
      try {
        await snapshots.discard(snapshotPath(name), "DELETE");
      } catch (error) {
        // Deleting what is not there is done, as it is for every provider.
        if (error instanceof SmolApiError && error.status === 404) return;
        throw error;
      }
    },
    waitForSnapshotActive: async (name: string): Promise<ProviderSnapshot> => {
      const deadline = Date.now() + activeTimeoutMs;
      for (;;) {
        const snapshot = await read(name);
        if (snapshot?.state === "active") {
          return toProviderSnapshot(snapshot) as ProviderSnapshot;
        }
        if (snapshot?.state === "failed") {
          throw new Error(
            `Snapshot ${name} failed on its host${snapshot.errorReason ? `: ${snapshot.errorReason}` : ""}`,
          );
        }
        if (!snapshot) {
          throw new Error(`Snapshot ${name} is no longer on its host`);
        }
        if (Date.now() >= deadline) {
          throw new Error(
            `Snapshot ${name} was still being taken after ${Math.round(activeTimeoutMs / 60_000)} minutes`,
          );
        }
        await sleep(pollIntervalMs);
      }
    },
    /**
     * Start the capture. The rig is stopped and packed, so there is no
     * keep-running mode: `amikaHostdCapabilities.fullSnapshotCapture` is
     * false and the create-snapshot API refuses `mode: "full"` before
     * reaching here, which leaves this guard for a direct caller.
     */
    capture: async (
      providerSandboxId: string,
      snapshotName: string,
      opts: { keepSourceRunning: boolean },
    ): Promise<CapturedSnapshot> => {
      if (opts.keepSourceRunning) {
        throw new SandboxProviderUnsupportedError(
          "amika-hostd",
          "full snapshot capture",
        );
      }
      await rigs.discard(
        `${machinePath(providerSandboxId)}/snapshots`,
        "POST",
        { name: snapshotName },
      );
      // Named, never id-addressed: hostd boots a snapshot by the name the
      // control plane gave it.
      return { providerSnapshotId: null };
    },
    /**
     * Amika never puts injected secrets in a rig's create environment (they
     * are delivered at initialize time, into files the scrub removes), so a
     * host rig's environment holds nothing to scrub and a pack carries no
     * credential bindings either.
     */
    isEnvScrubbable: () => Promise.resolve(true),
  };
}

/**
 * The path a snapshot is addressed at. Amika's names are namespaced
 * (`org_abc123/sandbox/nightly`), so each segment is escaped and the
 * separators are left as separators: hostd decodes the whole remainder back
 * to the name it stored.
 */
export function snapshotPath(name: string): string {
  if (!name) throw new Error("amika-hostd requires a snapshot name");
  return `/${name.split("/").map(encodeURIComponent).join("/")}`;
}

/**
 * hostd's snapshot as the provider contract describes it, with everything
 * else it reported passed through — API responses validate the shape
 * loosely, so a host that reports more than this still surfaces it.
 */
function toProviderSnapshot(
  snapshot: HostdSnapshot | null,
): ProviderSnapshot | null {
  if (!snapshot) return null;
  return {
    ...snapshot,
    name: snapshot.name,
    providerSnapshotId: null,
    // `error` is the terminal failure every provider reports and the control
    // plane settles a capture on; hostd's own word for it is `failed`.
    state: snapshot.state === "failed" ? "error" : snapshot.state,
    ...(snapshot.image === undefined ? {} : { imageName: snapshot.image }),
    ...(snapshot.errorReason === undefined
      ? {}
      : { errorReason: snapshot.errorReason }),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
