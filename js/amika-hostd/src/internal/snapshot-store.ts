/**
 * The snapshots this host holds: `.smolmachine` artifacts on its own disk,
 * and the index that names them.
 *
 * A snapshot is a disk-only pack of a rig (`smolvm pack create --from-vm`),
 * kept locally rather than pushed anywhere: an org's rigs on its own hosts
 * never leave the host, and neither do their snapshots. `snapshots.json`
 * beside the daemon's other state records one entry per snapshot; the
 * artifacts live in their own directory, which an operator can point at a
 * larger disk (`snapshot_dir`), since each one is gigabytes.
 *
 * Amika's snapshot names carry slashes (`org_abc123/sandbox/nightly`), so a
 * name is never a path component here: every artifact's filename is derived
 * from a slug plus a digest of the full name (`artifactFileName`), which
 * makes traversal impossible by construction rather than by validation. The
 * index is the only thing that maps a name to its file.
 */
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { z } from "zod";
import { writePrivateFile } from "./private-file.js";

/**
 * Where a snapshot is in its life. A capture reserves the name first and
 * writes the artifact afterwards, so a `capturing` entry holds a name
 * without yet holding a bootable file; only `active` can be booted.
 */
export type SnapshotState = "capturing" | "active" | "failed";

/** A snapshot as the API reports it. */
export interface SnapshotInfo {
  name: string;
  state: SnapshotState;
  /** The rig it was captured from, kept after that rig is gone. */
  sourceRig: string;
  /** What that rig booted, for provenance; absent on older entries. */
  image?: string;
  /** The artifact's size, once it exists. */
  sizeBytes?: number;
  createdAt: string;
  updatedAt: string;
  /** Why a capture failed, safe to surface (never a command or env value). */
  errorReason?: string;
}

/** Raised when a name is already taken by a live snapshot. */
export class SnapshotConflictError extends Error {
  override name = "SnapshotConflictError";
}

/** Raised when a name could never be a snapshot's. */
export class SnapshotNameError extends Error {
  override name = "SnapshotNameError";
}

export interface SnapshotStore {
  list(): SnapshotInfo[];
  get(name: string): SnapshotInfo | undefined;
  /**
   * The artifact path of an `active` snapshot, or undefined when the name is
   * unknown, still capturing, or its file has gone missing underneath us.
   */
  artifact(name: string): string | undefined;
  /**
   * Take `name` for a capture about to start. Refuses a name a live snapshot
   * holds; a `failed` one is replaced, which is the retry path.
   */
  reserve(input: { name: string; sourceRig: string; image?: string }): void;
  /** Record a finished capture, adopting `stagedArtifact` as the snapshot. */
  activate(name: string, stagedArtifact: string): SnapshotInfo;
  /** Record a capture that did not finish. The name stays taken, as failed. */
  fail(name: string, reason: string): void;
  /** Remove a snapshot and its artifact. False when there was none. */
  remove(name: string): boolean;
  /** A private directory for a capture to stage its artifact in. */
  staging(): string;
  /**
   * Whether a capture holds `rig`: from the moment its name is reserved
   * until the snapshot is `active` or `failed`.
   */
  isCapturing(rig: string): boolean;
}

export interface SnapshotStoreOptions {
  /** Holds the artifacts; made owner-only, created when missing. */
  directory: string;
  /** The index, `snapshots.json`, normally beside the daemon's other state. */
  indexFile: string;
}

/**
 * Open the store, sweeping what an interrupted run left behind: a capture
 * that was still running when the daemon stopped can never finish, so its
 * entry becomes `failed`, and an entry whose artifact has vanished is
 * dropped outright. Staging directories are removed with it.
 */
export function openSnapshotStore({
  directory,
  indexFile,
}: SnapshotStoreOptions): SnapshotStore {
  ensurePrivate(directory);
  const index = readIndex(indexFile);
  const save = () => writeIndex(indexFile, index);
  let swept = false;
  for (const [name, entry] of index.snapshots) {
    if (entry.state === "capturing") {
      index.snapshots.set(name, {
        ...entry,
        state: "failed",
        errorReason: "the daemon stopped while this snapshot was being taken",
        updatedAt: new Date().toISOString(),
      });
      swept = true;
    } else if (
      entry.state === "active" &&
      fileSize(artifactPath(entry)) === undefined
    ) {
      index.snapshots.delete(name);
      swept = true;
    }
  }
  if (swept) save();
  rmSync(stagingRoot(directory), { recursive: true, force: true });

  const info = (entry: SnapshotEntry): SnapshotInfo => ({
    name: entry.name,
    state: entry.state,
    sourceRig: entry.sourceRig,
    ...(entry.image === undefined ? {} : { image: entry.image }),
    ...(entry.sizeBytes === undefined ? {} : { sizeBytes: entry.sizeBytes }),
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
    ...(entry.errorReason === undefined
      ? {}
      : { errorReason: entry.errorReason }),
  });

  return {
    list: () =>
      [...index.snapshots.values()]
        .map(info)
        .sort((a, b) => a.name.localeCompare(b.name)),
    get: (name) => {
      const entry = index.snapshots.get(name);
      return entry && info(entry);
    },
    artifact: (name) => {
      const entry = index.snapshots.get(name);
      if (!entry || entry.state !== "active") return undefined;
      const file = artifactPath(entry);
      return fileSize(file) === undefined ? undefined : file;
    },
    reserve: ({ name, sourceRig, image }) => {
      const existing = index.snapshots.get(validName(name));
      if (existing && existing.state !== "failed") {
        throw new SnapshotConflictError(
          existing.state === "capturing"
            ? `snapshot ${JSON.stringify(name)} is already being taken`
            : `snapshot ${JSON.stringify(name)} already exists`,
        );
      }
      // A failed entry is replaced, so its artifact (if a later failure left
      // one) never outlives the entry that named it.
      if (existing) removeArtifact(existing);
      const now = new Date().toISOString();
      index.snapshots.set(name, {
        name,
        file: artifactFileName(name),
        directory,
        state: "capturing",
        sourceRig,
        image,
        createdAt: now,
        updatedAt: now,
      });
      save();
    },
    activate: (name, stagedArtifact) => {
      const entry = held(index, name);
      const destination = artifactPath(entry);
      mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
      // Staging sits under the artifact directory, so this is a rename
      // within one filesystem and the artifact appears whole or not at all.
      adopt(stagedArtifact, destination);
      const next: SnapshotEntry = {
        ...entry,
        state: "active",
        sizeBytes: fileSize(destination),
        updatedAt: new Date().toISOString(),
        errorReason: undefined,
      };
      index.snapshots.set(name, next);
      save();
      return info(next);
    },
    fail: (name, reason) => {
      const entry = index.snapshots.get(name);
      if (!entry) return;
      removeArtifact(entry);
      index.snapshots.set(name, {
        ...entry,
        state: "failed",
        sizeBytes: undefined,
        errorReason: reason,
        updatedAt: new Date().toISOString(),
      });
      save();
    },
    remove: (name) => {
      const entry = index.snapshots.get(name);
      if (!entry) return false;
      removeArtifact(entry);
      index.snapshots.delete(name);
      save();
      return true;
    },
    staging: () => {
      const dir = path.join(
        stagingRoot(directory),
        createHash("sha256")
          .update(`${process.pid}:${Date.now()}:${Math.random()}`)
          .digest("hex")
          .slice(0, 16),
      );
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      return dir;
    },
    isCapturing: (rig) =>
      [...index.snapshots.values()].some(
        (entry) => entry.state === "capturing" && entry.sourceRig === rig,
      ),
  };
}

/**
 * The longest a snapshot name may be. Amika's own are well under this
 * (`<org id>/sandbox/<80-char slug>`); the cap is here so a name can never
 * make the index unwieldy or the derived filename unusable.
 */
const MAX_NAME_LENGTH = 200;

/**
 * A name that can be a snapshot's: non-empty, printable, no control
 * characters, and no path traversal even though the artifact's filename is
 * derived rather than taken from it. Slashes are kept, since Amika namespaces
 * snapshots as `<org id>/sandbox/<label>`.
 */
export function validName(name: string): string {
  const parsed = z
    .string()
    .min(1)
    .max(MAX_NAME_LENGTH)
    // eslint-disable-next-line no-control-regex
    .refine((value) => !/[\u0000-\u001f\u007f]/.test(value))
    .refine(
      (value) =>
        !value.split("/").some((part) => part === "." || part === ".."),
    )
    .refine((value) => !value.startsWith("/") && !value.endsWith("/"))
    .safeParse(name);
  if (!parsed.success) {
    throw new SnapshotNameError(
      `invalid snapshot name ${JSON.stringify(name)}`,
    );
  }
  return parsed.data;
}

/** One snapshot as the index stores it. */
interface SnapshotEntry extends Omit<SnapshotInfo, "image" | "sizeBytes"> {
  /** The artifact's filename, derived from the name when it was reserved. */
  file: string;
  /** Where that file lives, so moving `snapshot_dir` leaves old ones findable. */
  directory: string;
  image?: string;
  sizeBytes?: number;
}

const entrySchema = z.object({
  name: z.string().min(1),
  file: z.string().min(1),
  directory: z.string().min(1),
  state: z.enum(["capturing", "active", "failed"]),
  sourceRig: z.string(),
  image: z.string().optional(),
  sizeBytes: z.number().int().nonnegative().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
  errorReason: z.string().optional(),
});

const indexSchema = z.object({
  snapshots: z.array(entrySchema).default([]),
});

interface SnapshotIndex {
  snapshots: Map<string, SnapshotEntry>;
}

/** A missing or unreadable index is an empty one, as `prepull.json` is. */
function readIndex(file: string): SnapshotIndex {
  try {
    const parsed = indexSchema.parse(JSON.parse(readFileSync(file, "utf8")));
    return {
      snapshots: new Map(parsed.snapshots.map((entry) => [entry.name, entry])),
    };
  } catch {
    return { snapshots: new Map() };
  }
}

function writeIndex(file: string, index: SnapshotIndex): void {
  writePrivateFile(
    file,
    `${JSON.stringify(
      { snapshots: [...index.snapshots.values()] },
      null,
      2,
    )}\n`,
  );
}

function held(index: SnapshotIndex, name: string): SnapshotEntry {
  const entry = index.snapshots.get(name);
  if (!entry) {
    throw new Error(`snapshot ${JSON.stringify(name)} is no longer reserved`);
  }
  return entry;
}

function artifactPath(entry: SnapshotEntry): string {
  return path.join(entry.directory, entry.file);
}

/**
 * The filename an artifact takes: a readable slug of the name so an operator
 * browsing the directory can tell them apart, plus a digest of the whole
 * name so two names that slugify alike never collide, and so no part of the
 * name ever reaches the filesystem verbatim.
 */
function artifactFileName(name: string): string {
  const slug =
    name
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60) || "snapshot";
  const digest = createHash("sha256").update(name).digest("hex").slice(0, 12);
  return `${slug}-${digest}.smolmachine`;
}

/** Captures stage here, under the artifact directory, so adopting is a rename. */
function stagingRoot(directory: string): string {
  return path.join(directory, ".staging");
}

/**
 * Move a staged artifact into place. A rename within the directory is atomic;
 * a copy would leave a half-written artifact readable as a snapshot. The mode
 * is set first, while the file is still private to staging: an artifact is a
 * whole image of a rig's disks, and the pack wrote it under smolvm's umask.
 */
function adopt(staged: string, destination: string): void {
  chmodSync(staged, 0o600);
  rmSync(destination, { force: true });
  renameSync(staged, destination);
}

/**
 * The artifact directory, owner-only where it is hostd's to say so.
 * `mkdirSync` returns the first path it created, so a `snapshot_dir` an
 * operator made themselves is left exactly as they made it rather than
 * silently relabelled: an artifact is made `0600` on its way in either way,
 * which is the protection that matters. A failure is left to the first
 * capture to report, since a daemon that cannot pack still serves every
 * other route.
 */
function ensurePrivate(directory: string): void {
  try {
    if (mkdirSync(directory, { recursive: true, mode: 0o700 }) !== undefined) {
      chmodSync(directory, 0o700);
    }
  } catch {
    // Reported by the capture that cannot stage into it.
  }
}

function removeArtifact(entry: SnapshotEntry): void {
  rmSync(artifactPath(entry), { force: true });
}

/** A file's size, or undefined when it is not there. */
function fileSize(file: string): number | undefined {
  try {
    return statSync(file).size;
  } catch {
    return undefined;
  }
}
