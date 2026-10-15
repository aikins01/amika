/** The on-disk snapshot store: naming, state, and what survives a restart. */
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  openSnapshotStore,
  SnapshotConflictError,
  SnapshotNameError,
  validName,
  type SnapshotStore,
} from "./snapshot-store.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function open(): {
  store: SnapshotStore;
  root: string;
  reopen: () => SnapshotStore;
} {
  const root = mkdtempSync(path.join(tmpdir(), "amika-hostd-snapshots-"));
  roots.push(root);
  const options = {
    directory: path.join(root, "snapshots"),
    indexFile: path.join(root, "snapshots.json"),
  };
  return {
    root,
    store: openSnapshotStore(options),
    reopen: () => openSnapshotStore(options),
  };
}

/** Stand in for a finished pack: the artifact `activate` adopts. */
function stagePack(store: SnapshotStore, contents = "pack"): string {
  const stub = path.join(store.staging(), "pack");
  writeFileSync(`${stub}.smolmachine`, contents);
  return `${stub}.smolmachine`;
}

describe("snapshot names", () => {
  it("keeps the slashes Amika namespaces snapshots with", () => {
    expect(validName("org_abc123/sandbox/nightly")).toBe(
      "org_abc123/sandbox/nightly",
    );
  });

  it.each([
    ["empty", ""],
    ["a dot segment", "org/../etc/passwd"],
    ["a bare dot segment", "org/./x"],
    ["a leading slash", "/org/sandbox/x"],
    ["a trailing slash", "org/sandbox/"],
    ["a control character", "org/sandbox/a\u0000b"],
    ["too long", `org/${"x".repeat(300)}`],
  ])("refuses %s", (_label, name) => {
    expect(() => validName(name)).toThrow(SnapshotNameError);
  });
});

describe("taking a snapshot", () => {
  it("holds the name while capturing and adopts the artifact", () => {
    const { store } = open();
    store.reserve({ name: "org/sandbox/a", sourceRig: "rig-1", image: "img" });
    expect(store.get("org/sandbox/a")).toMatchObject({
      name: "org/sandbox/a",
      state: "capturing",
      sourceRig: "rig-1",
      image: "img",
    });
    // Nothing is bootable until the pack lands.
    expect(store.artifact("org/sandbox/a")).toBeUndefined();

    const active = store.activate("org/sandbox/a", stagePack(store, "bytes"));
    expect(active).toMatchObject({ state: "active", sizeBytes: 5 });
    const artifact = store.artifact("org/sandbox/a");
    expect(artifact).toBeDefined();
    expect(readFileSync(artifact as string, "utf8")).toBe("bytes");
  });

  it("never lets a name reach the filesystem verbatim", () => {
    const { store, root } = open();
    store.reserve({ name: "org_abc123/sandbox/Nightly Build", sourceRig: "r" });
    store.activate("org_abc123/sandbox/Nightly Build", stagePack(store));
    // One flat file whose name is a slug plus a digest: no directory tree
    // mirroring the snapshot's name, and nothing to traverse out of.
    const files = readdirSync(path.join(root, "snapshots")).filter(
      (entry) => entry !== ".staging",
    );
    expect(files).toEqual([
      expect.stringMatching(
        /^org_abc123-sandbox-nightly-build-[0-9a-f]{12}\.smolmachine$/,
      ),
    ]);
  });

  it("keeps the artifact owner-only, whatever the pack wrote", () => {
    const { store, root, reopen } = open();
    const directory = path.join(root, "snapshots");
    const mode = (file: string) => statSync(file).mode & 0o777;
    // The pack writes its artifact under smolvm's umask, and an operator can
    // point `snapshot_dir` at a directory of their own. An artifact is a
    // whole image of a rig's disks, so neither of those decides who may read
    // it: the directory hostd makes is its own to keep owner-only, and the
    // artifact is made owner-only wherever it lands.
    expect(mode(directory)).toBe(0o700);
    chmodSync(directory, 0o755);
    store.reserve({ name: "org/sandbox/a", sourceRig: "r" });
    const staged = stagePack(store);
    chmodSync(staged, 0o644);
    store.activate("org/sandbox/a", staged);
    expect(mode(store.artifact("org/sandbox/a") as string)).toBe(0o600);

    // A directory hostd did not create is the operator's, not hostd's.
    reopen();
    expect(mode(directory)).toBe(0o755);
  });

  it("gives names that slugify alike their own artifacts", () => {
    const { store } = open();
    for (const name of ["org/sandbox/a-b", "org/sandbox/a_b"]) {
      store.reserve({ name, sourceRig: "r" });
      store.activate(name, stagePack(store, name));
    }
    expect(
      readFileSync(store.artifact("org/sandbox/a-b") as string, "utf8"),
    ).toBe("org/sandbox/a-b");
    expect(
      readFileSync(store.artifact("org/sandbox/a_b") as string, "utf8"),
    ).toBe("org/sandbox/a_b");
  });

  it("refuses a name a live snapshot holds, and reuses a failed one", () => {
    const { store } = open();
    store.reserve({ name: "org/sandbox/a", sourceRig: "r" });
    expect(() =>
      store.reserve({ name: "org/sandbox/a", sourceRig: "r" }),
    ).toThrow(SnapshotConflictError);
    store.activate("org/sandbox/a", stagePack(store));
    expect(() =>
      store.reserve({ name: "org/sandbox/a", sourceRig: "r" }),
    ).toThrow(SnapshotConflictError);

    store.fail("org/sandbox/a", "the pack died");
    expect(store.get("org/sandbox/a")).toMatchObject({
      state: "failed",
      errorReason: "the pack died",
    });
    // Retrying is the one reuse allowed, and the failed artifact is gone.
    expect(store.artifact("org/sandbox/a")).toBeUndefined();
    expect(() =>
      store.reserve({ name: "org/sandbox/a", sourceRig: "r" }),
    ).not.toThrow();
  });

  it("removes the artifact with the snapshot", () => {
    const { store } = open();
    store.reserve({ name: "org/sandbox/a", sourceRig: "r" });
    store.activate("org/sandbox/a", stagePack(store));
    const artifact = store.artifact("org/sandbox/a") as string;

    expect(store.remove("org/sandbox/a")).toBe(true);
    expect(store.remove("org/sandbox/a")).toBe(false);
    expect(store.get("org/sandbox/a")).toBeUndefined();
    expect(existsSync(artifact)).toBe(false);
  });
});

describe("a rig being captured", () => {
  // A full disk, say: the capture never starts, so nothing would ever
  // release a reservation left behind in memory.
  it("is not held by a reservation the index could not record", () => {
    const { store, root } = open();
    mkdirSync(path.join(root, "snapshots.json"));
    expect(() =>
      store.reserve({ name: "org/sandbox/a", sourceRig: "rig-1" }),
    ).toThrow();
    expect(store.isCapturing("rig-1")).toBe(false);
    expect(store.get("org/sandbox/a")).toBeUndefined();
  });

  it("is held from the reservation until the snapshot lands", () => {
    const { store } = open();
    store.reserve({ name: "org/sandbox/a", sourceRig: "rig-1" });
    expect(store.isCapturing("rig-1")).toBe(true);
    expect(store.isCapturing("rig-2")).toBe(false);

    store.activate("org/sandbox/a", stagePack(store));
    expect(store.isCapturing("rig-1")).toBe(false);
  });

  it("is let go by a failed capture", () => {
    const { store } = open();
    store.reserve({ name: "org/sandbox/a", sourceRig: "rig-1" });
    store.fail("org/sandbox/a", "the pack failed");
    expect(store.isCapturing("rig-1")).toBe(false);
  });
});

describe("reopening after a restart", () => {
  it("keeps what landed and fails what was still being taken", () => {
    const { store, reopen } = open();
    store.reserve({ name: "org/sandbox/done", sourceRig: "r" });
    store.activate("org/sandbox/done", stagePack(store));
    store.reserve({ name: "org/sandbox/midway", sourceRig: "r" });

    // A capture cannot outlive the daemon that spawned it, so on the way
    // back up it is a failure rather than a snapshot stuck at `capturing`.
    const reopened = reopen();
    expect(reopened.get("org/sandbox/done")).toMatchObject({ state: "active" });
    expect(reopened.get("org/sandbox/midway")).toMatchObject({
      state: "failed",
      errorReason: expect.stringContaining("daemon stopped"),
    });
    expect(reopened.isCapturing("r")).toBe(false);
  });

  it("drops a snapshot whose artifact has gone missing", () => {
    const { store, reopen } = open();
    store.reserve({ name: "org/sandbox/a", sourceRig: "r" });
    store.activate("org/sandbox/a", stagePack(store));
    rmSync(store.artifact("org/sandbox/a") as string);

    // Reporting a snapshot whose file an operator deleted would hand the
    // control plane a name that can never boot.
    expect(reopen().get("org/sandbox/a")).toBeUndefined();
  });

  it("clears staging left behind mid-pack", () => {
    const { store, root, reopen } = open();
    const staged = store.staging();
    writeFileSync(path.join(staged, "pack.smolmachine"), "half");
    reopen();
    expect(existsSync(path.join(root, "snapshots", ".staging"))).toBe(false);
  });

  it("starts empty on an unreadable index rather than refusing to serve", () => {
    const { root } = open();
    writeFileSync(path.join(root, "snapshots.json"), "{ not json");
    expect(
      openSnapshotStore({
        directory: path.join(root, "snapshots"),
        indexFile: path.join(root, "snapshots.json"),
      }).list(),
    ).toEqual([]);
  });
});
