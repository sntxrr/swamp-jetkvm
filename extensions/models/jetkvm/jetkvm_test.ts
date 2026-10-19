// Tests hand the scripted context to execute() as `any`, as sibling extensions do.
// deno-lint-ignore-file no-explicit-any
import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20260928.39";
import {
  checkProbeCache,
  compareVersions,
  describeTailnet,
  evaluateHealth,
  type HttpResult,
  model,
  parseMetrics,
  parseProbe,
  parseSwapState,
  type Probe,
  PROBE_END,
  PROBE_SCRIPT,
  pruneBackupsScript,
  rejoinPoll,
  ROLLBACK_LOG,
  rollbackScript,
  sshArgs,
  type SshResult,
  SWAP_STATE_SCRIPT,
  swapScript,
  tailnetFindings,
  tailnetOk,
  type Transport,
  transportFactory,
} from "./jetkvm.ts";

rejoinPoll.intervalMs = 1;

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

const G = model.globalArguments.parse({ host: "192.0.2.10" });

Deno.test("sshArgs refuses unknown host keys, never prompts, and pins when given a key", () => {
  const plain = sshArgs(G, null, "sh -s");
  assertStringIncludes(plain.join(" "), "BatchMode=yes");
  assertStringIncludes(plain.join(" "), "StrictHostKeyChecking=yes");
  assertStringIncludes(plain.join(" "), "ControlPath=none");
  assert(!plain.join(" ").includes("UserKnownHostsFile"));
  assertEquals(plain.slice(-3), ["--", "192.0.2.10", "sh -s"]);
  assert(!plain.includes("-n"), "stdin carries the script; -n would empty it");

  const pinned = sshArgs(
    { ...G, sshKeyFile: "/k/id" },
    "/tmp/kh",
    "true",
  ).join(" ");
  assertStringIncludes(pinned, "UserKnownHostsFile=/tmp/kh");
  assertStringIncludes(pinned, "GlobalKnownHostsFile=/dev/null");
  assertStringIncludes(pinned, "HostKeyAlias=jetkvm");
  assertStringIncludes(pinned, "-i /k/id -o IdentitiesOnly=yes");
});

Deno.test("hostKey and host reject shell and option injection", () => {
  assert(!model.globalArguments.safeParse({ host: "-oProxyCommand" }).success);
  assert(!model.globalArguments.safeParse({ host: "a b" }).success);
  assert(!model.globalArguments.safeParse({ host: "a;b" }).success);
  assert(
    !model.globalArguments.safeParse({
      host: "h",
      hostKey: "ssh-ed25519 AAAA\nx",
    })
      .success,
  );
});

Deno.test("parseMetrics reads labels and values", () => {
  const m = parseMetrics(
    `# HELP x\njetkvm_build_info{branch="dev",version="0.5.9"} 1\njetkvm_timesync_status 0\n`,
  );
  assertEquals(m.get("jetkvm_build_info")?.[0].labels.version, "0.5.9");
  assertEquals(m.get("jetkvm_timesync_status")?.[0].value, 0);
});

Deno.test("compareVersions is numeric, not lexical", () => {
  assertEquals(compareVersions("1.104.1", "1.98.8"), 1);
  assertEquals(compareVersions("0.5.9", "0.5.9"), 0);
  assertEquals(compareVersions("v0.2.7", "0.2.8"), -1);
});

function probeText(over: Record<string, string> = {}, end = true): string {
  const kv: Record<string, string> = {
    system: "0.2.8",
    serial: "abc123",
    usb: "configured",
    devmode: "1",
    uptime: "300.5",
    now: String(Math.floor(Date.now() / 1000)),
    disk: "13840000,11600000",
    video: "native+video{inactive}",
    ts_installed: "1",
    ts_version: "1.98.8",
    ts_boot: "1",
    ts_daemon: "1",
    ts_backend: "Running",
    ts_online: "true",
    ts_ip: "198.51.100.7",
    ts_dns: "kvm-a.example.ts.net.",
    boot_id: "boot-1",
    ...over,
  };
  return Object.entries(kv).map(([k, v]) => `${k}=${v}`).join("\n") +
    (end ? `\n${PROBE_END}\n` : "\n");
}

Deno.test("parseProbe reads every field", () => {
  const p = parseProbe(probeText());
  assertEquals(p.systemVersion, "0.2.8");
  assertEquals(p.usbState, "configured");
  assertEquals(p.devMode, true);
  assertEquals(p.diskFreeKb, 11600000);
  assertEquals(p.videoPipeline, "inactive");
  assertEquals(p.tailscale.version, "1.98.8");
  assertEquals(p.tailscale.online, true);
  assertEquals(p.tailscale.ip, "198.51.100.7");
});

Deno.test("parseProbe treats output without the end marker as a failure, not a clean pass", () => {
  let threw = false;
  try {
    parseProbe(probeText({}, false));
  } catch (e) {
    threw = true;
    assertStringIncludes((e as Error).message, "incomplete");
  }
  assert(threw);
  assert(
    (() => {
      try {
        parseProbe("");
        return false;
      } catch {
        return true;
      }
    })(),
    "empty output must not parse",
  );
});

function facts(p: Probe, over: Record<string, unknown> = {}) {
  return {
    checkedAt: new Date(),
    appVersion: "0.5.9",
    latestApp: "0.5.9",
    latestSystem: "0.2.8",
    timeSynced: true,
    probe: p,
    latestTailscale: "1.98.8",
    strictSecurity: false,
    maxClockSkewSeconds: 300,
    minFreeDiskPercent: 10,
    tailnet: null,
    ...over,
  };
}

Deno.test("evaluateHealth: a current, healthy device is ok with dev mode as info", () => {
  const r = evaluateHealth(facts(parseProbe(probeText())));
  assertEquals(r.verdict, "ok");
  assertEquals(r.findings.map((f) => f.code), ["developer_mode_enabled"]);
  const strict = evaluateHealth(
    facts(parseProbe(probeText()), { strictSecurity: true }),
  );
  assertEquals(strict.verdict, "warn");
});

Deno.test("evaluateHealth flags updates, USB, Tailscale state, disk and clock", () => {
  const p = parseProbe(probeText({
    usb: "not attached",
    disk: "1000,50",
    ts_boot: "0",
    ts_online: "false",
    now: "1000",
  }));
  const codes = evaluateHealth(facts(p, {
    latestApp: "0.6.0",
    latestSystem: "0.3.0",
    latestTailscale: "1.104.1",
    timeSynced: false,
  })).findings.map((f) => f.code);
  for (
    const c of [
      "app_update_available",
      "system_update_available",
      "usb_not_configured",
      "disk_low",
      "clock_unsynced",
      "clock_skew",
      "tailscale_offline",
      "tailscale_boot_script_missing",
      "tailscale_update_available",
    ]
  ) assert(codes.includes(c), `missing ${c}: ${codes}`);
});

Deno.test("evaluateHealth: a stopped daemon is tailscale_down, not offline", () => {
  const p = parseProbe(probeText({ ts_daemon: "0", ts_backend: "" }));
  const codes = evaluateHealth(facts(p)).findings.map((f) => f.code);
  assert(codes.includes("tailscale_down"));
  assert(!codes.includes("tailscale_offline"));
});

Deno.test("swap and rollback scripts refuse non-version input and keep the vendor layout", () => {
  const s = swapScript("1.104.1", "1.98.8");
  assertStringIncludes(s, "set -e");
  assertStringIncludes(s, "/userdata/tailscale/backup-1.98.8");
  assertStringIncludes(s, "tailscale_1.104.1_arm");
  assertStringIncludes(s, "tailscale configure jetkvm");
  assertStringIncludes(s, "/userdata/init.d/S22tailscale start");
  assert(
    !s.includes("reboot"),
    "the update restarts the daemon, not the device",
  );
  // the backup is taken only once, so a second run cannot overwrite it with the new binaries
  assertStringIncludes(s, "if [ ! -d /userdata/tailscale/backup-1.98.8 ]");
  assertRejectsSync(() => swapScript("1.104.1; rm -rf /", "1.98.8"));
  assertRejectsSync(() => rollbackScript("$(id)"));
  assertStringIncludes(
    rollbackScript("1.98.8"),
    "cp -p /userdata/tailscale/backup-1.98.8/$b /userdata/tailscale/$b.rb",
  );
});

function assertRejectsSync(fn: () => unknown) {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  assert(threw, "expected a throw");
}

// ---------------------------------------------------------------------------
// Generated shell
// ---------------------------------------------------------------------------

async function shSyntax(script: string): Promise<string> {
  const child = new Deno.Command("sh", {
    args: ["-n"],
    stdin: "piped",
    stdout: "null",
    stderr: "piped",
  }).spawn();
  const w = child.stdin.getWriter();
  await w.write(enc(script));
  await w.close();
  const out = await child.output();
  return out.code === 0 ? "" : dec(out.stderr);
}

Deno.test("every generated script parses as sh", async () => {
  for (
    const [name, script] of [
      ["probe", PROBE_SCRIPT],
      ["swap", swapScript("1.104.1", "1.98.8")],
      ["rollback", rollbackScript("1.98.8")],
      ["swap state", SWAP_STATE_SCRIPT],
      ["prune", pruneBackupsScript("1.98.8")],
    ]
  ) assertEquals(await shSyntax(script), "", `${name} script: syntax error`);
});

Deno.test("the swap script records its pid and status, cleans up and restarts the daemon on any exit", () => {
  const s = swapScript("1.104.1", "1.98.8");
  assertStringIncludes(s, "echo $$ > /userdata/tailscale-update.pid");
  assertStringIncludes(s, "trap finish EXIT");
  assertStringIncludes(s, "> /userdata/tailscale-update.status");
  assertStringIncludes(
    s,
    "pidof tailscaled >/dev/null 2>&1 || /userdata/init.d/S22tailscale start",
  );
  // atomic backup: a half-copied backup is never mistaken for a complete one
  assertStringIncludes(
    s,
    "mv /userdata/tailscale/backup-1.98.8.tmp /userdata/tailscale/backup-1.98.8",
  );
  assert(s.indexOf("trap finish EXIT") < s.indexOf("set -e"));
  const r = rollbackScript("1.98.8");
  assert(
    r.indexOf("backup-1.98.8/tailscale ]") < r.indexOf("S22tailscale stop"),
    "the rollback checks both binaries before stopping anything",
  );
  assertStringIncludes(r, "trap 'pidof tailscaled");
});

Deno.test("parseSwapState reads each state and treats missing output as unknown", () => {
  const mk = (head: string, log = "") => `${head}\n---\n${log}\n${PROBE_END}\n`;
  assertEquals(parseSwapState(mk("state=running")).state, "running");
  const ex = parseSwapState(mk("state=exited 3", "x tarball lacks binaries"));
  assertEquals([ex.state, ex.exitCode], ["exited", 3]);
  assertStringIncludes(ex.log, "tarball lacks binaries");
  assertEquals(parseSwapState(mk("state=none")).state, "none");
  assertEquals(parseSwapState(null).state, "unknown");
  assertEquals(
    parseSwapState("state=exited 0\n---\n").state,
    "unknown",
    "no end marker",
  );
});

// ---------------------------------------------------------------------------
// Scripted device
// ---------------------------------------------------------------------------

const TGZ = enc("fake tarball bytes");
const WRONG_SHA = "0".repeat(64);
const OLD = "1.98.8";
const NEW = "1.104.1";

async function hex(b: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new Uint8Array(b));
  return Array.from(new Uint8Array(d)).map((x) =>
    x.toString(16).padStart(2, "0")
  ).join("");
}

/**
 * A JetKVM as the model sees it. It acts like sh where that matters: a
 * backgrounded `cat` gets no stdin, an empty script does nothing, the swap is
 * asynchronous, and sha256sum hashes what actually arrived.
 */
class FakeJetKvm implements Transport {
  sshLog: { command: string; stdin: string }[] = [];
  fetchLog: string[] = [];
  tsVersion = OLD;
  online = true;
  uptime = 5000;
  bootId = "boot-1";
  /** ok: swaps and rejoins. stuck: swaps, never online. slow: running for `slowProbes` probes, then ok. hang: running forever. noop: exits 3 before swapping. */
  swapPlan: "ok" | "stuck" | "slow" | "hang" | "noop" | "starting" = "ok";
  slowProbes = 0;
  /** With swapPlan "starting": state checks before the swap finishes. */
  startingChecks = Infinity;
  launchCode = 0;
  rollbackWorks = true;
  /** ok: reboots and comes back. dead: never answers again. noboot: back without Tailscale online. ignored: no reboot happens. */
  rebootOutcome: "ok" | "dead" | "noboot" | "ignored" = "ok";
  rebootCode = 0;
  corruptUpload = false;
  rebooted = false;
  script = "";
  swap: {
    state: "none" | "running" | "starting" | "exited";
    code: number | null;
    log: string;
  } = {
    state: "none",
    code: null,
    log: "",
  };
  pending = 0;

  constructor(
    private opts: {
      httpDown?: boolean;
      sshDown?: boolean;
      truncated?: boolean;
      badSum?: boolean;
      probeOver?: Record<string, string>;
      /** What ssh-keyscan sees; undefined = the pinned test key. */
      scannedKey?: string | null;
      /** A non-JetKVM answer on /metrics. */
      foreignMetrics?: { status: number; body: string };
    } = {},
  ) {}

  scans: string[] = [];
  scanHostKey(type: string): Promise<string | null> {
    this.scans.push(type);
    return Promise.resolve(
      this.opts.scannedKey === undefined ? PINNED_KEY : this.opts.scannedKey,
    );
  }

  device(path: string): Promise<HttpResult> {
    if (this.opts.httpDown) {
      return Promise.reject(new Error("Failed to connect"));
    }
    if (this.opts.foreignMetrics) {
      return Promise.resolve({
        status: this.opts.foreignMetrics.status,
        body: enc(this.opts.foreignMetrics.body),
      });
    }
    if (path !== "/metrics") {
      return Promise.resolve({ status: 404, body: enc("") });
    }
    return Promise.resolve({
      status: 200,
      body: enc(
        `jetkvm_build_info{version="0.5.9"} 1\njetkvm_timesync_status 1\n`,
      ),
    });
  }

  private ok(stdout = ""): SshResult {
    return { code: 0, stdout, stderr: "" };
  }

  private finishSwap() {
    this.tsVersion = NEW;
    if (this.swapPlan === "stuck") this.online = false;
    this.swap = {
      state: "exited",
      code: 0,
      log: "backup ready\nbinaries swapped\nSWAP_DONE",
    };
  }

  sshTimeouts: (number | undefined)[] = [];
  async ssh(
    command: string,
    stdin?: Uint8Array,
    timeoutMs?: number,
  ): Promise<SshResult> {
    const input = stdin ? dec(stdin) : "";
    this.sshLog.push({ command, stdin: input });
    this.sshTimeouts.push(timeoutMs);
    if (this.opts.sshDown) {
      return {
        code: 255,
        stdout: "",
        stderr: "Permission denied (publickey).",
      };
    }
    if (command === "sh -s" && input === PROBE_SCRIPT) {
      if (this.rebooted && this.rebootOutcome === "dead") {
        return { code: 255, stdout: "", stderr: "Connection refused" };
      }
      if (
        this.swap.state === "running" && this.swapPlan === "slow" &&
        --this.pending <= 0
      ) {
        this.finishSwap();
      }
      this.uptime += 1;
      return this.ok(probeText(
        {
          ts_version: this.tsVersion,
          ts_online: String(this.online),
          uptime: String(this.uptime),
          boot_id: this.bootId,
          ...this.opts.probeOver,
        },
        !this.opts.truncated,
      ));
    }
    if (command === "sh -s" && input === SWAP_STATE_SCRIPT) {
      if (this.swap.state === "starting" && --this.startingChecks <= 0) {
        this.finishSwap();
      }
      const head = this.swap.state === "exited"
        ? `state=exited ${this.swap.code}`
        : `state=${this.swap.state}`;
      return this.ok(`${head}\n---\n${this.swap.log}\n${PROBE_END}\n`);
    }
    if (command === "sh -s" && input.includes("ROLLBACK_DONE")) {
      if (!this.rollbackWorks) {
        return { code: 3, stdout: "no complete backup", stderr: "" };
      }
      this.tsVersion = OLD;
      this.online = true;
      return this.ok("ROLLBACK_DONE\n");
    }
    if (command.startsWith(`cat > /userdata/tailscale-${NEW}.tgz`)) {
      const body = this.corruptUpload
        ? enc("truncated")
        : stdin ?? new Uint8Array();
      return this.ok(`${await hex(body)}  /userdata/x.tgz\n`);
    }
    if (command.includes("cat > /userdata/tailscale-update.sh")) {
      // Like sh: a backgrounded list gets /dev/null as stdin.
      this.script = command.trimEnd().endsWith("&") ? "" : input;
      return this.ok(
        command.includes("wc -c") ? `${enc(this.script).length}\n` : "",
      );
    }
    if (command.includes("nohup sh /userdata/tailscale-update.sh")) {
      // An empty script runs nothing and leaves no pid or status behind.
      if (this.script.includes("binaries swapped")) {
        if (this.swapPlan === "starting") {
          // The redirect created the log, and sh has not written its pid yet.
          this.swap = { state: "starting", code: null, log: "" };
        } else if (this.swapPlan === "noop") {
          this.swap = {
            state: "exited",
            code: 3,
            log: "tarball lacks binaries",
          };
        } else if (this.swapPlan === "slow" || this.swapPlan === "hang") {
          this.swap = { state: "running", code: null, log: "backup ready" };
          this.pending = this.slowProbes;
        } else this.finishSwap();
      }
      return {
        code: this.launchCode,
        stdout: "",
        stderr: this.launchCode ? "Connection reset" : "",
      };
    }
    if (command.includes("reboot")) {
      if (this.rebootCode !== 0) {
        return {
          code: this.rebootCode,
          stdout: "",
          stderr: "reboot: not permitted",
        };
      }
      if (this.rebootOutcome !== "ignored") {
        this.rebooted = true;
        this.bootId = "boot-2";
        this.uptime = 10;
      }
      if (this.rebootOutcome === "noboot") this.online = false;
      return this.ok();
    }
    return this.ok();
  }

  async fetch(url: string): Promise<HttpResult> {
    this.fetchLog.push(url);
    if (url.startsWith("https://pkgs.tailscale.com/stable/?mode=json")) {
      return {
        status: 200,
        body: enc(JSON.stringify({ TarballsVersion: NEW })),
      };
    }
    if (url.startsWith("https://api.jetkvm.com/releases")) {
      return {
        status: 200,
        body: enc(
          JSON.stringify({ appVersion: "0.5.9", systemVersion: "0.2.8" }),
        ),
      };
    }
    if (url.endsWith(".tgz.sha256")) {
      return {
        status: 200,
        body: enc(this.opts.badSum ? WRONG_SHA : await hex(TGZ)),
      };
    }
    if (url.endsWith(".tgz")) return { status: 200, body: TGZ };
    return { status: 404, body: enc("") };
  }
}

async function withFake<T>(fake: FakeJetKvm, fn: () => Promise<T>): Promise<T> {
  const orig = transportFactory.create;
  transportFactory.create = () => fake;
  try {
    return await fn();
  } finally {
    transportFactory.create = orig;
  }
}

function ctx() {
  return createModelTestContext({
    globalArgs: model.globalArguments.parse({ host: "192.0.2.10" }),
  });
}

const parseArgs = (
  m: keyof typeof model.methods,
  a: Record<string, unknown>,
): any => model.methods[m].arguments.parse(a);

const runHealth = async (fake: FakeJetKvm) => {
  const { context, getWrittenResources } = ctx();
  await withFake(
    fake,
    () => model.methods.health.execute(parseArgs("health", {}), context as any),
  );
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  return w.data as any;
};

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

Deno.test("health on a current device: warn only for the Tailscale update, and nothing but the probe runs", async () => {
  const fake = new FakeJetKvm();
  const d = await runHealth(fake);
  assertEquals(d.verdict, "warn");
  assertEquals(d.appVersion, "0.5.9");
  assertEquals(d.latestTailscale, NEW);
  assert(d.findings.some((f: any) => f.code === "tailscale_update_available"));
  assertEquals(
    fake.sshLog.map((l) => l.command),
    ["sh -s"],
    "health must run only the read-only probe",
  );
  assert(
    !fake.sshLog[0].stdin.includes("kvm_config.json"),
    "the probe must not read the config (password hash, cloud token)",
  );
});

Deno.test("health records an SSH denial as fail, never as a pass", async () => {
  const d = await runHealth(new FakeJetKvm({ sshDown: true }));
  assertEquals(d.verdict, "fail");
  assertEquals(d.sshOk, false);
  assertEquals(d.httpOk, true);
  assert(d.findings.some((f: any) => f.code === "ssh_failed"));
});

Deno.test("health records a truncated probe as fail", async () => {
  const d = await runHealth(new FakeJetKvm({ truncated: true }));
  assertEquals(d.verdict, "fail");
  assertStringIncludes(d.error, "incomplete");
});

Deno.test("health records a fully unreachable device as fail with both findings", async () => {
  const d = await runHealth(new FakeJetKvm({ httpDown: true, sshDown: true }));
  assertEquals(d.verdict, "fail");
  assertEquals(d.findings.map((f: any) => f.code), [
    "unreachable",
    "ssh_failed",
  ]);
});

Deno.test("health with SSH up and HTTP down is at least warn", async () => {
  const fake = new FakeJetKvm({ httpDown: true });
  fake.tsVersion = NEW;
  const d = await runHealth(fake);
  assertEquals(d.verdict, "warn");
  assertEquals(d.findings[0].code, "web_unreachable");
});

// ---------------------------------------------------------------------------
// tailscale
// ---------------------------------------------------------------------------

const runTs = (
  fake: FakeJetKvm,
  a: Record<string, unknown>,
  method: "tailscale" | "tailscaleUpdate" = "tailscale",
) => {
  const { context, getWrittenResources } = ctx();
  const p = withFake(
    fake,
    () =>
      (model.methods[method].execute as any)(
        parseArgs(method, a),
        context as any,
      ),
  );
  return { p, written: () => getWrittenResources().map((w) => w.data as any) };
};

/** tailscaleUpdate: the only method that writes. */
const runUpd = (fake: FakeJetKvm, a: Record<string, unknown>) =>
  runTs(fake, a, "tailscaleUpdate");

/** Everything sent to the device except the read-only probe and swap-state reads. */
const deviceWrites = (fake: FakeJetKvm) =>
  fake.sshLog.filter((l) =>
    !(l.command === "sh -s" &&
      (l.stdin === PROBE_SCRIPT || l.stdin === SWAP_STATE_SCRIPT))
  );
const sent = (fake: FakeJetKvm, needle: string) =>
  deviceWrites(fake).some((l) =>
    l.command.includes(needle) || l.stdin.includes(needle)
  );

const APPLY = { rejoinTimeoutMs: 40 };

async function applied(fake: FakeJetKvm, extra: Record<string, unknown> = {}) {
  const r = runUpd(fake, { ...APPLY, ...extra });
  let error: Error | null = null;
  await r.p.catch((e) => (error = e));
  const [w] = r.written();
  model.resources.tailscale.schema.parse(w);
  return { w, error: error as Error | null };
}

Deno.test("tailscale status reports the version and the available update, touching nothing", async () => {
  const fake = new FakeJetKvm();
  const { p, written } = runTs(fake, {});
  await p;
  const [w] = written();
  model.resources.tailscale.schema.parse(w);
  assertEquals(w.outcome, "status");
  assertStringIncludes(w.message, `${NEW} is available`);
  assertEquals(deviceWrites(fake).length, 0);
});

Deno.test("tailscale update without apply is a dry run listing every step", async () => {
  const fake = new FakeJetKvm();
  const { p, written } = runTs(fake, { action: "update" });
  await p;
  const [w] = written();
  assertEquals(w.outcome, "dry-run");
  assertEquals(w.targetVersion, NEW);
  assertEquals(w.steps.length, 5);
  assertEquals(
    deviceWrites(fake).length,
    0,
    "dry run must not touch the device",
  );
  assert(
    !fake.fetchLog.some((u) => u.endsWith(".tgz")),
    "dry run must not download",
  );
});

Deno.test("tailscale update applies: verify, upload, write, launch, confirm the same node rejoined", async () => {
  const fake = new FakeJetKvm();
  const { w, error } = await applied(fake);
  assertEquals(error, null);
  assertEquals(w.outcome, "done");
  assertEquals(w.after.version, NEW);
  assertEquals(w.after.ip, "198.51.100.7");
  const writes = deviceWrites(fake);
  assert(writes[0].command.startsWith(`cat > /userdata/tailscale-${NEW}.tgz`));
  assertEquals(writes[0].stdin, dec(TGZ));
  assertStringIncludes(
    writes[1].command,
    "cat > /userdata/tailscale-update.sh && wc -c",
  );
  assertStringIncludes(
    writes[1].command,
    "rm -f /userdata/tailscale-update.pid /userdata/tailscale-update.status /userdata/tailscale-update.log",
  );
  assert(
    !writes[1].command.trimEnd().endsWith("&"),
    "the script write must not be backgrounded",
  );
  assertStringIncludes(writes[1].stdin, `backup-${OLD}`);
  assertStringIncludes(
    writes[2].command,
    "nohup sh /userdata/tailscale-update.sh",
  );
  assertStringIncludes(writes[2].command, "< /dev/null");
  // After the node is proven back: prune backups, keeping the one just made.
  assertStringIncludes(writes[3].command, "/userdata/tailscale/backup-*");
  assertStringIncludes(writes[3].command, `backup-${OLD}`);
  assertEquals(writes.length, 4);
});

Deno.test("tailscale update refuses a tarball whose sha256 does not match, before touching the device", async () => {
  const fake = new FakeJetKvm({ badSum: true });
  const { w, error } = await applied(fake);
  assertStringIncludes(String(error), "sha256 mismatch");
  assertEquals(w.outcome, "refused");
  assertEquals(deviceWrites(fake).length, 0);
});

Deno.test("tailscale update refuses an upload that arrives altered, and removes it", async () => {
  const fake = new FakeJetKvm();
  fake.corruptUpload = true;
  const { w, error } = await applied(fake);
  assertStringIncludes(String(error), "did not verify");
  assertEquals(w.outcome, "refused");
  assert(sent(fake, `rm -f /userdata/tailscale-${NEW}.tgz`));
  assert(!sent(fake, "nohup"));
});

Deno.test("tailscale update rolls back when the swapped node does not come back online", async () => {
  const fake = new FakeJetKvm();
  fake.swapPlan = "stuck";
  const { w, error } = await applied(fake);
  assertStringIncludes(String(error), "rolled back");
  assertEquals(w.outcome, "rolled-back");
  assertEquals(w.after.version, OLD);
  assert(sent(fake, "ROLLBACK_DONE"));
});

Deno.test("a failed rollback is recorded as rollback-failed, not rolled-back", async () => {
  const fake = new FakeJetKvm();
  fake.swapPlan = "stuck";
  fake.rollbackWorks = false;
  const { w, error } = await applied(fake);
  assertStringIncludes(String(error), "rollback failed");
  assertEquals(w.outcome, "rollback-failed");
  assertStringIncludes(w.message, "NEEDS A HUMAN");
});

Deno.test("a swap still running at the deadline is waited for, not misread as unchanged", async () => {
  const fake = new FakeJetKvm();
  fake.swapPlan = "slow";
  fake.slowProbes = 60; // well past rejoinTimeoutMs at 1 ms polling, inside 2x
  const { w, error } = await applied(fake, { rejoinTimeoutMs: 400 });
  assertEquals(error, null);
  assertEquals(w.outcome, "done");
  assert(!sent(fake, "ROLLBACK_DONE"));
});

Deno.test("a swap that never finishes is swap-unconfirmed, and nothing races it", async () => {
  const fake = new FakeJetKvm();
  fake.swapPlan = "hang";
  const { w, error } = await applied(fake);
  assertStringIncludes(String(error), "unconfirmed");
  assertEquals(w.outcome, "swap-unconfirmed");
  assert(
    !sent(fake, "ROLLBACK_DONE"),
    "no rollback while the swap may still act",
  );
});

Deno.test("a swap that exits before swapping is unchanged, applied false, with no rollback", async () => {
  const fake = new FakeJetKvm();
  fake.swapPlan = "noop";
  const { w, error } = await applied(fake);
  assertStringIncludes(String(error), "device unchanged");
  assertEquals(w.outcome, "unchanged");
  assertEquals(w.applied, false);
  assertStringIncludes(w.message, "tarball lacks binaries");
  assert(!sent(fake, "ROLLBACK_DONE"));
});

Deno.test("a launch whose session drops after the job started is still watched to the end", async () => {
  const fake = new FakeJetKvm();
  fake.launchCode = 255;
  const { w, error } = await applied(fake);
  assertEquals(error, null);
  assertEquals(w.outcome, "done");
});

Deno.test("a launch that failed with no trace on the device is refused and cleaned up", async () => {
  const fake = new FakeJetKvm();
  fake.launchCode = 255;
  fake.swapPlan = "ok";
  // the script never lands as runnable, so the launch leaves no pid or status
  const orig = fake.ssh.bind(fake);
  fake.ssh = (c: string, i?: Uint8Array) =>
    c.includes("nohup")
      ? Promise.resolve({ code: 255, stdout: "", stderr: "Connection reset" })
      : orig(c, i);
  const { w, error } = await applied(fake);
  assertStringIncludes(String(error), "could not start the swap");
  assertEquals(w.outcome, "refused");
  assert(
    sent(
      fake,
      "rm -f /userdata/tailscale-1.104.1.tgz /userdata/tailscale-update.sh",
    ),
  );
});

Deno.test("tailscale update is a no-op when already current, and refuses downgrades", async () => {
  const cur = new FakeJetKvm();
  cur.tsVersion = NEW;
  const a = runUpd(cur, APPLY);
  await a.p;
  assertEquals(a.written()[0].outcome, "current");
  assertEquals(deviceWrites(cur).length, 0);

  const down = new FakeJetKvm();
  const b = runUpd(down, { ...APPLY, version: "1.90.0" });
  await assertRejects(() => b.p, Error, "older than");
  assertEquals(deviceWrites(down).length, 0);
});

Deno.test("tailscale update refuses without the boot script, an install, or a readable free-space figure", async () => {
  for (
    const [over, msg] of [
      [{ ts_boot: "0" }, "S22tailscale"],
      [{ ts_installed: "0" }, "not installed"],
      [{ disk: "" }, "could not read free space"],
    ] as const
  ) {
    const fake = new FakeJetKvm({ probeOver: over });
    const r = runUpd(fake, APPLY);
    await assertRejects(() => r.p, Error, msg);
    assertEquals(deviceWrites(fake).length, 0, msg);
    assert(!fake.fetchLog.some((u) => u.endsWith(".tgz")), msg);
  }
});

Deno.test("version argument rejects anything that is not x.y.z", () => {
  assert(
    !model.methods.tailscale.arguments.safeParse({ version: "1.2.3;reboot" })
      .success,
  );
});

// ---------------------------------------------------------------------------
// rebootAfter
// ---------------------------------------------------------------------------

Deno.test("rebootAfter: reboots once after a verified update and requires a new boot id that rejoins", async () => {
  const fake = new FakeJetKvm();
  const { w, error } = await applied(fake, { rebootAfter: true });
  assertEquals(error, null);
  assertEquals(w.outcome, "done");
  assertStringIncludes(w.message, "Rebooted");
  assertEquals(w.steps.length, 6);
  const cmds = deviceWrites(fake).map((l) => l.command);
  assertEquals(cmds.filter((c) => c.includes("reboot")).length, 1);
  assert(
    cmds.findIndex((c) => c.includes("nohup")) <
      cmds.findIndex((c) => c.includes("reboot")),
    "reboot only after the swap",
  );
});

Deno.test("rebootAfter is not sent without apply, nor when the update did not rejoin", async () => {
  const dry = new FakeJetKvm();
  const a = runTs(dry, { action: "update", rebootAfter: true });
  await a.p;
  assertEquals(deviceWrites(dry).length, 0);

  const stuck = new FakeJetKvm();
  stuck.swapPlan = "stuck";
  await applied(stuck, { rebootAfter: true });
  assert(!sent(stuck, "reboot"));
});

Deno.test("rebootAfter does not reboot when the boot id cannot be read first", async () => {
  const fake = new FakeJetKvm({ probeOver: { boot_id: "" } });
  const { w, error } = await applied(fake, { rebootAfter: true });
  assertStringIncludes(String(error), "was not rebooted");
  assertEquals(w.outcome, "reboot-unverified");
  assert(!sent(fake, "reboot"));
});

Deno.test("rebootAfter reports a failed reboot command at once, with its error", async () => {
  const fake = new FakeJetKvm();
  fake.rebootCode = 1;
  const { w, error } = await applied(fake, {
    rebootAfter: true,
    rebootTimeoutMs: 100000,
  });
  assertStringIncludes(String(error), "reboot command failed");
  assertEquals(w.outcome, "reboot-unverified");
  assertStringIncludes(w.message, "not permitted");
});

for (
  const [outcome, msg] of [
    ["dead", "did not answer SSH"],
    ["noboot", "after the reboot Tailscale"],
    ["ignored", "boot id unchanged"],
  ] as const
) {
  Deno.test(`rebootAfter fails loudly, never green, when the reboot is ${outcome}`, async () => {
    const fake = new FakeJetKvm();
    fake.rebootOutcome = outcome;
    const { w, error } = await applied(fake, {
      rebootAfter: true,
      rebootTimeoutMs: 30,
    });
    assertStringIncludes(String(error), msg);
    assertEquals(w.outcome, "reboot-unverified");
    assertStringIncludes(w.message, `backup-${OLD}`);
  });
}

const PINNED_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID5AESOfH5LKGSwMVNdO1iK1L2c4wZNfxsNt1KrD9BAp";

// ---------------------------------------------------------------------------
// tailnet probe
// ---------------------------------------------------------------------------

const tsCodes = (over: Record<string, unknown>) =>
  evaluateHealth(facts(parseProbe(probeText()), over)).findings
    .filter((f) => f.code.startsWith("tailscale_"))
    .map((f) => `${f.severity} ${f.code}`);

Deno.test("tailnet: answering on the configured IP adds no finding", () => {
  assertEquals(
    tsCodes({
      tailnet: {
        ip: "198.51.100.7",
        reachable: true,
        sameDevice: true,
        error: null,
      },
    }),
    [],
  );
});

Deno.test("tailnet: a node deleted from the tailnet still says Running and online; only the probe catches it", () => {
  assertEquals(
    tsCodes({
      tailnet: {
        ip: "198.51.100.7",
        reachable: false,
        sameDevice: null,
        error: "curl exit 28",
      },
    }),
    ["warn tailscale_unreachable"],
  );
});

Deno.test("tailnet: a re-added node with a new IP warns and names both", () => {
  const r = evaluateHealth(facts(parseProbe(probeText()), {
    tailnet: {
      ip: "198.51.100.9",
      reachable: false,
      sameDevice: null,
      error: null,
    },
  }));
  const f = r.findings.find((x) => x.code === "tailscale_ip_changed")!;
  assertEquals(f.severity, "warn");
  assertStringIncludes(f.message, "198.51.100.7");
  assertStringIncludes(f.message, "198.51.100.9");
});

async function runHealthVia(
  fakes: Record<string, FakeJetKvm>,
  globals: Record<string, unknown>,
) {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: model.globalArguments.parse(globals),
  });
  const orig = transportFactory.create;
  transportFactory.create = (g) => {
    const f = fakes[g.host];
    if (!f) throw new Error(`no fake for ${g.host}`);
    return f;
  };
  try {
    await model.methods.health.execute(
      parseArgs("health", {}),
      context as any,
    );
  } finally {
    transportFactory.create = orig;
  }
  const [w] = getWrittenResources();
  model.resources.health.schema.parse(w.data);
  return w.data as any;
}

Deno.test("health fetches /metrics on the tailnet IP and nothing else there", async () => {
  const lan = new FakeJetKvm();
  const tailnet = new FakeJetKvm();
  const d = await runHealthVia(
    { "192.0.2.10": lan, "198.51.100.7": tailnet },
    { host: "192.0.2.10", tailnetIp: "198.51.100.7" },
  );
  assertEquals(d.tailnet, {
    ip: "198.51.100.7",
    reachable: true,
    sameDevice: null,
    error: null,
  });
  assert(!d.findings.some((f: any) => f.code === "tailscale_unreachable"));
  assertEquals(tailnet.sshLog.length, 0, "no SSH over the tailnet");
  assertEquals(tailnet.fetchLog.length, 0);
});

Deno.test("health records an unanswered tailnet IP as tailscale_unreachable, not a throw", async () => {
  const d = await runHealthVia(
    {
      "192.0.2.10": new FakeJetKvm(),
      "198.51.100.7": new FakeJetKvm({ httpDown: true }),
    },
    { host: "192.0.2.10", tailnetIp: "198.51.100.7" },
  );
  assertEquals(d.sshOk, true);
  assertEquals(d.tailnet.reachable, false);
  const f = d.findings.find((x: any) => x.code === "tailscale_unreachable");
  assertEquals(f.severity, "warn");
  assertStringIncludes(f.message, "Failed to connect");
});

Deno.test("without tailnetIp, health records tailnet as null", async () => {
  const d = await runHealth(new FakeJetKvm());
  assertEquals(d.tailnet, null);
});

Deno.test("tailnetIp must be an IPv4 literal", () => {
  let threw = false;
  try {
    model.globalArguments.parse({
      host: "192.0.2.10",
      tailnetIp: "kvm.example.ts.net",
    });
  } catch {
    threw = true;
  }
  assert(threw);
});

Deno.test("tailnet probe: a pinned host key that matches proves the same device", async () => {
  const tail = new FakeJetKvm();
  const d = await runHealthVia(
    { "192.0.2.10": new FakeJetKvm(), "198.51.100.7": tail },
    { host: "192.0.2.10", tailnetIp: "198.51.100.7", hostKey: PINNED_KEY },
  );
  assertEquals(d.tailnet.sameDevice, true);
  assertEquals(tail.scans, ["ssh-ed25519"]);
  assertEquals(
    tail.sshLog.length,
    0,
    "the probe never logs in over the tailnet",
  );
});

Deno.test("tailnet probe: a different host key, or a non-JetKVM answer, is tailscale_wrong_device", async () => {
  for (
    const opts of [
      {
        scannedKey:
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTH",
      },
      { foreignMetrics: { status: 200, body: "<html>not a jetkvm</html>" } },
      { foreignMetrics: { status: 404, body: "" } },
    ]
  ) {
    const d = await runHealthVia(
      { "192.0.2.10": new FakeJetKvm(), "198.51.100.7": new FakeJetKvm(opts) },
      { host: "192.0.2.10", tailnetIp: "198.51.100.7", hostKey: PINNED_KEY },
    );
    assertEquals(d.tailnet.reachable, true, JSON.stringify(opts));
    assertEquals(d.tailnet.sameDevice, false, JSON.stringify(opts));
    assert(
      d.findings.some((f: any) => f.code === "tailscale_wrong_device"),
      JSON.stringify(opts),
    );
  }
});

Deno.test("tailnet probe transport carries no login material and a capped timeout", async () => {
  const seen: any[] = [];
  const fakes: Record<string, FakeJetKvm> = {
    "192.0.2.10": new FakeJetKvm(),
    "198.51.100.7": new FakeJetKvm(),
  };
  const orig = transportFactory.create;
  transportFactory.create = (g) => (seen.push(g), fakes[g.host]);
  try {
    const { context } = createModelTestContext({
      globalArgs: model.globalArguments.parse({
        host: "192.0.2.10",
        tailnetIp: "198.51.100.7",
        hostKey: PINNED_KEY,
        sshKeyFile: "/keys/id_ed25519",
      }),
    });
    await model.methods.health.execute(parseArgs("health", {}), context as any);
  } finally {
    transportFactory.create = orig;
  }
  const tg = seen.find((g) => g.host === "198.51.100.7");
  assertEquals(tg.sshKeyFile, undefined);
  assertEquals(tg.hostKey, undefined);
  assert(tg.timeoutMs <= 10000);
});

Deno.test("with SSH down, the tailnet probe is still recorded, with its finding", async () => {
  const d = await runHealthVia(
    {
      "192.0.2.10": new FakeJetKvm({ sshDown: true }),
      "198.51.100.7": new FakeJetKvm({ httpDown: true }),
    },
    { host: "192.0.2.10", tailnetIp: "198.51.100.7" },
  );
  assertEquals(d.sshOk, false);
  assertEquals(d.verdict, "fail");
  assertEquals(d.tailnet.reachable, false);
  assert(d.findings.some((f: any) => f.code === "tailscale_unreachable"));
});

Deno.test("tailnetFindings: no ip_changed when the device IP is unknown", () => {
  const t = {
    ip: "198.51.100.7",
    reachable: true,
    sameDevice: true,
    error: null,
  };
  assertEquals(tailnetFindings(t, null), []);
  assertEquals(tailnetFindings(t, "198.51.100.7"), []);
  assertEquals(tailnetFindings(null, "198.51.100.9"), []);
  assertEquals(tailnetFindings(t, "198.51.100.9").map((f) => f.code), [
    "tailscale_ip_changed",
  ]);
});

Deno.test("tailnetIp rejects out-of-range octets and leading zeros", () => {
  for (
    const bad of ["256.1.1.1", "198.051.100.7", "198.51.100", "kvm.example.com"]
  ) {
    let threw = false;
    try {
      model.globalArguments.parse({ host: "192.0.2.10", tailnetIp: bad });
    } catch {
      threw = true;
    }
    assert(threw, bad);
  }
});

Deno.test("rollback script survives a dropped session and renames binaries into place", () => {
  const s = rollbackScript(OLD);
  assertStringIncludes(s, "trap '' HUP");
  assertStringIncludes(s, `>>${ROLLBACK_LOG} 2>&1`);
  assertStringIncludes(
    s,
    "cp -p /userdata/tailscale/backup-" + OLD + "/$b /userdata/tailscale/$b.rb",
  );
  assertStringIncludes(
    s,
    "mv /userdata/tailscale/$b.rb /userdata/tailscale/$b",
  );
  assert(
    !s.includes(
      `cp -p /userdata/tailscale/backup-${OLD}/tailscale /userdata/tailscale/backup-${OLD}/tailscaled /userdata/tailscale/`,
    ),
  );
});

Deno.test("pruneBackupsScript keeps only the named backup and refuses non-versions", () => {
  const s = pruneBackupsScript(OLD);
  assertStringIncludes(s, `/userdata/tailscale/backup-${OLD}`);
  assertStringIncludes(s, "/userdata/tailscale/backup-*");
  let threw = false;
  try {
    pruneBackupsScript("1.2.3; rm -rf /");
  } catch {
    threw = true;
  }
  assert(threw);
});

Deno.test("parseSwapState reads 'starting' (log written, pid not yet)", () => {
  assertEquals(
    parseSwapState(`state=starting\n---\nx\n${PROBE_END}\n`).state,
    "starting",
  );
});

Deno.test("the rollback runs with a budget that covers its own 20 s stop wait", async () => {
  const fake = new FakeJetKvm();
  fake.swapPlan = "stuck";
  await applied(fake);
  const i = fake.sshLog.findIndex((l) => l.stdin.includes("ROLLBACK_DONE"));
  assert(i >= 0);
  assert((fake.sshTimeouts[i] ?? 0) >= 60000, String(fake.sshTimeouts[i]));
});

Deno.test("a failed rollback leaves old backups alone: pruning only follows a verified update", async () => {
  const fake = new FakeJetKvm();
  fake.swapPlan = "stuck";
  await applied(fake);
  assert(!fake.sshLog.some((l) => l.command.includes("backup-*")));
});

Deno.test("a launch error while the swap is only 'starting' is watched, not refused or cleaned up", async () => {
  const fake = new FakeJetKvm();
  fake.launchCode = 255;
  fake.swapPlan = "starting";
  const { w } = await applied(fake);
  assertEquals(w.outcome, "swap-unconfirmed");
  assert(
    !fake.sshLog.some((l) =>
      l.command.startsWith(`rm -f /userdata/tailscale-${NEW}.tgz`)
    ),
    "a starting swap must not have its files removed",
  );
  assert(!sent(fake, "ROLLBACK_DONE"), "nor be rolled back under it");
});

Deno.test("a swap still 'starting' at the deadline is waited for, and its completion is seen", async () => {
  const fake = new FakeJetKvm();
  fake.launchCode = 255;
  fake.swapPlan = "starting";
  fake.startingChecks = 3;
  const { w, error } = await applied(fake);
  assertEquals(error, null);
  assertEquals(w.outcome, "done");
});

// ---------------------------------------------------------------------------
// 2026.10.19.1: reads and writes split; labeled pre-flight checks
// ---------------------------------------------------------------------------

Deno.test("tailscale refuses apply: true loudly and touches nothing", async () => {
  const fake = new FakeJetKvm();
  const r = runTs(fake, { action: "update", apply: true });
  await assertRejects(() => r.p, Error, "tailscaleUpdate");
  assertEquals(fake.sshLog.length, 0, "a refused call must not even probe");
  assertEquals(r.written().length, 0);
});

Deno.test("the tailscale plan points at tailscaleUpdate, and tailscaleUpdate takes no apply or action", async () => {
  const fake = new FakeJetKvm();
  const r = runTs(fake, { action: "update" });
  await r.p;
  assertStringIncludes(r.written()[0].message, "call tailscaleUpdate");
  const shape = model.methods.tailscaleUpdate.arguments.shape as Record<
    string,
    unknown
  >;
  assert(!("apply" in shape) && !("action" in shape));
});

Deno.test("every check is labeled live and scoped to tailscaleUpdate only", () => {
  const names = Object.keys(model.checks).sort();
  assertEquals(names, [
    "tailnet-path",
    "tailscale-boot-script",
    "tailscale-installed",
    "userdata-free-space",
  ]);
  for (const [n, c] of Object.entries(model.checks)) {
    // An unscoped swamp check runs before EVERY method, health included.
    assertEquals(c.appliesTo, ["tailscaleUpdate"], n);
    assert(c.labels.includes("live"), n);
  }
});

const runCheck = async (
  name: keyof typeof model.checks,
  fakes: Record<string, FakeJetKvm>,
  globals: Record<string, unknown> = { host: "192.0.2.10" },
) => {
  checkProbeCache.clear();
  const orig = transportFactory.create;
  transportFactory.create = (g) => {
    const f = fakes[g.host];
    if (!f) throw new Error(`no fake for ${g.host}`);
    return f;
  };
  try {
    return await model.checks[name].execute({ globalArgs: globals });
  } finally {
    transportFactory.create = orig;
  }
};

Deno.test("checks pass on a healthy device and share one probe", async () => {
  const lan = new FakeJetKvm();
  checkProbeCache.clear();
  for (
    const n of [
      "tailscale-installed",
      "tailscale-boot-script",
      "userdata-free-space",
    ] as const
  ) {
    const orig = transportFactory.create;
    transportFactory.create = () => lan;
    try {
      assertEquals(
        await model.checks[n].execute({ globalArgs: { host: "192.0.2.10" } }),
        { pass: true },
        n,
      );
    } finally {
      transportFactory.create = orig;
    }
  }
  assertEquals(lan.sshLog.length, 1, "three checks, one SSH probe");
  assertEquals(
    await runCheck("tailnet-path", { "192.0.2.10": lan }),
    { pass: true },
    "no tailnetIp: nothing to check against",
  );
});

Deno.test("each device check fails on its own condition, with the method's wording", async () => {
  for (
    const [name, over, msg] of [
      ["tailscale-installed", { ts_installed: "0" }, "not installed"],
      ["tailscale-boot-script", { ts_boot: "0" }, "S22tailscale"],
      ["userdata-free-space", { disk: "" }, "could not read free space"],
      ["userdata-free-space", { disk: "13830232,102400" }, "100 MB free"],
    ] as const
  ) {
    const r = await runCheck(name, {
      "192.0.2.10": new FakeJetKvm({ probeOver: over }),
    });
    assertEquals(r.pass, false, name);
    assertStringIncludes(r.errors![0], msg, name);
  }
});

Deno.test("a device check fails closed when the probe fails, and the failure is not cached", async () => {
  const down = new FakeJetKvm({ sshDown: true });
  const r = await runCheck("tailscale-installed", { "192.0.2.10": down });
  assertEquals(r.pass, false);
  assertStringIncludes(r.errors![0], "could not probe");
  await Promise.resolve();
  assertEquals(checkProbeCache.entries.size, 0);
});

Deno.test("the tailnet-path check fails on an unreachable or wrong device, passes on the right one", async () => {
  const g = {
    host: "192.0.2.10",
    tailnetIp: "198.51.100.7",
    hostKey: PINNED_KEY,
  };
  const lan = new FakeJetKvm();
  assertEquals(
    await runCheck("tailnet-path", {
      "192.0.2.10": lan,
      "198.51.100.7": new FakeJetKvm(),
    }, g),
    { pass: true },
  );
  const dead = await runCheck("tailnet-path", {
    "192.0.2.10": lan,
    "198.51.100.7": new FakeJetKvm({ httpDown: true }),
  }, g);
  assertEquals(dead.pass, false);
  assertStringIncludes(dead.errors![0], "already broken");
  const other = await runCheck("tailnet-path", {
    "192.0.2.10": lan,
    "198.51.100.7": new FakeJetKvm({
      scannedKey:
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTH",
    }),
  }, g);
  assertEquals(other.pass, false);
});

Deno.test("tailnetOk and describeTailnet", () => {
  const ip = "198.51.100.7";
  assert(tailnetOk(null));
  assert(tailnetOk({ ip, reachable: true, sameDevice: null, error: null }));
  assert(tailnetOk({ ip, reachable: true, sameDevice: true, error: null }));
  assert(!tailnetOk({ ip, reachable: true, sameDevice: false, error: "x" }));
  assert(!tailnetOk({ ip, reachable: false, sameDevice: null, error: "x" }));
  assertStringIncludes(
    describeTailnet({
      ip,
      reachable: false,
      sameDevice: null,
      error: "curl exit 28",
    }),
    "unreachable (curl exit 28)",
  );
});

// ---------------------------------------------------------------------------
// The tailnet is part of "rejoined" (2026-10-19: the device said online, a peer
// could not reach it)
// ---------------------------------------------------------------------------

/** The tailnet side of a device: answers or not depending on the LAN fake's state. */
class TailnetFake extends FakeJetKvm {
  constructor(
    private lan: FakeJetKvm,
    private downWhen: (lan: FakeJetKvm) => boolean,
  ) {
    super();
  }
  override device(path: string): Promise<HttpResult> {
    return this.downWhen(this.lan)
      ? Promise.reject(new Error("curl exit 28: connection timed out"))
      : super.device(path);
  }
}

async function appliedVia(
  lan: FakeJetKvm,
  tail: FakeJetKvm,
  extra: Record<string, unknown> = {},
) {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: model.globalArguments.parse({
      host: "192.0.2.10",
      tailnetIp: "198.51.100.7",
      hostKey: PINNED_KEY,
    }),
  });
  const orig = transportFactory.create;
  transportFactory.create = (g) => (g.host === "198.51.100.7" ? tail : lan);
  let error: Error | null = null;
  try {
    await model.methods.tailscaleUpdate.execute(
      parseArgs("tailscaleUpdate", { ...APPLY, ...extra }),
      context as any,
    ).catch((e) => (error = e));
  } finally {
    transportFactory.create = orig;
  }
  const [w] = getWrittenResources().map((x) => x.data as any);
  model.resources.tailscale.schema.parse(w);
  return { w, error: error as Error | null };
}

Deno.test("a swap the device reports as rejoined, but that does not answer over the tailnet, is rolled back", async () => {
  const lan = new FakeJetKvm(); // swaps, comes back Running + online, same IP
  const tail = new TailnetFake(lan, (l) => l.tsVersion === NEW);
  const { w, error } = await appliedVia(lan, tail);
  assertStringIncludes(String(error), "rolled back");
  assertEquals(w.outcome, "rolled-back");
  assertEquals(w.after.version, OLD);
  assertStringIncludes(
    w.message,
    "but tailnet from this host: 198.51.100.7 unreachable",
  );
  // After the restore the old version answers again, and the record says so.
  assertEquals(w.tailnet.reachable, true);
  assert(
    !lan.sshLog.some((l) => l.command.includes("backup-*")),
    "no prune without a verified update",
  );
  assertEquals(tail.sshLog.length, 0, "the tailnet side is never logged into");
});

Deno.test("an update whose tailnet path is already broken is refused before anything is downloaded", async () => {
  const lan = new FakeJetKvm();
  const { w, error } = await appliedVia(
    lan,
    new FakeJetKvm({ httpDown: true }),
  );
  assertStringIncludes(String(error), "already broken");
  assertEquals(w.outcome, "refused");
  assertEquals(w.tailnet.reachable, false);
  assertEquals(deviceWrites(lan).length, 0);
  assert(!lan.fetchLog.some((u) => u.endsWith(".tgz")));
});

Deno.test("with the tailnet answering, the update is done and the record carries the probe", async () => {
  const lan = new FakeJetKvm();
  const { w, error } = await appliedVia(lan, new TailnetFake(lan, () => false));
  assertEquals(error, null);
  assertEquals(w.outcome, "done");
  assertEquals(w.tailnet, {
    ip: "198.51.100.7",
    reachable: true,
    sameDevice: true,
    error: null,
  });
  assertStringIncludes(
    w.message,
    "tailnet from this host: 198.51.100.7 answers",
  );
});

Deno.test("a tailnet path that comes back within the rejoin window still counts as done", async () => {
  const lan = new FakeJetKvm();
  let misses = 3;
  const tail = new TailnetFake(lan, (l) => l.tsVersion === NEW && misses-- > 0);
  const { w, error } = await appliedVia(lan, tail, { rejoinTimeoutMs: 400 });
  assertEquals(error, null);
  assertEquals(w.outcome, "done");
});

Deno.test("rebootAfter: back after boot but not answering over the tailnet is reboot-unverified", async () => {
  const lan = new FakeJetKvm();
  const tail = new TailnetFake(lan, (l) => l.rebooted);
  const { w, error } = await appliedVia(lan, tail, {
    rebootAfter: true,
    rebootTimeoutMs: 30,
  });
  assertStringIncludes(String(error), "update applied, but");
  assertEquals(w.outcome, "reboot-unverified");
  assertStringIncludes(w.message, "tailnet: 198.51.100.7 unreachable");
});

Deno.test("without tailnetIp the update behaves as before: no tailnet probe, record tailnet null", async () => {
  const fake = new FakeJetKvm();
  const { w, error } = await applied(fake);
  assertEquals(error, null);
  assertEquals(w.outcome, "done");
  assertEquals(w.tailnet, null);
  assertEquals(fake.scans.length, 0);
});
