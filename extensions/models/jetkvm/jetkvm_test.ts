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
  compareVersions,
  evaluateHealth,
  type HttpResult,
  model,
  parseMetrics,
  parseProbe,
  type Probe,
  PROBE_END,
  rejoinPoll,
  rollbackScript,
  sshArgs,
  type SshResult,
  swapScript,
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
    "cp -p /userdata/tailscale/backup-1.98.8/tailscale",
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
// Scripted device
// ---------------------------------------------------------------------------

const TGZ = enc("fake tarball bytes");
const WRONG_SHA = "0".repeat(64);

class FakeJetKvm implements Transport {
  sshLog: { command: string; stdin: string }[] = [];
  fetchLog: string[] = [];
  tsVersion = "1.98.8";
  online = true;
  uptime = 5000;
  /** What a reboot does: "ok" comes back, "dead" never answers, "noboot" loses Tailscale, "ignored" never reboots. */
  rebootOutcome: "ok" | "dead" | "noboot" | "ignored" = "ok";
  rebooted = false;
  script = "";
  /** What the swap does to the device: "ok" joins, "stuck" never rejoins. */
  swapOutcome: "ok" | "stuck" = "ok";
  sha = "";
  constructor(
    private opts: {
      httpDown?: boolean;
      sshDown?: boolean;
      truncated?: boolean;
      badSum?: boolean;
      probeOver?: Record<string, string>;
    } = {},
  ) {}

  device(path: string): Promise<HttpResult> {
    if (this.opts.httpDown) {
      return Promise.reject(new Error("Failed to connect"));
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

  ssh(command: string, stdin?: Uint8Array): Promise<SshResult> {
    this.sshLog.push({ command, stdin: stdin ? dec(stdin) : "" });
    if (this.opts.sshDown) {
      return Promise.resolve({
        code: 255,
        stdout: "",
        stderr: "Permission denied (publickey).",
      });
    }
    if (command === "sh -s" && stdin && dec(stdin).includes(PROBE_END)) {
      if (this.rebooted && this.rebootOutcome === "dead") {
        return Promise.resolve({
          code: 255,
          stdout: "",
          stderr: "Connection refused",
        });
      }
      this.uptime += 1;
      return Promise.resolve({
        code: 0,
        stdout: probeText(
          {
            ts_version: this.tsVersion,
            ts_online: String(this.online),
            uptime: String(this.uptime),
            ...this.opts.probeOver,
          },
          !this.opts.truncated,
        ),
        stderr: "",
      });
    }
    if (
      command.startsWith("cat > /userdata/tailscale-") &&
      command.includes("sha256sum")
    ) {
      return Promise.resolve({
        code: 0,
        stdout: `${this.sha}  /userdata/x.tgz\n`,
        stderr: "",
      });
    }
    if (command.includes("reboot")) {
      if (this.rebootOutcome !== "ignored") {
        this.rebooted = true;
        this.uptime = 10;
      }
      if (this.rebootOutcome === "noboot") this.online = false;
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    if (command.startsWith("cat > /userdata/tailscale-update.sh")) {
      // Like sh: a backgrounded list gets /dev/null as stdin.
      this.script = command.trimEnd().endsWith("&")
        ? ""
        : (stdin ? dec(stdin) : "");
      return Promise.resolve({
        code: 0,
        stdout: command.includes("wc -c") ? `${enc(this.script).length}\n` : "",
        stderr: "",
      });
    }
    if (command.includes("nohup sh /userdata/tailscale-update.sh")) {
      if (!this.script.includes("binaries swapped")) {
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      if (this.swapOutcome === "ok") this.tsVersion = "1.104.1";
      else {
        this.tsVersion = "1.104.1";
        this.online = false;
      }
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    if (command === "sh -s" && stdin && dec(stdin).includes("ROLLBACK_DONE")) {
      this.tsVersion = "1.98.8";
      this.online = true;
      return Promise.resolve({
        code: 0,
        stdout: "ROLLBACK_DONE\n",
        stderr: "",
      });
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  }

  async fetch(url: string): Promise<HttpResult> {
    this.fetchLog.push(url);
    if (url.startsWith("https://pkgs.tailscale.com/stable/?mode=json")) {
      return {
        status: 200,
        body: enc(JSON.stringify({ TarballsVersion: "1.104.1" })),
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
      const d = await crypto.subtle.digest("SHA-256", TGZ);
      const hex = Array.from(new Uint8Array(d)).map((b) =>
        b.toString(16).padStart(2, "0")
      ).join("");
      this.sha = hex;
      return { status: 200, body: enc(this.opts.badSum ? WRONG_SHA : hex) };
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
  assertEquals(d.latestTailscale, "1.104.1");
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
  fake.tsVersion = "1.104.1";
  const d = await runHealth(fake);
  assertEquals(d.verdict, "warn");
  assertEquals(d.findings[0].code, "web_unreachable");
});

// ---------------------------------------------------------------------------
// tailscale
// ---------------------------------------------------------------------------

const runTs = (fake: FakeJetKvm, a: Record<string, unknown>) => {
  const { context, getWrittenResources } = ctx();
  const p = withFake(
    fake,
    () =>
      model.methods.tailscale.execute(
        parseArgs("tailscale", a),
        context as any,
      ),
  );
  return { p, written: () => getWrittenResources().map((w) => w.data as any) };
};

const deviceWrites = (fake: FakeJetKvm) =>
  fake.sshLog.filter((l) =>
    !(l.command === "sh -s" && l.stdin.includes(PROBE_END))
  );

Deno.test("tailscale status reports the version and the available update, touching nothing", async () => {
  const fake = new FakeJetKvm();
  const { p, written } = await runTs(fake, {});
  await p;
  const [w] = written();
  model.resources.tailscale.schema.parse(w);
  assertEquals(w.outcome, "status");
  assertStringIncludes(w.message, "1.104.1 is available");
  assertEquals(deviceWrites(fake).length, 0);
});

Deno.test("tailscale update without apply is a dry run listing every step", async () => {
  const fake = new FakeJetKvm();
  const { p, written } = await runTs(fake, { action: "update" });
  await p;
  const [w] = written();
  assertEquals(w.outcome, "dry-run");
  assertEquals(w.targetVersion, "1.104.1");
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

Deno.test("tailscale update applies: verify, upload, swap, and confirm the same node rejoined", async () => {
  const fake = new FakeJetKvm();
  const { p, written } = await runTs(fake, { action: "update", apply: true });
  await p;
  const [w] = written();
  model.resources.tailscale.schema.parse(w);
  assertEquals(w.outcome, "done");
  assertEquals(w.after.version, "1.104.1");
  assertEquals(w.after.ip, "198.51.100.7");
  const cmds = deviceWrites(fake).map((l) => l.command);
  assert(cmds[0].startsWith("cat > /userdata/tailscale-1.104.1.tgz"));
  assertEquals(deviceWrites(fake)[0].stdin, dec(TGZ));
  assert(cmds[1].startsWith("cat > /userdata/tailscale-update.sh"));
  assert(
    !cmds[1].trimEnd().endsWith("&"),
    "the script write must not be backgrounded",
  );
  assertStringIncludes(deviceWrites(fake)[1].stdin, "backup-1.98.8");
  assertStringIncludes(cmds[2], "nohup sh /userdata/tailscale-update.sh");
  assertStringIncludes(cmds[2], "< /dev/null");
});

Deno.test("tailscale update refuses a tarball whose sha256 does not match, before touching the device", async () => {
  const fake = new FakeJetKvm({ badSum: true });
  const { p, written } = await runTs(fake, { action: "update", apply: true });
  await assertRejects(() => p, Error, "sha256 mismatch");
  assertEquals(written()[0].outcome, "refused");
  assertEquals(deviceWrites(fake).length, 0);
});

Deno.test("tailscale update rolls back when the node does not come back online", async () => {
  const fake = new FakeJetKvm();
  fake.swapOutcome = "stuck";
  const { p, written } = await runTs(fake, {
    action: "update",
    apply: true,
    rejoinTimeoutMs: 30,
  });
  await assertRejects(() => p, Error, "rolled back");
  const [w] = written();
  assertEquals(w.outcome, "rolled-back");
  assertEquals(w.after.version, "1.98.8");
  assert(deviceWrites(fake).some((l) => l.stdin.includes("ROLLBACK_DONE")));
});

Deno.test("tailscale update is a no-op when already current, and refuses downgrades", async () => {
  const cur = new FakeJetKvm();
  cur.tsVersion = "1.104.1";
  const a = await runTs(cur, { action: "update", apply: true });
  await a.p;
  assertEquals(a.written()[0].outcome, "current");
  assertEquals(deviceWrites(cur).length, 0);

  const down = new FakeJetKvm();
  const b = await runTs(down, {
    action: "update",
    version: "1.90.0",
    apply: true,
  });
  await assertRejects(() => b.p, Error, "older than");
  assertEquals(deviceWrites(down).length, 0);
});

Deno.test("tailscale update refuses without the vendor boot script or an install", async () => {
  const noBoot = new FakeJetKvm({ probeOver: { ts_boot: "0" } });
  const a = await runTs(noBoot, { action: "update", apply: true });
  await assertRejects(() => a.p, Error, "S22tailscale");
  const none = new FakeJetKvm({ probeOver: { ts_installed: "0" } });
  const b = await runTs(none, { action: "update", apply: true });
  await assertRejects(() => b.p, Error, "not installed");
  assertEquals(deviceWrites(noBoot).length + deviceWrites(none).length, 0);
});

Deno.test("version argument rejects anything that is not x.y.z", () => {
  assert(
    !model.methods.tailscale.arguments.safeParse({ version: "1.2.3;reboot" })
      .success,
  );
});

Deno.test("rebootAfter: reboots once after a verified update and requires a fresh boot that rejoins", async () => {
  const fake = new FakeJetKvm();
  const { p, written } = runTs(fake, {
    action: "update",
    apply: true,
    rebootAfter: true,
  });
  await p;
  const [w] = written();
  model.resources.tailscale.schema.parse(w);
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
  stuck.swapOutcome = "stuck";
  const b = runTs(stuck, {
    action: "update",
    apply: true,
    rebootAfter: true,
    rejoinTimeoutMs: 30,
  });
  await assertRejects(() => b.p, Error, "rolled back");
  assert(!deviceWrites(stuck).some((l) => l.command.includes("reboot")));
});

for (
  const [outcome, msg] of [
    ["dead", "did not answer SSH"],
    ["noboot", "after the reboot Tailscale"],
    ["ignored", "never showed a reboot"],
  ] as const
) {
  Deno.test(`rebootAfter fails loudly, never green, when the reboot is ${outcome}`, async () => {
    const fake = new FakeJetKvm();
    fake.rebootOutcome = outcome;
    const { p, written } = runTs(fake, {
      action: "update",
      apply: true,
      rebootAfter: true,
      rebootTimeoutMs: 30,
    });
    await assertRejects(() => p, Error, msg);
    const [w] = written();
    model.resources.tailscale.schema.parse(w);
    assertEquals(w.outcome, "reboot-unverified");
    assertStringIncludes(w.message, "backup-1.98.8");
  });
}

Deno.test("tailscale update reports a swap that never took effect as unchanged, without a pointless rollback", async () => {
  const fake = new FakeJetKvm();
  // the launch runs, but the device never changes (e.g. the script died before swapping)
  fake.script = "";
  const origSsh = fake.ssh.bind(fake);
  fake.ssh = (command: string, stdin?: Uint8Array) =>
    command.includes("nohup")
      ? Promise.resolve({ code: 0, stdout: "", stderr: "" })
      : origSsh(command, stdin);
  const { p, written } = runTs(fake, {
    action: "update",
    apply: true,
    rejoinTimeoutMs: 30,
  });
  await assertRejects(() => p, Error, "device unchanged");
  const [w] = written();
  assertEquals(w.outcome, "rolled-back");
  assertStringIncludes(w.message, "did not take effect");
  assert(!deviceWrites(fake).some((l) => l.stdin.includes("ROLLBACK_DONE")));
});
