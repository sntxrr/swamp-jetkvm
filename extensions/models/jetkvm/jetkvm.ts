/**
 * Operate a JetKVM from swamp: health checks and Tailscale updates.
 *
 * ## Three things about these devices that shape the code
 *
 * **Almost nothing is on HTTP.** The JetKVM web UI talks to the device over a
 * WebRTC data channel: video, USB state, version, update status and every
 * setting are JSON-RPC calls on that channel, and there is no snapshot
 * endpoint at all. The plain HTTP surface is a login form, `/device/status`
 * and an unauthenticated Prometheus `/metrics` page, which carries the app
 * version (`jetkvm_build_info`) and NTP sync state. Everything else this model
 * reads over **SSH as root**, which the device offers once developer mode is on
 * and a public key is installed. That is a prerequisite, not an accident, and
 * `health` reports it as a posture finding.
 *
 * **There is no CA store on the device.** `tailscale update` run on a JetKVM
 * fails with `x509: certificate signed by unknown authority`, and so would any
 * other HTTPS fetch from it. So downloads happen on the machine running swamp,
 * with proper TLS, and are streamed to the device over SSH. The same goes for
 * the firmware release check: the model reads the device ID over SSH and asks
 * JetKVM's release API itself.
 *
 * **Tailscale is an add-on with a fixed layout.** JetKVM's own installer puts
 * the binaries in `/userdata/tailscale/`, and `tailscale configure jetkvm`
 * writes `/userdata/init.d/S22tailscale`, which survives firmware updates from
 * system 0.2.7 on. `tailscale update` here keeps that layout: it backs up the
 * running binaries, swaps in the new ones, re-runs `configure jetkvm`, restarts
 * the daemon (no reboot), and rolls back by itself if the node does not rejoin
 * the tailnet with the same address.
 *
 * Every method that changes the device defaults to a dry run; pass
 * `apply: true` to act.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  host: z.string().min(1).regex(/^[A-Za-z0-9.:_][A-Za-z0-9.:_-]*$/).describe(
    "Address of the JetKVM: a LAN IP or a hostname that resolves from wherever " +
      "swamp runs. Prefer the LAN IP: a Tailscale update restarts tailscaled, " +
      "which would cut an SSH session that runs over the tailnet.",
  ),
  scheme: z.enum(["http", "https"]).default("http").describe(
    "Scheme of the web UI, used only for the unauthenticated /metrics page. " +
      "With https the device's self-signed certificate is not verified.",
  ),
  sshUser: z.string().min(1).regex(/^[a-z_][a-z0-9_-]*$/).default("root")
    .describe("SSH user. JetKVM developer mode authorises keys for root."),
  sshPort: z.number().int().min(1).max(65535).default(22),
  sshKeyFile: z.string().optional().describe(
    "Private key for SSH. Omit to use the ssh agent and ~/.ssh/config.",
  ),
  hostKey: z.string().regex(
    /^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]+$/,
  )
    .optional().describe(
      "Pin the device's SSH host key ('ssh-ed25519 AAAA...'). Without it, the " +
        "user's known_hosts must already hold the key; either way an unknown " +
        "or changed key fails the connection rather than being accepted.",
    ),
  timeoutMs: z.number().int().positive().default(20000).describe(
    "Timeout for one HTTP request or SSH command (uploads take their own).",
  ),
});

/** Validated global arguments for one JetKVM. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** Raw HTTP response. */
export interface HttpResult {
  status: number;
  body: Uint8Array;
}

/** Result of one remote command. */
export interface SshResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Everything the model needs from the network, injectable for tests. */
export interface Transport {
  /** GET a path on the device's web UI. */
  device(path: string): Promise<HttpResult>;
  /** Run `command` on the device, feeding `stdin` to it. */
  ssh(
    command: string,
    stdin?: Uint8Array,
    timeoutMs?: number,
  ): Promise<SshResult>;
  /** GET a public URL with full TLS verification (release APIs, tarballs). */
  fetch(url: string, timeoutMs?: number): Promise<HttpResult>;
}

/** The `ssh` argv for one command. Pure and exported for tests. */
export function sshArgs(
  g: GlobalArgs,
  knownHostsFile: string | null,
  command: string,
): string[] {
  const args = [
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ConnectTimeout=10",
    // A shared master from the user's config could be talking to a different
    // device that once had this address.
    "-o",
    "ControlPath=none",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
    "-p",
    String(g.sshPort),
  ];
  if (knownHostsFile) {
    args.push(
      "-o",
      `UserKnownHostsFile=${knownHostsFile}`,
      "-o",
      "GlobalKnownHostsFile=/dev/null",
      "-o",
      "HostKeyAlias=jetkvm",
    );
  }
  if (g.sshKeyFile) args.push("-i", g.sshKeyFile, "-o", "IdentitiesOnly=yes");
  args.push("-l", g.sshUser, "--", g.host, command);
  return args;
}

async function run(
  cmd: string,
  args: string[],
  stdin: Uint8Array,
  timeoutMs: number,
): Promise<{ code: number; stdout: Uint8Array; stderr: string }> {
  // Only `ssh` and `curl`, with argv built from schema-validated globals
  // (sshArgs, device): there is no swamp primitive for SSH, and the device's
  // self-signed TLS needs curl.
  // swamp-quality-ignore deno-command
  const child = new Deno.Command(cmd, {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      child.kill("SIGKILL");
    } catch { /* already exited */ }
  }, timeoutMs);
  try {
    const w = child.stdin.getWriter();
    await w.write(stdin).catch(() => {});
    await w.close().catch(() => {});
    const out = await child.output();
    const stderr = new TextDecoder().decode(out.stderr);
    return {
      code: out.code,
      stdout: out.stdout,
      stderr: timedOut ? `timed out after ${timeoutMs}ms; ${stderr}` : stderr,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Default transport: `curl` for the device, `ssh` for commands, fetch for the internet. */
export class CliTransport implements Transport {
  constructor(private readonly g: GlobalArgs) {}

  async device(path: string): Promise<HttpResult> {
    const host = this.g.host.includes(":") ? `[${this.g.host}]` : this.g.host;
    const outFile = await Deno.makeTempFile({ prefix: "jetkvm-" });
    try {
      const args = [
        "-sS",
        "--max-time",
        String(Math.ceil(this.g.timeoutMs / 1000)),
        "-o",
        outFile,
        "-w",
        "%{http_code}",
      ];
      // The device's certificate is self-signed; nothing secret is sent.
      if (this.g.scheme === "https") args.push("--insecure");
      args.push(`${this.g.scheme}://${host}${path}`);
      const res = await run(
        "curl",
        args,
        new Uint8Array(),
        this.g.timeoutMs + 5000,
      );
      if (res.code !== 0) {
        throw new Error(
          `GET ${path} on ${this.g.host} failed (curl exit ${res.code}): ${res.stderr.trim()}`,
        );
      }
      return {
        status: Number(new TextDecoder().decode(res.stdout)),
        body: await Deno.readFile(outFile),
      };
    } finally {
      await Deno.remove(outFile).catch(() => {});
    }
  }

  async ssh(
    command: string,
    stdin: Uint8Array = new Uint8Array(),
    timeoutMs = this.g.timeoutMs,
  ): Promise<SshResult> {
    // A per-call known_hosts file, removed afterwards: it holds only the
    // public host key, but nothing should be left in the temp dir.
    let knownHosts: string | null = null;
    if (this.g.hostKey) {
      knownHosts = await Deno.makeTempFile({ prefix: "jetkvm-kh-" });
      await Deno.writeTextFile(knownHosts, `jetkvm ${this.g.hostKey}\n`);
    }
    try {
      const res = await run(
        "ssh",
        sshArgs(this.g, knownHosts, command),
        stdin,
        timeoutMs,
      );
      return {
        code: res.code,
        stdout: new TextDecoder().decode(res.stdout),
        stderr: res.stderr,
      };
    } finally {
      if (knownHosts) await Deno.remove(knownHosts).catch(() => {});
    }
  }

  async fetch(url: string, timeoutMs = this.g.timeoutMs): Promise<HttpResult> {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
      .catch((e) => {
        throw new Error(`GET ${url} failed: ${(e as Error).message}`);
      });
    return {
      status: res.status,
      body: new Uint8Array(await res.arrayBuffer()),
    };
  }
}

/**
 * Seam for tests: swap `create` to inject a fake transport. Production code
 * never touches this.
 */
export const transportFactory = {
  create: (g: GlobalArgs): Transport => new CliTransport(g),
};

// ---------------------------------------------------------------------------
// Parsing (pure)
// ---------------------------------------------------------------------------

/** Parse Prometheus text exposition into `name{labels}` → samples. */
export function parseMetrics(
  text: string,
): Map<string, { labels: Record<string, string>; value: number }[]> {
  const out = new Map<
    string,
    { labels: Record<string, string>; value: number }[]
  >();
  for (const line of text.split("\n")) {
    const m = line.match(/^([a-zA-Z_:][\w:]*)(\{([^}]*)\})?\s+(\S+)/);
    if (!m) continue;
    const labels: Record<string, string> = {};
    for (const l of (m[3] ?? "").matchAll(/(\w+)="((?:[^"\\]|\\.)*)"/g)) {
      labels[l[1]] = l[2];
    }
    const list = out.get(m[1]) ?? [];
    list.push({ labels, value: Number(m[4]) });
    out.set(m[1], list);
  }
  return out;
}

/** Sentinel the probe prints last; a run without it is incomplete, not clean. */
export const PROBE_END = "__JETKVM_PROBE_END__";

/** Tailscale's binaries and boot script, as `tailscale configure jetkvm` lays them out. */
export const TS_DIR = "/userdata/tailscale";
export const TS_BOOT = "/userdata/init.d/S22tailscale";

/**
 * Read-only device probe, run with `sh -s`. Prints `key=value` lines and the
 * end sentinel. It never reads kvm_config.json, which holds the password hash
 * and cloud token.
 */
export const PROBE_SCRIPT = `
echo "system=$(cat /version 2>/dev/null)"
echo "serial=$(awk -F': ' '/^Serial/{print $2}' /proc/cpuinfo 2>/dev/null)"
for f in /sys/class/udc/*/state; do [ -r "$f" ] && echo "usb=$(cat "$f")"; done
echo "devmode=$([ -e /userdata/jetkvm/devmode.enable ] && echo 1 || echo 0)"
echo "uptime=$(cut -d' ' -f1 /proc/uptime)"
echo "now=$(date -u +%s)"
echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
df -k /userdata 2>/dev/null | tail -1 | awk '{print "disk="$(NF-4)","$(NF-2)}'
echo "video=$(ps 2>/dev/null | grep -o 'native+video{[a-z]*}' | head -1)"
ts=${TS_DIR}/tailscale
if [ -x "$ts" ]; then
  echo "ts_installed=1"
  echo "ts_version=$("$ts" version 2>/dev/null | head -1)"
  echo "ts_boot=$([ -x ${TS_BOOT} ] && echo 1 || echo 0)"
  echo "ts_daemon=$(pidof tailscaled >/dev/null 2>&1 && echo 1 || echo 0)"
  st=$("$ts" status --json --peers=false 2>/dev/null)
  echo "ts_backend=$(echo "$st" | grep -m1 '"BackendState"' | sed 's/.*: *"\\([^"]*\\)".*/\\1/')"
  echo "ts_online=$(echo "$st" | grep -m1 '"Online"' | sed 's/.*: *\\([a-z]*\\).*/\\1/')"
  echo "ts_ip=$(echo "$st" | sed -n '/"TailscaleIPs"/,/]/p' | grep -o '"[0-9][0-9.]*"' | head -1 | tr -d '"')"
  echo "ts_dns=$(echo "$st" | grep -m1 '"DNSName"' | sed 's/.*: *"\\([^"]*\\)".*/\\1/')"
else
  echo "ts_installed=0"
fi
echo "${PROBE_END}"
`;

/** What the probe found. Nulls mean the device did not say. */
export interface Probe {
  systemVersion: string | null;
  serial: string | null;
  usbState: string | null;
  devMode: boolean;
  uptimeSeconds: number | null;
  deviceTime: number | null;
  /** Kernel boot id: changes on every boot, unlike uptime it cannot be misread. */
  bootId: string | null;
  diskTotalKb: number | null;
  diskFreeKb: number | null;
  videoPipeline: string | null;
  tailscale: {
    installed: boolean;
    version: string | null;
    bootScript: boolean;
    daemonRunning: boolean;
    backendState: string | null;
    online: boolean | null;
    ip: string | null;
    dnsName: string | null;
  };
}

/** Parse the probe output. Throws when the end sentinel is missing. */
export function parseProbe(stdout: string): Probe {
  if (!stdout.includes(PROBE_END)) {
    throw new Error(
      `probe output is incomplete (no end marker; ${stdout.length} bytes)`,
    );
  }
  const kv = new Map<string, string>();
  for (const line of stdout.split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) kv.set(line.slice(0, i).trim(), line.slice(i + 1).trim());
  }
  const s = (k: string): string | null => kv.get(k) || null;
  const n = (k: string): number | null => {
    const v = Number(kv.get(k));
    return kv.get(k) && Number.isFinite(v) ? v : null;
  };
  const [total, free] = (kv.get("disk") ?? "").split(",").map(Number);
  const video = s("video")?.match(/\{([a-z]+)\}/)?.[1] ?? null;
  const online = s("ts_online");
  return {
    systemVersion: s("system"),
    serial: s("serial"),
    usbState: s("usb"),
    devMode: kv.get("devmode") === "1",
    uptimeSeconds: n("uptime"),
    deviceTime: n("now"),
    bootId: s("boot_id"),
    diskTotalKb: Number.isFinite(total) && total > 0 ? total : null,
    diskFreeKb: Number.isFinite(free) && total > 0 ? free : null,
    videoPipeline: video,
    tailscale: {
      installed: kv.get("ts_installed") === "1",
      version: s("ts_version"),
      bootScript: kv.get("ts_boot") === "1",
      daemonRunning: kv.get("ts_daemon") === "1",
      backendState: s("ts_backend"),
      online: online === "true" ? true : online === "false" ? false : null,
      ip: s("ts_ip"),
      dnsName: s("ts_dns"),
    },
  };
}

/** Compare dotted versions numerically; a leading `v` is ignored. */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) =>
    v.replace(/^v/, "").split(/[.-]/).map((p) => Number(p) || 0);
  const pa = parts(a), pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

/** Tailscale versions are plain x.y.z; anything else never reaches a shell. */
const TS_VERSION = /^\d+\.\d+\.\d+$/;

// ---------------------------------------------------------------------------
// Health evaluation (pure)
// ---------------------------------------------------------------------------

const FindingSchema = z.object({
  severity: z.enum(["info", "warn", "fail"]),
  code: z.string(),
  message: z.string(),
});

/** One observation from `health`. Only `warn` and `fail` affect the verdict. */
export type Finding = z.infer<typeof FindingSchema>;

/** The facts `evaluateHealth` judges. */
export interface HealthFacts {
  checkedAt: Date;
  appVersion: string | null;
  latestApp: string | null;
  latestSystem: string | null;
  timeSynced: boolean | null;
  probe: Probe;
  latestTailscale: string | null;
  strictSecurity: boolean;
  maxClockSkewSeconds: number;
  minFreeDiskPercent: number;
}

/** Turn device facts into findings and a verdict. Pure and exported for tests. */
export function evaluateHealth(f: HealthFacts): {
  findings: Finding[];
  verdict: "ok" | "warn" | "fail";
} {
  const findings: Finding[] = [];
  const p = f.probe;
  const ts = p.tailscale;

  if (
    f.appVersion && f.latestApp &&
    compareVersions(f.latestApp, f.appVersion) > 0
  ) {
    findings.push({
      severity: "warn",
      code: "app_update_available",
      message: `app ${f.appVersion} is installed; ${f.latestApp} is available`,
    });
  }
  if (
    p.systemVersion && f.latestSystem &&
    compareVersions(f.latestSystem, p.systemVersion) > 0
  ) {
    findings.push({
      severity: "warn",
      code: "system_update_available",
      message:
        `system ${p.systemVersion} is installed; ${f.latestSystem} is available`,
    });
  }
  if (p.usbState !== null && p.usbState !== "configured") {
    findings.push({
      severity: "warn",
      code: "usb_not_configured",
      message:
        `USB gadget state is '${p.usbState}': the target has not enumerated the KVM's keyboard and mouse`,
    });
  }
  if (p.diskTotalKb && p.diskFreeKb !== null) {
    const pct = (p.diskFreeKb / p.diskTotalKb) * 100;
    if (pct < f.minFreeDiskPercent) {
      findings.push({
        severity: "warn",
        code: "disk_low",
        message: `/userdata is ${Math.round(100 - pct)}% full`,
      });
    }
  }
  if (f.timeSynced === false) {
    findings.push({
      severity: "warn",
      code: "clock_unsynced",
      message: "the device reports its clock is not synchronised",
    });
  }
  if (p.deviceTime !== null) {
    const skew = Math.abs(p.deviceTime - f.checkedAt.getTime() / 1000);
    if (skew > f.maxClockSkewSeconds) {
      findings.push({
        severity: "warn",
        code: "clock_skew",
        message: `device clock is ${Math.round(skew)}s off`,
      });
    }
  }

  if (!ts.installed) {
    findings.push({
      severity: "info",
      code: "tailscale_not_installed",
      message: `no Tailscale under ${TS_DIR}`,
    });
  } else {
    if (!ts.daemonRunning || ts.backendState !== "Running") {
      findings.push({
        severity: "warn",
        code: "tailscale_down",
        message: `tailscaled is ${
          ts.daemonRunning
            ? `in state ${ts.backendState ?? "unknown"}`
            : "not running"
        }`,
      });
    } else if (ts.online === false) {
      findings.push({
        severity: "warn",
        code: "tailscale_offline",
        message:
          "tailscaled is running but the coordination server sees it offline",
      });
    }
    if (!ts.bootScript) {
      findings.push({
        severity: "warn",
        code: "tailscale_boot_script_missing",
        message:
          `${TS_BOOT} is missing, so Tailscale will not start after a reboot`,
      });
    }
    if (
      ts.version && f.latestTailscale &&
      compareVersions(f.latestTailscale, ts.version) > 0
    ) {
      findings.push({
        severity: "warn",
        code: "tailscale_update_available",
        message:
          `Tailscale ${ts.version} is installed; ${f.latestTailscale} is the current stable`,
      });
    }
  }
  if (p.devMode) {
    findings.push({
      severity: f.strictSecurity ? "warn" : "info",
      code: "developer_mode_enabled",
      message:
        "developer mode is on: root SSH is open to the installed key (this model needs it)",
    });
  }

  const verdict = findings.some((x) => x.severity === "fail")
    ? "fail"
    : findings.some((x) => x.severity === "warn")
    ? "warn"
    : "ok";
  return { findings, verdict };
}

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

const TailscaleStateSchema = z.object({
  installed: z.boolean(),
  version: z.string().nullable(),
  bootScript: z.boolean(),
  daemonRunning: z.boolean(),
  backendState: z.string().nullable(),
  online: z.boolean().nullable(),
  ip: z.string().nullable(),
  dnsName: z.string().nullable(),
});

const HealthSchema = z.object({
  host: z.string(),
  checkedAt: z.string(),
  httpOk: z.boolean(),
  sshOk: z.boolean(),
  verdict: z.enum(["ok", "warn", "fail"]),
  findings: z.array(FindingSchema),
  appVersion: z.string().nullable(),
  latestApp: z.string().nullable(),
  systemVersion: z.string().nullable(),
  latestSystem: z.string().nullable(),
  deviceId: z.string().nullable(),
  usbState: z.string().nullable().describe(
    "USB gadget state from /sys/class/udc; 'configured' means the target enumerated it.",
  ),
  videoPipeline: z.string().nullable().describe(
    "The app's video pipeline state (e.g. 'inactive' with no viewer). Not proof of an HDMI signal either way.",
  ),
  timeSynced: z.boolean().nullable(),
  uptimeSeconds: z.number().nullable(),
  diskFreeBytes: z.number().nullable(),
  developerMode: z.boolean().nullable(),
  tailscale: TailscaleStateSchema.nullable(),
  latestTailscale: z.string().nullable(),
  error: z.string().nullable(),
});

const TailscaleSchema = z.object({
  host: z.string(),
  at: z.string(),
  action: z.enum(["status", "update"]),
  applied: z.boolean(),
  outcome: z.enum([
    "status",
    "current",
    "dry-run",
    "done",
    "refused",
    "unchanged",
    "rolled-back",
    "rollback-failed",
    "swap-unconfirmed",
    "reboot-unverified",
  ]).describe(
    "unchanged: the swap never took effect. rollback-failed and swap-unconfirmed need a human: the device may be on either version, or have tailscaled down.",
  ),
  message: z.string(),
  fromVersion: z.string().nullable(),
  targetVersion: z.string().nullable(),
  latestVersion: z.string().nullable(),
  sha256: z.string().nullable(),
  before: TailscaleStateSchema,
  after: TailscaleStateSchema.nullable(),
  steps: z.array(z.string()).describe("What was (or would be) done, in order."),
});

// ---------------------------------------------------------------------------
// Helpers shared by methods
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new Uint8Array(data));
  return Array.from(new Uint8Array(d)).map((b) =>
    b.toString(16).padStart(2, "0")
  )
    .join("");
}

/** Run the probe; throws on SSH failure or truncated output. */
export async function probe(t: Transport): Promise<Probe> {
  const res = await t.ssh("sh -s", new TextEncoder().encode(PROBE_SCRIPT));
  if (res.code !== 0) {
    throw new Error(
      `SSH probe failed (exit ${res.code}): ${
        res.stderr.trim() || "no error output"
      }`,
    );
  }
  return parseProbe(res.stdout);
}

/** Current stable Tailscale version from pkgs.tailscale.com. */
export async function latestTailscale(t: Transport): Promise<string> {
  const r = await t.fetch("https://pkgs.tailscale.com/stable/?mode=json");
  if (r.status !== 200) throw new Error(`pkgs.tailscale.com: HTTP ${r.status}`);
  const v = JSON.parse(new TextDecoder().decode(r.body))?.TarballsVersion;
  if (typeof v !== "string" || !TS_VERSION.test(v)) {
    throw new Error(`pkgs.tailscale.com returned no usable version`);
  }
  return v;
}

/** Latest app and system versions JetKVM offers this device. */
export async function latestFirmware(
  t: Transport,
  deviceId: string,
): Promise<{ app: string | null; system: string | null }> {
  const q = new URLSearchParams({ deviceId, prerelease: "false" });
  const r = await t.fetch(`https://api.jetkvm.com/releases?${q}`);
  if (r.status !== 200) throw new Error(`api.jetkvm.com: HTTP ${r.status}`);
  const j = JSON.parse(new TextDecoder().decode(r.body));
  return {
    app: typeof j?.appVersion === "string" ? j.appVersion : null,
    system: typeof j?.systemVersion === "string" ? j.systemVersion : null,
  };
}

/** Files the detached swap leaves on the device. The log is kept for diagnosis. */
export const SWAP_SH = "/userdata/tailscale-update.sh";
export const SWAP_LOG = "/userdata/tailscale-update.log";
export const SWAP_PID = "/userdata/tailscale-update.pid";
export const SWAP_STATUS = "/userdata/tailscale-update.status";

/**
 * The on-device swap, run detached so that it finishes even if the SSH
 * session that started it drops. It records its PID, and on any exit its
 * status, removes its staging files, and makes sure tailscaled is running, so
 * a failure part-way never leaves the daemon down. Pure and exported for tests.
 */
export function swapScript(version: string, fromVersion: string): string {
  if (!TS_VERSION.test(version) || !TS_VERSION.test(fromVersion)) {
    throw new Error(
      "refusing to build a swap script from a non-version string",
    );
  }
  const stage = `/userdata/tailscale-stage-${version}`;
  const tgz = `/userdata/tailscale-${version}.tgz`;
  const backup = `${TS_DIR}/backup-${fromVersion}`;
  return `log() { echo "$(date -u +%H:%M:%S) $*"; }
echo $$ > ${SWAP_PID}
finish() {
  rc=$?
  rm -rf ${stage} ${tgz} ${TS_DIR}/tailscale.new ${TS_DIR}/tailscaled.new ${backup}.tmp
  pidof tailscaled >/dev/null 2>&1 || ${TS_BOOT} start
  log "exit $rc"
  echo "$rc" > ${SWAP_STATUS}
}
trap finish EXIT
set -e
cd /userdata
rm -rf ${stage}
mkdir -p ${stage}
tar xzf ${tgz} -C ${stage}
src=${stage}/tailscale_${version}_arm
[ -x "$src/tailscale" ] && [ -x "$src/tailscaled" ] || { log "tarball lacks binaries"; exit 3; }
if [ ! -d ${backup} ]; then
  rm -rf ${backup}.tmp
  mkdir -p ${backup}.tmp
  cp -p ${TS_DIR}/tailscale ${TS_DIR}/tailscaled ${backup}.tmp/
  mv ${backup}.tmp ${backup}
fi
[ -x ${backup}/tailscale ] && [ -x ${backup}/tailscaled ] || { log "backup in ${backup} is incomplete"; exit 4; }
log "backup ready in ${backup}"
cp "$src/tailscale" ${TS_DIR}/tailscale.new
cp "$src/tailscaled" ${TS_DIR}/tailscaled.new
${TS_BOOT} stop || true
i=0; while pidof tailscaled >/dev/null 2>&1 && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
mv ${TS_DIR}/tailscale.new ${TS_DIR}/tailscale
mv ${TS_DIR}/tailscaled.new ${TS_DIR}/tailscaled
log "binaries swapped"
${TS_DIR}/tailscale configure jetkvm || log "configure jetkvm failed (non-fatal)"
${TS_BOOT} start
log "tailscaled started"
log "SWAP_DONE"
`;
}

/**
 * Restore the backed-up binaries and restart. Checks the backup before
 * stopping anything, and starts tailscaled on any exit. Pure and exported.
 */
export function rollbackScript(fromVersion: string): string {
  if (!TS_VERSION.test(fromVersion)) {
    throw new Error(
      "refusing to build a rollback script from a non-version string",
    );
  }
  const backup = `${TS_DIR}/backup-${fromVersion}`;
  return `[ -x ${backup}/tailscale ] && [ -x ${backup}/tailscaled ] || { echo "no complete backup at ${backup}"; exit 3; }
trap 'pidof tailscaled >/dev/null 2>&1 || ${TS_BOOT} start' EXIT
set -e
${TS_BOOT} stop || true
i=0; while pidof tailscaled >/dev/null 2>&1 && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
cp -p ${backup}/tailscale ${backup}/tailscaled ${TS_DIR}/
${TS_BOOT} start
echo ROLLBACK_DONE
`;
}

/** Report the detached swap's state and log. Read-only. */
export const SWAP_STATE_SCRIPT =
  `if [ -f ${SWAP_STATUS} ]; then echo "state=exited $(cat ${SWAP_STATUS})"
elif [ -f ${SWAP_PID} ] && kill -0 "$(cat ${SWAP_PID})" 2>/dev/null; then echo "state=running"
elif [ -f ${SWAP_PID} ]; then echo "state=vanished"
else echo "state=none"; fi
echo "---"
cat ${SWAP_LOG} 2>/dev/null
echo "${PROBE_END}"
`;

/** What the detached swap is doing. `unknown` when the device could not say. */
export interface SwapState {
  state: "running" | "exited" | "vanished" | "none" | "unknown";
  exitCode: number | null;
  log: string;
}

/** Parse SWAP_STATE_SCRIPT output. Pure and exported for tests. */
export function parseSwapState(stdout: string | null): SwapState {
  if (!stdout || !stdout.includes(PROBE_END)) {
    return { state: "unknown", exitCode: null, log: "" };
  }
  const [head, ...rest] = stdout.split("\n---\n");
  const log = rest.join("\n---\n").replace(PROBE_END, "").trim();
  const m = head.match(/state=(running|exited|vanished|none)(?: (\d+))?/);
  if (!m) return { state: "unknown", exitCode: null, log };
  return {
    state: m[1] as SwapState["state"],
    exitCode: m[2] === undefined ? null : Number(m[2]),
    log,
  };
}

async function swapState(t: Transport): Promise<SwapState> {
  const r = await t.ssh("sh -s", new TextEncoder().encode(SWAP_STATE_SCRIPT))
    .catch(() => null);
  return parseSwapState(r && r.code === 0 ? r.stdout : null);
}

/** Polling cadence for the rejoin check. Exported so tests can shorten it. */
export const rejoinPoll = { intervalMs: 3000 };

interface Ctx {
  globalArgs: GlobalArgs;
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<unknown>;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warn: (msg: string, props?: Record<string, unknown>) => void;
  };
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/** The `@sntxrr/jetkvm` model: health and Tailscale updates for one JetKVM. */
export const model = {
  type: "@sntxrr/jetkvm",
  version: "2026.10.16.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    health: {
      description:
        "Device health, firmware and Tailscale currency, and posture.",
      schema: HealthSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    tailscale: {
      description:
        "Tailscale state on the device and the outcome of an update.",
      schema: TailscaleSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  methods: {
    health: {
      description:
        "Read-only health check: web UI reachability and app version (/metrics), then an SSH probe for system version, USB gadget state, disk, clock and Tailscale (version, daemon, online, boot script). Compares app/system against JetKVM's release API and Tailscale against pkgs.tailscale.com. Records an unreachable device as verdict 'fail' rather than throwing, so a scheduled check always leaves a record.",
      arguments: z.object({
        checkUpdates: z.boolean().default(true).describe(
          "Ask api.jetkvm.com and pkgs.tailscale.com for the latest versions. A failure there is logged, not counted.",
        ),
        strictSecurity: z.boolean().default(false).describe(
          "Promote developer_mode_enabled from info to warn.",
        ),
        maxClockSkewSeconds: z.number().int().positive().default(300),
        minFreeDiskPercent: z.number().min(0).max(100).default(10),
      }),
      execute: async (
        args: {
          checkUpdates: boolean;
          strictSecurity: boolean;
          maxClockSkewSeconds: number;
          minFreeDiskPercent: number;
        },
        context: Ctx,
      ): Promise<{ dataHandles: unknown[] }> => {
        const g = context.globalArgs;
        const t = transportFactory.create(g);
        const checkedAt = new Date();
        context.logger.info("JetKVM {host}: health check", { host: g.host });
        const blank = {
          host: g.host,
          checkedAt: checkedAt.toISOString(),
          appVersion: null,
          latestApp: null,
          systemVersion: null,
          latestSystem: null,
          deviceId: null,
          usbState: null,
          videoPipeline: null,
          timeSynced: null,
          uptimeSeconds: null,
          diskFreeBytes: null,
          developerMode: null,
          tailscale: null,
          latestTailscale: null,
        };

        let httpOk = false;
        let httpError: string | null = null;
        let appVersion: string | null = null;
        let timeSynced: boolean | null = null;
        try {
          const r = await t.device("/metrics");
          if (r.status !== 200) throw new Error(`/metrics: HTTP ${r.status}`);
          const m = parseMetrics(new TextDecoder().decode(r.body));
          appVersion = m.get("jetkvm_build_info")?.[0]?.labels.version ?? null;
          const sync = m.get("jetkvm_timesync_status")?.[0]?.value;
          timeSynced = sync === undefined ? null : sync === 1;
          httpOk = true;
        } catch (e) {
          httpError = (e as Error).message;
        }

        let p: Probe;
        try {
          p = await probe(t);
        } catch (e) {
          const msg = (e as Error).message;
          const findings: Finding[] = [];
          if (httpError) {
            findings.push({
              severity: "fail",
              code: "unreachable",
              message: httpError,
            });
          }
          findings.push({
            severity: "fail",
            code: "ssh_failed",
            message:
              `${msg}. Needs developer mode on, this key authorised, and a known host key`,
          });
          context.logger.warn("JetKVM {host}: {msg}", { host: g.host, msg });
          const h = await context.writeResource("health", "health", {
            ...blank,
            appVersion,
            timeSynced,
            httpOk,
            sshOk: false,
            verdict: "fail",
            findings,
            error: httpError ? `${httpError}; ${msg}` : msg,
          });
          return { dataHandles: [h] };
        }

        let latestApp: string | null = null;
        let latestSystem: string | null = null;
        let latestTs: string | null = null;
        if (args.checkUpdates) {
          if (p.serial) {
            await latestFirmware(t, p.serial).then((v) => {
              latestApp = v.app;
              latestSystem = v.system;
            }).catch((e) =>
              context.logger.warn("firmware release check failed: {msg}", {
                msg: (e as Error).message,
              })
            );
          }
          if (p.tailscale.installed) {
            latestTs = await latestTailscale(t).catch((e) => {
              context.logger.warn("Tailscale release check failed: {msg}", {
                msg: (e as Error).message,
              });
              return null;
            });
          }
        }

        const { findings, verdict } = evaluateHealth({
          checkedAt,
          appVersion,
          latestApp,
          latestSystem,
          timeSynced,
          probe: p,
          latestTailscale: latestTs,
          strictSecurity: args.strictSecurity,
          maxClockSkewSeconds: args.maxClockSkewSeconds,
          minFreeDiskPercent: args.minFreeDiskPercent,
        });
        if (httpError) {
          findings.unshift({
            severity: "warn",
            code: "web_unreachable",
            message: `SSH works but the web UI did not answer: ${httpError}`,
          });
        }
        const finalVerdict = verdict === "ok" && httpError ? "warn" : verdict;

        context.logger.info("JetKVM {host}: {verdict} ({n} findings)", {
          host: g.host,
          verdict: finalVerdict,
          n: findings.length,
        });
        const h = await context.writeResource("health", "health", {
          ...blank,
          httpOk,
          sshOk: true,
          verdict: finalVerdict,
          findings,
          appVersion,
          latestApp,
          systemVersion: p.systemVersion,
          latestSystem,
          deviceId: p.serial,
          usbState: p.usbState,
          videoPipeline: p.videoPipeline,
          timeSynced,
          uptimeSeconds: p.uptimeSeconds,
          diskFreeBytes: p.diskFreeKb === null ? null : p.diskFreeKb * 1024,
          developerMode: p.devMode,
          tailscale: p.tailscale,
          latestTailscale: latestTs,
          error: httpError,
        });
        return { dataHandles: [h] };
      },
    },

    tailscale: {
      description:
        "Report Tailscale on the JetKVM, or update it. The device has no CA store, so `tailscale update` cannot run there: this method downloads the official arm tarball on the swamp host, checks its sha256, streams it over SSH, backs up the running binaries, swaps them, re-runs `tailscale configure jetkvm` and restarts tailscaled without a reboot. It then waits for the node to be Running and online with the same tailnet IP, and restores the backup by itself if it is not. Dry run unless apply is true.",
      arguments: z.object({
        action: z.enum(["status", "update"]).default("status"),
        version: z.string().regex(TS_VERSION).optional().describe(
          "Target version (e.g. 1.104.1). Default: the current stable from pkgs.tailscale.com.",
        ),
        allowDowngrade: z.boolean().default(false),
        rejoinTimeoutMs: z.number().int().positive().default(120000).describe(
          "How long to wait for the node to rejoin before rolling back.",
        ),
        transferTimeoutMs: z.number().int().positive().default(600000),
        rebootAfter: z.boolean().default(false).describe(
          "After a verified update, reboot the KVM and wait for it to rejoin again: proves the new version starts from the boot script. The target machine is not affected; the KVM's own session drops for the reboot.",
        ),
        rebootTimeoutMs: z.number().int().positive().default(300000).describe(
          "How long to wait for the KVM to come back from rebootAfter.",
        ),
        apply: z.boolean().default(false).describe(
          "Actually update. Without it, report what would happen.",
        ),
      }),
      execute: async (
        args: {
          action: "status" | "update";
          version?: string;
          allowDowngrade: boolean;
          rejoinTimeoutMs: number;
          rebootAfter: boolean;
          rebootTimeoutMs: number;
          transferTimeoutMs: number;
          apply: boolean;
        },
        context: Ctx,
      ): Promise<{ dataHandles: unknown[] }> => {
        const g = context.globalArgs;
        const t = transportFactory.create(g);
        const before = await probe(t);
        const ts = before.tailscale;
        const latest = await latestTailscale(t).catch((e) => {
          context.logger.warn("Tailscale release check failed: {msg}", {
            msg: (e as Error).message,
          });
          return null;
        });
        const target = args.version ?? latest;
        const steps: string[] = [];
        const record = (rec: {
          applied: boolean;
          outcome: string;
          message: string;
          after?: Probe["tailscale"] | null;
          sha256?: string | null;
        }) =>
          context.writeResource("tailscale", "tailscale", {
            host: g.host,
            at: new Date().toISOString(),
            action: args.action,
            fromVersion: ts.version,
            targetVersion: target,
            latestVersion: latest,
            before: ts,
            steps,
            ...rec,
            after: rec.after ?? null,
            sha256: rec.sha256 ?? null,
          });
        const refuse = async (why: string): Promise<never> => {
          await record({ applied: false, outcome: "refused", message: why });
          throw new Error(`tailscale ${args.action} on ${g.host}: ${why}`);
        };

        if (args.action === "status") {
          const h = await record({
            applied: false,
            outcome: "status",
            message: ts.installed
              ? `Tailscale ${ts.version ?? "?"} (${
                ts.backendState ?? "unknown"
              }${
                ts.online === null ? "" : ts.online ? ", online" : ", offline"
              })` +
                (latest && ts.version && compareVersions(latest, ts.version) > 0
                  ? `; ${latest} is available`
                  : "")
              : "Tailscale is not installed",
          });
          return { dataHandles: [h] };
        }

        if (!ts.installed || !ts.version || !TS_VERSION.test(ts.version)) {
          await refuse(
            "Tailscale is not installed (or its version is unreadable); install it with JetKVM's install-tailscale.sh first",
          );
        }
        if (!ts.bootScript) {
          await refuse(
            `${TS_BOOT} is missing: this is not the layout \`tailscale configure jetkvm\` produces, so a swap could leave it unstartable`,
          );
        }
        if (!target) {
          await refuse(
            "no target version: pass `version`, or let pkgs.tailscale.com be reached",
          );
        }
        const cmp = compareVersions(target!, ts.version!);
        if (cmp === 0) {
          const h = await record({
            applied: false,
            outcome: "current",
            message: `already on ${target}`,
          });
          return { dataHandles: [h] };
        }
        if (cmp < 0 && !args.allowDowngrade) {
          await refuse(
            `${target} is older than the installed ${ts.version}; pass allowDowngrade: true to go back`,
          );
        }
        // Tarball (~30 MB) + staged copy (~65 MB) + backup (~65 MB).
        const needKb = 200 * 1024;
        if (before.diskFreeKb === null) {
          await refuse(
            "could not read free space on /userdata, so the update cannot check it fits",
          );
        }
        if (before.diskFreeKb! < needKb) {
          await refuse(
            `/userdata has ${Math.round(before.diskFreeKb! / 1024)} MB free; ${
              needKb / 1024
            } MB needed`,
          );
        }

        const tarball = `tailscale_${target}_arm.tgz`;
        const url = `https://pkgs.tailscale.com/stable/${tarball}`;
        steps.push(
          `download ${url} on the swamp host and check it against ${url}.sha256`,
          `stream it over SSH to /userdata/tailscale-${target}.tgz and re-check its sha256 on the device`,
          `back up ${TS_DIR}/tailscale{,d} to ${TS_DIR}/backup-${ts.version}/`,
          `stop tailscaled, swap in ${target}, run \`tailscale configure jetkvm\`, start it via ${TS_BOOT} (no reboot)`,
          `wait up to ${
            args.rejoinTimeoutMs / 1000
          }s for ${target}, Running, online, tailnet IP ${
            ts.ip ?? "(unknown)"
          }; otherwise restore the backup`,
        );
        if (args.rebootAfter) {
          steps.push(
            `reboot the KVM and wait up to ${
              args.rebootTimeoutMs / 1000
            }s for it to come back the same way (no automatic rollback after this point; the backup stays)`,
          );
        }
        if (!args.apply) {
          const h = await record({
            applied: false,
            outcome: "dry-run",
            message:
              `would update ${ts.version} → ${target}; pass apply: true to act`,
          });
          return { dataHandles: [h] };
        }

        // 1. Download and verify on the swamp host, with real TLS.
        const [tgz, sum] = await Promise.all([
          t.fetch(url, args.transferTimeoutMs),
          t.fetch(`${url}.sha256`),
        ]);
        if (tgz.status !== 200 || sum.status !== 200) {
          await refuse(
            `download failed: ${tarball} HTTP ${tgz.status}, .sha256 HTTP ${sum.status}`,
          );
        }
        const want = new TextDecoder().decode(sum.body).trim().split(/\s+/)[0];
        const got = await sha256Hex(tgz.body);
        if (!/^[0-9a-f]{64}$/.test(want) || got !== want) {
          await refuse(
            `sha256 mismatch for ${tarball}: got ${got}, expected ${want}`,
          );
        }

        // 2. Upload and re-verify on the device.
        context.logger.info("Tailscale update on {host}: {from} → {to}", {
          host: g.host,
          from: ts.version,
          to: target,
        });
        const remoteTgz = `/userdata/tailscale-${target}.tgz`;
        const cleanUp = () =>
          t.ssh(`rm -f ${remoteTgz} ${SWAP_SH} ${SWAP_PID} ${SWAP_STATUS}`)
            .catch(() => null);
        const up = await t.ssh(
          `cat > ${remoteTgz} && sha256sum ${remoteTgz}`,
          tgz.body,
          args.transferTimeoutMs,
        );
        if (up.code !== 0 || up.stdout.trim().split(/\s+/)[0] !== got) {
          await cleanUp();
          await refuse(
            `upload did not verify on the device (exit ${up.code}): ${up.stderr.trim()}`,
          );
        }

        // 3. Swap, detached so a dropped session cannot strand it half-done.
        // Writing the script and launching it are two sessions on purpose: in
        // `cat > f && nohup sh f &` the `&` backgrounds the whole list, and sh
        // gives a background job /dev/null as stdin, so cat writes an empty
        // file and nothing runs (seen live). The byte count proves it landed.
        const script = new TextEncoder().encode(
          swapScript(target!, ts.version!),
        );
        const wrote = await t.ssh(
          `rm -f ${SWAP_PID} ${SWAP_STATUS} ${SWAP_LOG} && cat > ${SWAP_SH} && wc -c < ${SWAP_SH}`,
          script,
        );
        if (wrote.code !== 0 || Number(wrote.stdout.trim()) !== script.length) {
          await cleanUp();
          await refuse(
            `the swap script did not land on the device (exit ${wrote.code}, ${
              wrote.stdout.trim() || 0
            } of ${script.length} bytes): ${wrote.stderr.trim()}`,
          );
        }
        const swap = await t.ssh(
          `nohup sh ${SWAP_SH} > ${SWAP_LOG} 2>&1 < /dev/null &`,
        ).catch((e) => ({
          code: -1,
          stdout: "",
          stderr: (e as Error).message,
        }));
        if (swap.code !== 0) {
          // The session can drop after the job started; only a device that
          // shows no trace of the script counts as "never started".
          const st = await swapState(t);
          if (st.state === "none") {
            await cleanUp();
            await refuse(
              `could not start the swap (exit ${swap.code}): ${swap.stderr.trim()}`,
            );
          }
          context.logger.warn(
            "swap launch on {host} returned exit {code}, but the device shows it {state}; watching it",
            { host: g.host, code: swap.code, state: st.state },
          );
        }

        // 4. Wait for the node to come back as the same machine. Past the
        // deadline, keep waiting while the script is still running (a slow tar
        // on armv7), up to twice the timeout: deciding while it runs would
        // race it.
        const rejoined = (p: Probe["tailscale"]) =>
          p.version === target && p.daemonRunning &&
          p.backendState === "Running" && p.online === true &&
          (ts.ip === null || p.ip === ts.ip);
        let after: Probe["tailscale"] | null = null;
        let st: SwapState = { state: "unknown", exitCode: null, log: "" };
        const started = Date.now();
        while (true) {
          await sleep(rejoinPoll.intervalMs);
          after = await probe(t).then((p) => p.tailscale).catch(() => after);
          if (after && rejoined(after)) break;
          const elapsed = Date.now() - started;
          if (elapsed < args.rejoinTimeoutMs) continue;
          st = await swapState(t);
          if (st.state !== "running" || elapsed >= 2 * args.rejoinTimeoutMs) {
            break;
          }
        }

        if (after && rejoined(after)) {
          const done =
            `updated ${ts.version} → ${target}; Running, online, ${after.ip}. Backup kept in ${TS_DIR}/backup-${ts.version}/`;
          if (!args.rebootAfter) {
            context.logger.info("{host}: {msg}", { host: g.host, msg: done });
            const h = await record({
              applied: true,
              outcome: "done",
              message: done,
              after,
              sha256: got,
            });
            return { dataHandles: [h] };
          }

          // 4b. Prove it also starts from the boot script. A reboot is seen as
          // a new kernel boot id; without one to compare, do not reboot.
          const unverified = async (why: string, last: Probe | null) => {
            await record({
              applied: true,
              outcome: "reboot-unverified",
              message:
                `${done}. But ${why}. Restore by hand from ${TS_DIR}/backup-${ts.version}/ if needed`,
              after: last?.tailscale ?? after,
              sha256: got,
            });
            throw new Error(
              `Tailscale on ${g.host}: update applied, but ${why}`,
            );
          };
          const pre = await probe(t).catch(() => null);
          if (!pre?.bootId) {
            await unverified(
              "the boot id could not be read before rebooting, so the KVM was not rebooted",
              pre,
            );
          }
          context.logger.info(
            "rebooting {host} to verify Tailscale starts at boot",
            { host: g.host },
          );
          const rb = await t.ssh("(sleep 1; reboot) >/dev/null 2>&1 &").catch((
            e,
          ) => ({ code: -1, stdout: "", stderr: (e as Error).message }));
          if (rb.code !== 0) {
            await unverified(
              `the reboot command failed (exit ${rb.code}): ${rb.stderr.trim()}`,
              pre,
            );
          }
          let booted: Probe | null = null;
          let sawReboot = false;
          const bootDeadline = Date.now() + args.rebootTimeoutMs;
          while (Date.now() < bootDeadline) {
            await sleep(rejoinPoll.intervalMs);
            const p = await probe(t).catch(() => null);
            if (!p) continue;
            booted = p;
            sawReboot = p.bootId !== null && p.bootId !== pre!.bootId;
            if (sawReboot && rejoined(p.tailscale)) break;
          }
          if (booted && sawReboot && rejoined(booted.tailscale)) {
            const msg =
              `${done}. Rebooted: back after boot with ${booted.tailscale.version}, Running, online, ${booted.tailscale.ip} (uptime ${booted.uptimeSeconds}s)`;
            context.logger.info("{host}: {msg}", { host: g.host, msg });
            const h = await record({
              applied: true,
              outcome: "done",
              message: msg,
              after: booted.tailscale,
              sha256: got,
            });
            return { dataHandles: [h] };
          }
          await unverified(
            (!booted
              ? "the KVM did not answer SSH after the reboot"
              : !sawReboot
              ? "the KVM never showed a reboot (boot id unchanged)"
              : `after the reboot Tailscale is ${booted.tailscale.version}, ${booted.tailscale.backendState}, online=${booted.tailscale.online}, ip=${booted.tailscale.ip}`) +
              ` within ${args.rebootTimeoutMs / 1000}s`,
            booted,
          );
        }

        const last = after
          ? `${after.version}, ${after.backendState}, online=${after.online}, ip=${after.ip}`
          : "no probe";
        const logText = st.log || "(empty)";

        // 5a. The script is still running, or the device cannot say: rolling
        // back now would race it. Leave it to a human, with what is known.
        if (st.state === "running" || st.state === "unknown") {
          await record({
            applied: true,
            outcome: "swap-unconfirmed",
            message: `the swap is ${st.state} after ${
              2 * args.rejoinTimeoutMs / 1000
            }s (last: ${last}); not rolling back while it may still act. Check ${SWAP_LOG} and ${SWAP_STATUS}; backup in ${TS_DIR}/backup-${ts.version}/`,
            after,
            sha256: got,
          });
          throw new Error(
            `Tailscale update on ${g.host} is unconfirmed (swap ${st.state}); swap log:\n${logText}`,
          );
        }

        // 5b. The script finished without swapping: the device is unchanged.
        if (!st.log.includes("binaries swapped")) {
          await record({
            applied: false,
            outcome: "unchanged",
            message: `the swap exited (${st.state}${
              st.exitCode === null ? "" : ` ${st.exitCode}`
            }) before swapping; the device is unchanged on ${ts.version} (${last}). Swap log: ${logText}`,
            after,
            sha256: got,
          });
          throw new Error(
            `Tailscale update on ${g.host} did not take effect; device unchanged. Swap log:\n${logText}`,
          );
        }

        // 5c. It was swapped and did not come back: restore the old binaries.
        context.logger.warn(
          "Tailscale on {host} did not rejoin as {to}; rolling back. Swap log: {log}",
          { host: g.host, to: target, log: logText },
        );
        const rbk = await t.ssh(
          "sh -s",
          new TextEncoder().encode(rollbackScript(ts.version!)),
        ).catch((e) => ({
          code: -1,
          stdout: "",
          stderr: (e as Error).message,
        }));
        let restored: Probe["tailscale"] | null = null;
        const rbDeadline = Date.now() + args.rejoinTimeoutMs;
        while (Date.now() < rbDeadline) {
          await sleep(rejoinPoll.intervalMs);
          restored = await probe(t).then((p) => p.tailscale).catch(() => null);
          if (
            restored?.version === ts.version && restored.daemonRunning &&
            restored.backendState === "Running"
          ) break;
        }
        const ok = rbk.code === 0 && restored?.version === ts.version &&
          restored.daemonRunning && restored.backendState === "Running";
        await record({
          applied: true,
          outcome: ok ? "rolled-back" : "rollback-failed",
          message:
            `${target} did not rejoin (last: ${last}); rollback exit ${rbk.code}${
              rbk.code === 0
                ? ""
                : ` (${rbk.stderr.trim() || rbk.stdout.trim()})`
            }, now ${restored?.version ?? "unknown"} ${
              restored?.backendState ?? ""
            }${
              ok
                ? ""
                : `. NEEDS A HUMAN: restore from ${TS_DIR}/backup-${ts.version}/`
            }`,
          after: restored,
          sha256: got,
        });
        throw new Error(
          `Tailscale update on ${g.host} ${
            ok ? "rolled back" : "failed AND its rollback failed"
          }; swap log:\n${logText}`,
        );
      },
    },
  },
};
