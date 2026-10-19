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
 * the tailnet with the same address. With `tailnetIp` set, "rejoined" also
 * means the device answers over the tailnet from the swamp host: the device's
 * own report can say Running and online while peers cannot reach it.
 *
 * Reads and writes are separate methods. `health` and `tailscale` (status, or
 * the plan for an update) never change the device; `tailscaleUpdate` always
 * does, and its labeled `live` pre-flight checks run first. The same
 * conditions are also enforced inside the method, so skipping the checks
 * skips only the early answer, never the guard.
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
  tailnetIp: z.ipv4().optional().describe(
    "The JetKVM's Tailscale IPv4 address. When set, `health` checks that the " +
      "device reports this address and fetches /metrics on it — the only test " +
      "that catches a node deleted from the tailnet, which tailscaled can keep " +
      "reporting as Running. An IP, not a MagicDNS name: inside a container a " +
      "short name can be completed by a search domain.",
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
  /**
   * The device's SSH host key of the pinned type, read with ssh-keyscan:
   * anonymous (no key is offered), so it is safe against any address.
   */
  scanHostKey(type: string): Promise<string | null>;
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
    // The session is a root shell on an appliance: never hand it the
    // operator's agent or any forwarding, whatever ~/.ssh/config says
    // (command-line options win over the config file).
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "ClearAllForwardings=yes",
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
  // Only `ssh`, `ssh-keyscan` and `curl`, with argv built from schema-validated
  // globals (sshArgs, device, scanHostKey): there is no swamp primitive for
  // SSH, and the device's self-signed TLS needs curl.
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
        // -q first: never read ~/.curlrc. --noproxy: reach the device directly,
        // or the tailnet probe would test the proxy's path, not this host's.
        "-q",
        "--noproxy",
        "*",
        "-sS",
        // A deleted tailnet node black-holes packets; fail the connect fast
        // instead of waiting out the whole budget.
        "--connect-timeout",
        String(Math.max(1, Math.min(10, Math.ceil(this.g.timeoutMs / 1000)))),
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
    try {
      if (this.g.hostKey) {
        knownHosts = await Deno.makeTempFile({ prefix: "jetkvm-kh-" });
        await Deno.writeTextFile(knownHosts, `jetkvm ${this.g.hostKey}\n`);
      }
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

  async scanHostKey(type: string): Promise<string | null> {
    const res = await run(
      "ssh-keyscan",
      [
        "-T",
        String(Math.max(1, Math.min(10, Math.ceil(this.g.timeoutMs / 1000)))),
        "-t",
        type,
        "-p",
        String(this.g.sshPort),
        "--",
        this.g.host,
      ],
      new Uint8Array(),
      this.g.timeoutMs + 5000,
    );
    const line = new TextDecoder().decode(res.stdout).split("\n")
      .find((l) => l && !l.startsWith("#"));
    const f = line?.trim().split(/\s+/);
    return f && f.length >= 3 ? `${f[1]} ${f[2]}` : null;
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
  echo "ts_daemon_version=$(${TS_DIR}/tailscaled --version 2>/dev/null | head -1)"
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
    /** tailscaled's own version; differs from `version` only after a swap cut between its renames. */
    daemonVersion: string | null;
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
      daemonVersion: s("ts_daemon_version"),
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
  /** The fetch of /metrics on `tailnetIp`; null when no tailnetIp is set. */
  tailnet: TailnetProbe | null;
}

/** Whether the web UI answered on the configured tailnet IP. */
export interface TailnetProbe {
  ip: string;
  /** Anything answered over HTTP. */
  reachable: boolean;
  /**
   * The answer came from this JetKVM: a /metrics page with jetkvm_build_info,
   * and the pinned SSH host key on that address. False when something else
   * answers; null when it could not be judged (no hostKey pinned).
   */
  sameDevice: boolean | null;
  error: string | null;
}

/**
 * Findings for the tailnet probe. `deviceIp` is the tailnet IP the device
 * reports, or null when unknown. Pure and exported for tests.
 */
export function tailnetFindings(
  tailnet: TailnetProbe | null,
  deviceIp: string | null,
): Finding[] {
  if (!tailnet) return [];
  const out: Finding[] = [];
  if (deviceIp && deviceIp !== tailnet.ip) {
    out.push({
      severity: "warn",
      code: "tailscale_ip_changed",
      message:
        `the device reports tailnet IP ${deviceIp}, not the configured ${tailnet.ip}; the node was probably re-added, so update tailnetIp`,
    });
  }
  const why = tailnet.error ? `: ${tailnet.error}` : "";
  if (!tailnet.reachable) {
    // Self.Online can lag, and a deleted node keeps saying Running: only a
    // connection from another node proves the path.
    out.push({
      severity: "warn",
      code: "tailscale_unreachable",
      message: `nothing answered on tailnet IP ${tailnet.ip}${why}`,
    });
  } else if (tailnet.sameDevice === false) {
    out.push({
      severity: "warn",
      code: "tailscale_wrong_device",
      message:
        `something other than this JetKVM answers on tailnet IP ${tailnet.ip}${why}`,
    });
  }
  return out;
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
    const mismatch = binariesMismatch(p);
    if (mismatch) {
      findings.push({
        severity: "warn",
        code: "tailscale_binaries_mismatch",
        message: mismatch,
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
  findings.push(
    ...tailnetFindings(f.tailnet, ts.installed ? ts.ip : null),
  );
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
  daemonVersion: z.string().nullable().default(null).describe(
    "tailscaled's own version. Null when unreadable, or on records from before 2026.10.19.2.",
  ),
  bootScript: z.boolean(),
  daemonRunning: z.boolean(),
  backendState: z.string().nullable(),
  online: z.boolean().nullable(),
  ip: z.string().nullable(),
  dnsName: z.string().nullable(),
});

const TailnetProbeSchema = z.object({
  ip: z.string(),
  reachable: z.boolean(),
  sameDevice: z.boolean().nullable(),
  error: z.string().nullable(),
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
  tailnet: TailnetProbeSchema.nullable().default(null).describe(
    "The anonymous probe of tailnetIp (/metrics and the SSH host key). Null when no tailnetIp is set, or on records from before 2026.10.18.1. Recorded even when SSH on the LAN fails.",
  ),
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
  tailnet: TailnetProbeSchema.nullable().default(null).describe(
    "The last anonymous probe of tailnetIp from the swamp host: after the swap (or the rollback, or the reboot), or before it for a refusal. Null without tailnetIp, before 2026.10.19.1, or when the run never got that far.",
  ),
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

/**
 * The anonymous tailnet probe: /metrics on `tailnetIp`, and with a pinned
 * hostKey an ssh-keyscan there. Null when no tailnetIp is set; never throws.
 *
 * Anonymous, so a stale address that now belongs to another node learns
 * nothing: /metrics needs no login and ssh-keyscan offers no key. Its
 * transport is built from the address and timeouts only, so it cannot be used
 * to log in. It proves the path from wherever swamp runs, not from every peer.
 */
export async function probeTailnet(
  g: GlobalArgs,
): Promise<TailnetProbe | null> {
  if (!g.tailnetIp) return null;
  const tt = transportFactory.create({
    host: g.tailnetIp,
    scheme: g.scheme,
    sshUser: g.sshUser,
    sshPort: g.sshPort,
    timeoutMs: Math.min(g.timeoutMs, 10000),
  });
  try {
    const r = await tt.device("/metrics");
    const isJetkvm = r.status === 200 &&
      parseMetrics(new TextDecoder().decode(r.body)).has("jetkvm_build_info");
    let sameKey: boolean | null = null;
    if (isJetkvm && g.hostKey) {
      const seen = await tt.scanHostKey(g.hostKey.split(" ")[0])
        .catch(() => null);
      sameKey = seen === null ? null : seen === g.hostKey;
    }
    return {
      ip: g.tailnetIp,
      reachable: true,
      sameDevice: isJetkvm ? sameKey : false,
      error: !isJetkvm
        ? `/metrics answered HTTP ${r.status} without jetkvm_build_info`
        : sameKey === false
        ? "a JetKVM answered, with a different SSH host key than the pinned one"
        : null,
    };
  } catch (e) {
    return {
      ip: g.tailnetIp,
      reachable: false,
      sameDevice: null,
      error: (e as Error).message,
    };
  }
}

/**
 * Whether a tailnet probe counts as "this device answers over the tailnet".
 * No probe (no tailnetIp) passes: there is nothing to check against. Pure.
 */
export function tailnetOk(p: TailnetProbe | null): boolean {
  return p === null || (p.reachable && p.sameDevice !== false);
}

/**
 * Stricter than tailnetOk, for the update: with a pinned hostKey the key on
 * the tailnet address must have been READ and match. health tolerates an
 * unreadable key (sameDevice null); an update must not count it as proof.
 */
export function tailnetVerified(
  p: TailnetProbe | null,
  hostKeyPinned: boolean,
): boolean {
  return tailnetOk(p) &&
    !(hostKeyPinned && p !== null && p.sameDevice === null);
}

/** One-line account of a tailnet probe, for messages. Pure. */
export function describeTailnet(p: TailnetProbe | null): string {
  if (!p) return "no tailnetIp to probe";
  if (!p.reachable) return `${p.ip} unreachable (${p.error ?? "no answer"})`;
  if (p.sameDevice === false) return `${p.ip} is another device (${p.error})`;
  if (p.sameDevice === null) {
    return `${p.ip} answers, but its SSH host key could not be read`;
  }
  return `${p.ip} answers`;
}

/**
 * Free space an update needs. At the peak /userdata holds the tarball
 * (~30 MB), the staged copy, the backup and the .new copies beside the
 * running binaries (~65 MB each): ~225 MB, rounded up for margin.
 */
export const NEED_FREE_KB = 256 * 1024;

/**
 * The pre-flight checks each need the same device facts. They run back to
 * back, so one probe serves them all; a short TTL keeps a later run from
 * judging a stale reading. A failed probe is not cached. Exported for tests.
 */
export const checkProbeCache = {
  ttlMs: 30000,
  entries: new Map<string, { at: number; p: Promise<Probe> }>(),
  clear() {
    this.entries.clear();
  },
};

/** Everything that decides which device a probe reaches and how it logs in. */
function probeKey(g: GlobalArgs): string {
  return JSON.stringify([
    g.host,
    g.sshPort,
    g.sshUser,
    g.sshKeyFile ?? null,
    g.hostKey ?? null,
  ]);
}

function forgetProbe(key: string, p: Promise<Probe>) {
  // Only our own entry: a newer probe may have replaced it since.
  if (checkProbeCache.entries.get(key)?.p === p) {
    checkProbeCache.entries.delete(key);
  }
}

function probeForChecks(g: GlobalArgs): { key: string; p: Promise<Probe> } {
  const key = probeKey(g);
  const hit = checkProbeCache.entries.get(key);
  if (hit && Date.now() - hit.at < checkProbeCache.ttlMs) {
    return { key, p: hit.p };
  }
  const p = probe(transportFactory.create(g));
  checkProbeCache.entries.set(key, { at: Date.now(), p });
  p.catch(() => forgetProbe(key, p));
  return { key, p };
}

/** Run a device-state check: probe, judge, and fail closed when the probe fails. */
async function deviceCheck(
  rawGlobals: unknown,
  judge: (p: Probe) => string | null,
): Promise<{ pass: boolean; errors?: string[] }> {
  let p: Probe;
  let entry: { key: string; p: Promise<Probe> };
  try {
    entry = probeForChecks(GlobalArgsSchema.parse(rawGlobals));
    p = await entry.p;
  } catch (e) {
    return {
      pass: false,
      errors: [`could not probe the device: ${(e as Error).message}`],
    };
  }
  const why = judge(p);
  // A failing reading is not kept: the operator fixes it and re-runs at once.
  if (why) forgetProbe(entry.key, entry.p);
  return why ? { pass: false, errors: [why] } : { pass: true };
}

/**
 * The CLI and the daemon on different versions: a swap or a rollback was cut
 * between its two renames (a power cut, or a failed second rename). The probe
 * reads the CLI's version, so without this the device would look current. Pure.
 */
export function binariesMismatch(p: Probe): string | null {
  const { version, daemonVersion } = p.tailscale;
  if (!version || !daemonVersion || version === daemonVersion) return null;
  return `tailscale is ${version} but tailscaled is ${daemonVersion}: a swap was cut between its two renames; restore both from whichever of ${TS_DIR}/backup-${daemonVersion}/ or ${TS_DIR}/backup-${version}/ exists (a cut swap leaves the daemon old, a cut rollback leaves it new) and restart tailscaled`;
}

/** Why an update must not start, judged from device facts; null when it may. Pure. */
export function installRefusal(p: Probe): string | null {
  const ts = p.tailscale;
  if (!ts.installed || !ts.version || !TS_VERSION.test(ts.version)) {
    return "Tailscale is not installed (or its version is unreadable); install it with JetKVM's install-tailscale.sh first";
  }
  // Backing up a mixed pair would make the backup itself unrestorable.
  return binariesMismatch(p);
}

/** See installRefusal. */
export function bootScriptRefusal(p: Probe): string | null {
  return p.tailscale.bootScript
    ? null
    : `${TS_BOOT} is missing: this is not the layout \`tailscale configure jetkvm\` produces, so a swap could leave it unstartable`;
}

/** See installRefusal. */
export function freeSpaceRefusal(p: Probe): string | null {
  if (p.diskFreeKb === null) {
    return "could not read free space on /userdata, so the update cannot check it fits";
  }
  if (p.diskFreeKb < NEED_FREE_KB) {
    return `/userdata has ${Math.round(p.diskFreeKb / 1024)} MB free; ${
      NEED_FREE_KB / 1024
    } MB needed`;
  }
  return null;
}

/** See installRefusal: an update the swamp host could not verify must not start. */
export function tailnetRefusal(
  t: TailnetProbe | null,
  hostKeyPinned: boolean,
): string | null {
  return tailnetVerified(t, hostKeyPinned)
    ? null
    : `the tailnet path from this host is already broken (${
      describeTailnet(t)
    }), so a swap could not be verified and would roll back; fix that first`;
}

/**
 * Stop tailscaled for good: the init script, 20 s of grace, then kill -9 and
 * 5 s more. A daemon wedged in shutdown would otherwise keep running the old
 * binary under renamed files, or hold the tunnel down with nothing to restart
 * it. Leaves the daemon stopped unless it survives kill -9 (uninterruptible).
 * `say` is how the calling script logs. Pure and exported for tests.
 */
export function stopDaemon(say: string, out = ""): string {
  return `${TS_BOOT} stop${out} || true
${WAIT_STOP}
if pidof tailscaled >/dev/null 2>&1; then
  ${say} "tailscaled did not stop in 20 s; killing it"
  kill -9 $(pidof tailscaled) 2>/dev/null || true
  i=0; while pidof tailscaled >/dev/null 2>&1 && [ $i -lt 5 ]; do sleep 1; i=$((i+1)); done
fi`;
}

const WAIT_STOP =
  "i=0; while pidof tailscaled >/dev/null 2>&1 && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done";

/** Files the detached swap leaves on the device. The log is kept for diagnosis. */
export const SWAP_SH = "/userdata/tailscale-update.sh";
export const SWAP_LOG = "/userdata/tailscale-update.log";
export const SWAP_PID = "/userdata/tailscale-update.pid";
export const SWAP_STATUS = "/userdata/tailscale-update.status";
/** The kernel boot id at launch: a launch from before a reboot is never "starting". */
export const SWAP_BOOT = "/userdata/tailscale-update.boot";
export const ROLLBACK_LOG = "/userdata/tailscale-rollback.log";

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
  # Under set -e a failed start would end the trap before the status is
  # written; the status file is what says the swap is over.
  set +e
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
${stopDaemon("log")}
# Renaming under a live daemon leaves it running the old binary while both
# files read the new version. Only an unkillable one gets here.
if pidof tailscaled >/dev/null 2>&1; then log "tailscaled survived kill -9"; exit 5; fi
log "swapping binaries"
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
  // A dropped SSH session must not abort the restore half-way: ignore HUP,
  // and send the init script's chatter to a log so a closed pipe cannot hit
  // it. Copy beside the binaries and rename over them: cp onto a still
  // running tailscaled fails ETXTBSY, a rename does not.
  return `[ -x ${backup}/tailscale ] && [ -x ${backup}/tailscaled ] || { echo "no complete backup at ${backup}"; exit 3; }
trap '' HUP
trap 'pidof tailscaled >/dev/null 2>&1 || ${TS_BOOT} start >>${ROLLBACK_LOG} 2>&1' EXIT
set -e
${stopDaemon("echo", ` >>${ROLLBACK_LOG} 2>&1`)}
for b in tailscale tailscaled; do
  cp -p ${backup}/$b ${TS_DIR}/$b.rb
  mv ${TS_DIR}/$b.rb ${TS_DIR}/$b
done
${TS_BOOT} start >>${ROLLBACK_LOG} 2>&1
echo ROLLBACK_DONE
`;
}

/**
 * Remove every Tailscale backup except the one for `keepVersion`. Pure and
 * exported for tests; the version is validated, so nothing else reaches sh.
 */
export function pruneBackupsScript(keepVersion: string): string {
  if (!TS_VERSION.test(keepVersion)) {
    throw new Error(
      "refusing to build a prune script from a non-version string",
    );
  }
  return `for d in ${TS_DIR}/backup-*; do [ -d "$d" ] && [ "$d" != ${TS_DIR}/backup-${keepVersion} ] && rm -rf "$d"; done; true`;
}

/**
 * Report the detached swap's state and log. Read-only. A pid file left by a
 * swap killed with the power proves nothing after a reboot (the pid may be
 * reused), so "running" needs that pid to still be the swap script.
 * "starting" needs the script file too (a failed upload's cleanUp removes it
 * but keeps an older run's log, which must not read as a swap) and a launch
 * from this boot: power lost before the pid was written must not block every
 * later update.
 */
export const SWAP_STATE_SCRIPT =
  `if [ -f ${SWAP_STATUS} ]; then echo "state=exited $(cat ${SWAP_STATUS})"
elif [ -f ${SWAP_PID} ] && p="$(cat ${SWAP_PID})" && [ -n "$p" ] && kill -0 "$p" 2>/dev/null && tr '\\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q "${SWAP_SH}"; then echo "state=running"
elif [ -f ${SWAP_PID} ]; then echo "state=vanished"
elif [ -f ${SWAP_LOG} ] && [ -f ${SWAP_SH} ] && b="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" && [ -n "$b" ] && [ "$(cat ${SWAP_BOOT} 2>/dev/null)" = "$b" ]; then echo "state=starting"
else echo "state=none"; fi
echo "---"
cat ${SWAP_LOG} 2>/dev/null
echo "${PROBE_END}"
`;

/** What the detached swap is doing. `unknown` when the device could not say. */
export interface SwapState {
  /** starting: the log exists but the pid is not written yet; treat as running. */
  state: "running" | "starting" | "exited" | "vanished" | "none" | "unknown";
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
  const m = head.match(
    /state=(running|starting|exited|vanished|none)(?: (\d+))?/,
  );
  if (!m) return { state: "unknown", exitCode: null, log };
  return {
    state: m[1] as SwapState["state"],
    exitCode: m[2] === undefined ? null : Number(m[2]),
    log,
  };
}

/** Why an update must not start given the device's swap state; null when it may. Pure. */
export function swapRunningRefusal(st: SwapState): string | null {
  if (st.state === "running" || st.state === "starting") {
    return `a Tailscale swap is already ${st.state} on the device (see ${SWAP_LOG}); wait for it to finish before starting another`;
  }
  if (st.state === "unknown") {
    return "could not read whether a Tailscale swap is already running on the device";
  }
  return null;
}

async function swapState(t: Transport): Promise<SwapState> {
  const r = await t.ssh("sh -s", new TextEncoder().encode(SWAP_STATE_SCRIPT))
    .catch(() => null);
  return parseSwapState(r && r.code === 0 ? r.stdout : null);
}

/** Polling cadence for the rejoin check. Exported so tests can shorten it. */
export const rejoinPoll = { intervalMs: 3000 };

/**
 * How long a device that reports itself rejoined has to also answer over the
 * tailnet before the update is judged failed. Exported so tests can shorten it.
 */
export const tailnetGrace = { ms: 45000 };

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

/** Arguments shared by `tailscale` (plan) and `tailscaleUpdate` (act). */
const UpdateArgsShape = {
  version: z.string().regex(TS_VERSION).optional().describe(
    "Target version (e.g. 1.104.1). Default: the current stable from pkgs.tailscale.com.",
  ),
  allowDowngrade: z.boolean().default(false),
  rejoinTimeoutMs: z.number().int().positive().default(120000).describe(
    "How long to wait for the node to rejoin (and, with tailnetIp, answer over the tailnet from the swamp host) before rolling back.",
  ),
  transferTimeoutMs: z.number().int().positive().default(600000),
  rebootAfter: z.boolean().default(false).describe(
    "After a verified update, reboot the KVM and wait for it to rejoin again: proves the new version starts from the boot script. The target machine is not affected; the KVM's own session drops for the reboot.",
  ),
  rebootTimeoutMs: z.number().int().positive().default(300000).describe(
    "How long to wait for the KVM to come back from rebootAfter.",
  ),
};

interface TailscaleRunArgs {
  action: "status" | "update";
  version?: string;
  allowDowngrade: boolean;
  rejoinTimeoutMs: number;
  rebootAfter: boolean;
  rebootTimeoutMs: number;
  transferTimeoutMs: number;
  apply: boolean;
}

/** The body of `tailscale` and `tailscaleUpdate`; only the latter passes apply. */
async function runTailscale(
  args: TailscaleRunArgs,
  context: Ctx,
): Promise<{ dataHandles: unknown[] }> {
  const g = context.globalArgs;
  const t = transportFactory.create(g);
  context.logger.info("JetKVM {host}: tailscale {action}{mode}", {
    host: g.host,
    action: args.action,
    mode: args.action === "update"
      ? (args.apply ? " (apply)" : " (dry run)")
      : "",
  });
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
  // Every record carries the most recent tailnet probe, so a rollback or a
  // refusal shows what the swamp host could (not) reach.
  let lastTailnet: TailnetProbe | null = null;
  const record = (rec: {
    applied: boolean;
    outcome: z.infer<typeof TailscaleSchema>["outcome"];
    message: string;
    after?: Probe["tailscale"] | null;
    sha256?: string | null;
  }) => {
    context.logger.info("JetKVM {host}: tailscale {outcome}: {message}", {
      host: g.host,
      outcome: rec.outcome,
      message: rec.message,
    });
    // Updates get their own instance: a later status or plan must not
    // become the latest record over a failed update.
    return context.writeResource(
      "tailscale",
      args.apply ? "update" : "tailscale",
      {
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
        tailnet: lastTailnet,
      },
    );
  };
  const refuse = async (why: string): Promise<never> => {
    await record({ applied: false, outcome: "refused", message: why });
    throw new Error(`tailscale ${args.action} on ${g.host}: ${why}`);
  };

  if (args.action === "status") {
    const h = await record({
      applied: false,
      outcome: "status",
      message: ts.installed
        ? `Tailscale ${ts.version ?? "?"} (${ts.backendState ?? "unknown"}${
          ts.online === null ? "" : ts.online ? ", online" : ", offline"
        })` +
          (latest && ts.version && compareVersions(latest, ts.version) > 0
            ? `; ${latest} is available`
            : "")
        : "Tailscale is not installed",
    });
    return { dataHandles: [h] };
  }

  // The same judgements as the pre-flight checks; repeated here so that
  // skipping the checks never skips the guard.
  for (const why of [installRefusal(before), bootScriptRefusal(before)]) {
    if (why) await refuse(why);
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
  const space = freeSpaceRefusal(before);
  if (space) await refuse(space);
  // A path that is already broken would make a good update look failed and
  // roll it back; say so up front instead.
  lastTailnet = await probeTailnet(g);
  const path = tailnetRefusal(lastTailnet, Boolean(g.hostKey));
  if (path) await refuse(path);
  const prior = swapRunningRefusal(await swapState(t));
  if (prior) await refuse(prior);

  const tarball = `tailscale_${target}_arm.tgz`;
  const url = `https://pkgs.tailscale.com/stable/${tarball}`;
  steps.push(
    `download ${url} on the swamp host and check it against ${url}.sha256`,
    `stream it over SSH to /userdata/tailscale-${target}.tgz and re-check its sha256 on the device`,
    `back up ${TS_DIR}/tailscale{,d} to ${TS_DIR}/backup-${ts.version}/`,
    `stop tailscaled, swap in ${target}, run \`tailscale configure jetkvm\`, start it via ${TS_BOOT} (no reboot)`,
    `wait up to ${
      args.rejoinTimeoutMs / 1000
    }s for ${target}, Running, online, tailnet IP ${ts.ip ?? "(unknown)"}${
      g.tailnetIp
        ? `, and answering anonymously on ${g.tailnetIp} from this host`
        : ""
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
        `would update ${ts.version} → ${target}; call tailscaleUpdate to act`,
    });
    return { dataHandles: [h] };
  }

  // 1. Download and verify on the swamp host, with real TLS.
  // A throw here (DNS, TLS, the transfer timeout) is a refusal like any
  // other: recorded, so the update record never lags behind the run.
  const [tgz, sum] = await Promise.all([
    t.fetch(url, args.transferTimeoutMs),
    t.fetch(`${url}.sha256`),
  ]).catch((e) =>
    refuse(`download of ${tarball} failed: ${(e as Error).message}`)
  );
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
    t.ssh(
      `rm -f ${remoteTgz} ${SWAP_SH} ${SWAP_PID} ${SWAP_STATUS} ${SWAP_BOOT}`,
    )
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
    `rm -f ${SWAP_PID} ${SWAP_STATUS} ${SWAP_LOG} ${SWAP_BOOT} && cat > ${SWAP_SH} && wc -c < ${SWAP_SH}`,
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
    `cat /proc/sys/kernel/random/boot_id > ${SWAP_BOOT} 2>/dev/null; nohup sh ${SWAP_SH} > ${SWAP_LOG} 2>&1 < /dev/null &`,
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
  // tailscaled's on-disk version too: a failed second rename leaves the old
  // binary beside the new CLI. (The swap stops the daemon, by kill -9 if it
  // must, before renaming, so the restarted process runs the file read here.)
  const rejoined = (p: Probe["tailscale"]) =>
    p.version === target &&
    (p.daemonVersion === null || p.daemonVersion === target) &&
    p.daemonRunning &&
    p.backendState === "Running" && p.online === true &&
    (ts.ip === null || p.ip === ts.ip);
  // The device's own report is not enough: on 2026-10-19 a swapped JetKVM said
  // Running and online while a peer's pings got no answer. With tailnetIp, it
  // must also answer over the tailnet from here. Probed only once the device
  // reports rejoined, so a dead path costs one capped timeout per round.
  const confirmed = async (p: Probe["tailscale"] | null) => {
    if (!p || !rejoined(p)) return false;
    lastTailnet = await probeTailnet(g);
    return tailnetVerified(lastTailnet, Boolean(g.hostKey));
  };
  // From here on a record must not carry the pre-swap probe: it would say
  // "reachable" about a device that may now be down.
  lastTailnet = null;
  const freshTailnet = async () => {
    if (g.tailnetIp) lastTailnet = await probeTailnet(g);
  };
  let after: Probe["tailscale"] | null = null;
  let ok = false;
  let st: SwapState = { state: "unknown", exitCode: null, log: "" };
  // When the device first reported itself rejoined. From then the tailnet
  // path gets tailnetGrace to answer: right after tailscaled restarts, peers
  // do not yet have its new endpoints, and a good update must not be rolled
  // back for that.
  let rejoinedAt: number | null = null;
  let lookedAgain = false;
  const started = Date.now();
  while (true) {
    await sleep(rejoinPoll.intervalMs);
    after = await probe(t).then((p) => p.tailscale).catch(() => after);
    if (after && rejoined(after)) {
      rejoinedAt ??= Date.now();
      if ((ok = await confirmed(after))) break;
    }
    const now = Date.now();
    const elapsed = now - started;
    if (elapsed < args.rejoinTimeoutMs) continue;
    if (rejoinedAt !== null) {
      if (now < rejoinedAt + tailnetGrace.ms) continue;
      st = await swapState(t);
      break;
    }
    st = await swapState(t);
    // The state check runs after this round's probe, so a swap seen to exit
    // just now was judged on the probe from before it finished: go round
    // once more (and into the grace, if it rejoined) before deciding.
    if (st.state === "exited" && !lookedAgain) {
      lookedAgain = true;
      continue;
    }
    const live = st.state === "running" || st.state === "starting";
    if (!live || elapsed >= 2 * args.rejoinTimeoutMs) {
      break;
    }
  }

  if (ok && after) {
    // Each update leaves a ~65 MB backup. Once the new version is proven,
    // keep only the one this update replaced: it is the rollback source.
    const keep = `${TS_DIR}/backup-${ts.version}`;
    const pruned = await t.ssh(pruneBackupsScript(ts.version!)).catch(
      (e) => ({ code: -1, stdout: "", stderr: (e as Error).message }),
    );
    if (pruned.code !== 0) {
      context.logger.warn(
        "could not prune old Tailscale backups on {host}: {msg}",
        { host: g.host, msg: pruned.stderr.trim() },
      );
    }
    const done =
      `updated ${ts.version} → ${target}; Running, online, ${after.ip}${
        g.tailnetIp
          ? `; tailnet from this host: ${describeTailnet(lastTailnet)}`
          : ""
      }. Backup kept in ${keep}/`;
    if (!args.rebootAfter) {
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
      await freshTailnet();
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
    let bootOk = false;
    const bootDeadline = Date.now() + args.rebootTimeoutMs;
    while (Date.now() < bootDeadline) {
      await sleep(rejoinPoll.intervalMs);
      const p = await probe(t).catch(() => null);
      if (!p) continue;
      booted = p;
      sawReboot = p.bootId !== null && p.bootId !== pre!.bootId;
      if (sawReboot && (bootOk = await confirmed(p.tailscale))) break;
    }
    if (booted && sawReboot && bootOk) {
      const msg =
        `${done}. Rebooted: back after boot with ${booted.tailscale.version}, Running, online, ${booted.tailscale.ip} (uptime ${booted.uptimeSeconds}s)`;
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
        : `after the reboot Tailscale is ${booted.tailscale.version}, ${booted.tailscale.backendState}, online=${booted.tailscale.online}, ip=${booted.tailscale.ip}${
          // lastTailnet is from after the reboot only if the device rejoined.
          g.tailnetIp && rejoined(booted.tailscale)
            ? `, tailnet: ${describeTailnet(lastTailnet)}`
            : ""}`) +
        ` within ${args.rebootTimeoutMs / 1000}s`,
      booted,
    );
  }

  // A device that reports itself rejoined failed only on the tailnet probe:
  // name it, or the message reads as if nothing was wrong.
  // Every record from here on is a failure: give it the path as it is now.
  await freshTailnet();
  const last = after
    ? `${after.version}, ${after.backendState}, online=${after.online}, ip=${after.ip}${
      g.tailnetIp && rejoined(after)
        ? `, but tailnet from this host: ${describeTailnet(lastTailnet)}`
        : ""
    }`
    : "no probe";
  const logText = st.log || "(empty)";

  // 5a. The script is still running, or the device cannot say: rolling
  // back now would race it. Leave it to a human, with what is known.
  if (
    st.state === "running" || st.state === "starting" ||
    st.state === "unknown"
  ) {
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

  // 5b. The script finished before touching the binaries: the device is
  // unchanged. Once it logged "swapping binaries" the two may be on
  // different versions, so anything short of a rejoin restores the backup.
  if (!st.log.includes("swapping binaries")) {
    // The binaries are untouched, but the swap stopped the daemon: say so if
    // it is not back, or the record reads as if nothing needs doing.
    const down = !after?.daemonRunning || after.backendState !== "Running"
      ? "; TAILSCALED IS NOT RUNNING NORMALLY: check the device"
      : "";
    await record({
      applied: false,
      outcome: "unchanged",
      message: `the swap exited (${st.state}${
        st.exitCode === null ? "" : ` ${st.exitCode}`
      }) before swapping; the binaries are unchanged on ${ts.version} (${last})${down}. Swap log: ${logText}`,
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
  // The script can wait 20 s for the daemon to stop before it copies:
  // the default per-command timeout would kill it mid-restore.
  const rbk = await t.ssh(
    "sh -s",
    new TextEncoder().encode(rollbackScript(ts.version!)),
    Math.max(g.timeoutMs, 60000) + 30000,
  ).catch((e) => ({
    code: -1,
    stdout: "",
    stderr: (e as Error).message,
  }));
  let restored: Probe["tailscale"] | null = null;
  const restoredRunning = (r: Probe["tailscale"] | null) =>
    r?.version === ts.version &&
    (r.daemonVersion === null || r.daemonVersion === ts.version) &&
    r.daemonRunning && r.backendState === "Running" && r.online === true;
  const rbDeadline = Date.now() + args.rejoinTimeoutMs;
  while (Date.now() < rbDeadline) {
    await sleep(rejoinPoll.intervalMs);
    restored = await probe(t).then((p) => p.tailscale).catch(() => null);
    if (restoredRunning(restored)) break;
  }
  const restoredOk = rbk.code === 0 && restoredRunning(restored);
  // Recorded, not judged: the old version is what worked before, and whether
  // its path came back says whether the new version was really the cause.
  await freshTailnet();
  await record({
    applied: true,
    outcome: restoredOk ? "rolled-back" : "rollback-failed",
    message:
      `${target} did not rejoin (last: ${last}); rollback exit ${rbk.code}${
        rbk.code === 0 ? "" : ` (${rbk.stderr.trim() || rbk.stdout.trim()})`
      }, now ${restored?.version ?? "unknown"} ${restored?.backendState ?? ""}${
        restoredOk && g.tailnetIp
          ? `, tailnet from this host: ${describeTailnet(lastTailnet)}`
          : ""
      }${
        restoredOk
          ? ""
          : `. NEEDS A HUMAN: restore from ${TS_DIR}/backup-${ts.version}/`
      }`,
    after: restored,
    sha256: got,
  });
  throw new Error(
    `Tailscale update on ${g.host} ${
      restoredOk ? "rolled back" : "failed AND its rollback failed"
    }; swap log:\n${logText}`,
  );
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/** The `@sntxrr/jetkvm` model: health and Tailscale updates for one JetKVM. */
export const model = {
  type: "@sntxrr/jetkvm",
  version: "2026.10.19.2",
  globalArguments: GlobalArgsSchema,

  upgrades: [
    {
      toVersion: "2026.10.18.1",
      description:
        "Adds the optional tailnetIp argument; health probes the tailnet path. Existing instances need no change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.18.2",
      description:
        "No argument change. Review fixes: the tailnet probe runs before SSH and proves identity (jetkvm_build_info and the pinned host key, read anonymously); the rollback has a budget that covers its own stop wait and survives a dropped session; old backups are pruned after a verified update.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.19.1",
      description:
        "No global-argument change. BREAKING for callers: updates moved to the new tailscaleUpdate method, behind labeled live pre-flight checks; tailscale is read-only and refuses apply: true. With tailnetIp, an update counts as rejoined only when the device also answers over the tailnet from the swamp host, and it refuses to start when that path is already broken. tailscale records gain a tailnet field (null on older records).",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.19.2",
      description:
        "No global-argument change. BREAKING for readers of update outcomes: tailscaleUpdate records move to their own `update` instance (data.latest(<model>, 'update')), so a status or plan run cannot hide a failed update; the read-only tailscale keeps the `tailscale` instance. Review fixes: the free-space check needs 256 MB (the .new copies were not counted); SSH never forwards the agent, X11 or ports; a stale pid or an old log no longer blocks updates; a swap that died between its two renames is rolled back instead of reported unchanged; the swap and the rollback stop tailscaled with kill -9 after 20 s rather than rename under it, and a rollback counts only once the old version is back online; health records from before 2026.10.18.1 parse. New health finding tailscale_binaries_mismatch (and a refusal) for a swap cut between its renames; a download that throws is recorded as refused.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],

  // Scoped with appliesTo: swamp runs an unscoped check before EVERY method
  // (measured on swamp 20261017), which would put SSH probes in front of
  // health and the read-only tailscale. The method repeats each guard, so
  // --skip-check-label live skips the early answer, never the protection.
  checks: {
    "tailscale-installed": {
      description:
        "Tailscale is installed in /userdata/tailscale, reports a version, and tailscaled is on the same one.",
      labels: ["live"],
      appliesTo: ["tailscaleUpdate"],
      execute: (context: { globalArgs: unknown }) =>
        deviceCheck(context.globalArgs, installRefusal),
    },
    "tailscale-boot-script": {
      description:
        "The boot script `tailscale configure jetkvm` writes exists, so a swapped daemon can be started.",
      labels: ["live"],
      appliesTo: ["tailscaleUpdate"],
      execute: (context: { globalArgs: unknown }) =>
        deviceCheck(context.globalArgs, bootScriptRefusal),
    },
    "userdata-free-space": {
      description:
        "/userdata has room for the tarball, the staged binaries, a backup and the new copies (256 MB).",
      labels: ["live"],
      appliesTo: ["tailscaleUpdate"],
      execute: (context: { globalArgs: unknown }) =>
        deviceCheck(context.globalArgs, freeSpaceRefusal),
    },
    "tailnet-path": {
      description:
        "With tailnetIp, the device already answers over the tailnet from this host; otherwise the update could not be verified. Passes when no tailnetIp is set.",
      labels: ["live"],
      appliesTo: ["tailscaleUpdate"],
      execute: async (context: { globalArgs: unknown }) => {
        let why: string | null;
        try {
          const g = GlobalArgsSchema.parse(context.globalArgs);
          why = tailnetRefusal(await probeTailnet(g), Boolean(g.hostKey));
        } catch (e) {
          why = `could not probe the tailnet path: ${(e as Error).message}`;
        }
        return why ? { pass: false, errors: [why] } : { pass: true };
      },
    },
    "swap-not-running": {
      description:
        "No earlier Tailscale swap is still running on the device; two would race on the same staging and backup paths.",
      labels: ["live"],
      appliesTo: ["tailscaleUpdate"],
      execute: async (context: { globalArgs: unknown }) => {
        let why: string | null;
        try {
          const g = GlobalArgsSchema.parse(context.globalArgs);
          why = swapRunningRefusal(await swapState(transportFactory.create(g)));
        } catch (e) {
          why = `could not read the swap state: ${(e as Error).message}`;
        }
        return why ? { pass: false, errors: [why] } : { pass: true };
      },
    },
  },

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
        "Tailscale on the device. Instance `tailscale`: status and plans from the read-only `tailscale` method. Instance `update`: every outcome of `tailscaleUpdate` (since 2026.10.19.2), so a later status or plan never hides a failed update.",
      schema: TailscaleSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  methods: {
    health: {
      description:
        "Read-only health check: web UI reachability and app version (/metrics), then an SSH probe for system version, USB gadget state, disk, clock and Tailscale (version, daemon, online, boot script, and with tailnetIp an anonymous probe over the tailnet that also checks the same device answers). Compares app/system against JetKVM's release API and Tailscale against pkgs.tailscale.com. Records an unreachable device as verdict 'fail' rather than throwing, so a scheduled check always leaves a record.",
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
        context.logger.info("JetKVM {host}: checking health", { host: g.host });
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
          tailnet: null,
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

        // The tailnet probe does not depend on SSH, so it runs first and is
        // recorded on every path: with the LAN down it is what tells "device
        // dead" from "LAN broken". See probeTailnet for why it is anonymous.
        const tailnet = await probeTailnet(g);
        if (tailnet) {
          context.logger.info(
            "JetKVM {host}: tailnet {ip} reachable={reachable} sameDevice={same}",
            {
              host: g.host,
              ip: g.tailnetIp,
              reachable: tailnet.reachable,
              same: String(tailnet.sameDevice),
            },
          );
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
          findings.push(...tailnetFindings(tailnet, null));
          const h = await context.writeResource("health", "health", {
            ...blank,
            appVersion,
            timeSynced,
            httpOk,
            sshOk: false,
            verdict: "fail",
            findings,
            tailnet,
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
          tailnet,
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
          tailnet,
          error: httpError,
        });
        return { dataHandles: [h] };
      },
    },

    tailscale: {
      description:
        "Read-only: report Tailscale on the JetKVM (action status), or plan an update (action update) and record every step it would take, including any refusal. Never changes the device. To update, call tailscaleUpdate. Since 2026.10.19.1 `apply: true` is refused here rather than ignored, so a caller written for the old method fails loudly instead of silently becoming a dry run.",
      arguments: z.object({
        action: z.enum(["status", "update"]).default("status"),
        ...UpdateArgsShape,
        apply: z.boolean().default(false).describe(
          "Removed in 2026.10.19.1: true is refused. Use tailscaleUpdate.",
        ),
      }),
      execute: async (
        args: Omit<TailscaleRunArgs, "apply"> & { apply: boolean },
        context: Ctx,
      ): Promise<{ dataHandles: unknown[] }> => {
        if (args.apply) {
          throw new Error(
            "tailscale is read-only since @sntxrr/jetkvm 2026.10.19.1: apply: true is refused, nothing was done. Call tailscaleUpdate to update.",
          );
        }
        return await runTailscale({ ...args, apply: false }, context);
      },
    },

    tailscaleUpdate: {
      description:
        "Update Tailscale on the JetKVM. Always acts; plan first with `tailscale` action update. " +
        "The device has no CA store, so `tailscale update` cannot run there: this method downloads the official arm tarball on the swamp host, checks its sha256, streams it over SSH, backs up the running binaries, swaps them, re-runs `tailscale configure jetkvm` and restarts tailscaled without a reboot. " +
        "It then waits for the node to be Running and online with the same tailnet IP (when the old one was readable) and, with tailnetIp, to answer anonymously over the tailnet from the swamp host; otherwise it restores the backup by itself. " +
        "The labeled `live` pre-flight checks run first; the method enforces the same conditions itself. " +
        "Every outcome after the first device probe is recorded as the `update` instance of the tailscale resource.",
      arguments: z.object(UpdateArgsShape),
      execute: async (
        args: Omit<TailscaleRunArgs, "action" | "apply">,
        context: Ctx,
      ): Promise<{ dataHandles: unknown[] }> =>
        await runTailscale({ ...args, action: "update", apply: true }, context),
    },
  },
};
