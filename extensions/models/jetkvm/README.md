# @sntxrr/jetkvm

Operate a [JetKVM](https://jetkvm.com) from swamp: health checks and Tailscale
updates.

Model type: `@sntxrr/jetkvm`

## Why this exists

Three things about the device make it unlike other IP-KVMs:

**Almost nothing is on HTTP.** The web UI talks to the device over a WebRTC
data channel. Video, USB state, version, update status and every setting are
JSON-RPC calls on that channel, and there is no snapshot endpoint. The plain
HTTP surface is a login form, `/device/status`, and an unauthenticated
Prometheus `/metrics` page, which carries the app version
(`jetkvm_build_info`) and NTP sync state. This model reads that page, and
everything else over **SSH as root**. That needs developer mode on, with your
public key installed. Without it, `health` fails with `ssh_failed`.

**The device has no CA store.** `tailscale update` run on a JetKVM fails with
`x509: certificate signed by unknown authority`, and so would any HTTPS fetch
from it. Downloads happen on the machine running swamp, with full TLS
verification, and are streamed to the device over SSH. The firmware release
check works the same way: the model reads the device ID over SSH and asks
`api.jetkvm.com` itself.

**Tailscale is an add-on with a fixed layout.** JetKVM's
[`install-tailscale.sh`](https://jetkvm.com/docs/networking/remote-access)
puts the binaries in `/userdata/tailscale/`, and `tailscale configure jetkvm`
writes `/userdata/init.d/S22tailscale`. On system 0.2.7 and later that location
survives firmware updates. The update method keeps this layout.

There is **no screenshot method**. A frame can only be had by negotiating
WebRTC and decoding H.264, which this model does not do.

## Methods

| Method      | Writes?          | What it does                                                         |
| ----------- | ---------------- | -------------------------------------------------------------------- |
| `health`    | no               | Reachability, firmware and Tailscale currency, USB, disk, clock      |
| `tailscale` | **with `apply`** | Tailscale status, or update it to the current stable or a pinned one |

### `health`

Writes one `health` resource with a `verdict` of `ok`, `warn` or `fail` and a
list of `findings`. An unreachable device, an SSH denial or truncated probe
output is recorded as `fail`, not thrown, so a scheduled check always leaves a
record. Empty output from the device is never read as a pass: the probe ends
with a sentinel line, and output without it fails.

| Finding                         | Severity           | Meaning                                                     |
| ------------------------------- | ------------------ | ----------------------------------------------------------- |
| `unreachable`, `ssh_failed`     | fail               | No web UI, or SSH refused (dev mode off, key, host key)     |
| `web_unreachable`               | warn               | SSH works but `/metrics` did not answer                     |
| `app_update_available`          | warn               | JetKVM's release API offers a newer app                     |
| `system_update_available`       | warn               | ...or a newer system image                                  |
| `usb_not_configured`            | warn               | The target has not enumerated the KVM's keyboard and mouse  |
| `disk_low`                      | warn               | `/userdata` free space under `minFreeDiskPercent`           |
| `clock_unsynced`, `clock_skew`  | warn               | NTP not synced, or the clock is off                         |
| `tailscale_down`                | warn               | tailscaled not running, or not in state `Running`           |
| `tailscale_offline`             | warn               | Running, but the coordination server sees it offline        |
| `tailscale_update_available`    | warn               | pkgs.tailscale.com has a newer stable                       |
| `tailscale_boot_script_missing` | warn               | No `S22tailscale`: Tailscale will not start after a reboot  |
| `tailscale_unreachable`         | warn               | With `tailnetIp`: `/metrics` did not answer on that address |
| `tailscale_ip_changed`          | warn               | With `tailnetIp`: the device reports a different tailnet IP |
| `tailscale_not_installed`       | info               |                                                             |
| `developer_mode_enabled`        | info (warn strict) | Root SSH is open to the installed key                       |

`videoPipeline` records the app's pipeline state (`inactive` with no viewer
connected). It is not proof of an HDMI signal either way, so it raises no
finding.

The probe never reads `kvm_config.json`, which holds the password hash and the
cloud token.

**The tailnet path.** A node deleted from the tailnet does not log the device
out: tailscaled keeps reporting `Running` with a stale peer list, so
`tailscale_down` stays quiet until the daemon restarts. Set the `tailnetIp`
global argument to have `health` also fetch `/metrics` on that address, which
proves the path from the tailnet node swamp runs behind. The request is
unauthenticated, so a stale address that now belongs to another node learns
nothing. A re-added node gets a new address; `tailscale_ip_changed` names both,
and the fix is updating `tailnetIp`.

### `tailscale`

`action: status` (default) records the installed version, daemon state, online
state and tailnet IP, and the current stable.

`action: update` moves to `version`, or to the current stable when no version
is given. It refuses a downgrade unless `allowDowngrade: true` is passed. It
also refuses when Tailscale is not installed, when the boot script is missing,
and when `/userdata` has less than 200 MB free. The dry run lists every step.
With `apply: true` it:

1. Downloads `tailscale_<ver>_arm.tgz` and its `.sha256` from
   pkgs.tailscale.com on the swamp host, and refuses on a mismatch.
2. Streams the tarball over SSH and re-checks its sha256 on the device.
3. Starts a detached script on the device, so a dropped session cannot leave
   the swap half-done. The script backs up the running binaries to
   `/userdata/tailscale/backup-<old>/` (once; a rerun never overwrites the
   backup), swaps in the new ones, runs `tailscale configure jetkvm`, and
   restarts tailscaled through `S22tailscale`. There is no reboot, so the KVM
   session stays up. Its log is `/userdata/tailscale-update.log`.
4. Polls until the node reports the new version, `Running`, online, with the
   **same tailnet IP**, which proves it is the same machine with its state
   intact.
5. If that does not happen within `rejoinTimeoutMs` (default 120 s), restores
   the backup, restarts the daemon, records `rolled-back` and fails.

The `outcome` says what happened, and which ones need a human:

| `outcome`           | Meaning                                                                   |
| ------------------- | ------------------------------------------------------------------------- |
| `done`              | Updated and rejoined (and, with `rebootAfter`, rejoined after a reboot)   |
| `unchanged`         | The swap exited before swapping; the device is as it was                  |
| `rolled-back`       | Swapped, did not rejoin, old binaries restored and running                |
| `rollback-failed`   | **Needs a human**: the restore did not bring the old version back up      |
| `swap-unconfirmed`  | **Needs a human**: the swap was still running or unreadable at 2x timeout |
| `reboot-unverified` | Updated, but the reboot check did not pass; the backup is still there     |

The swap script records its PID and exit status, and on any exit it removes
its staging files and starts tailscaled if it is not running, so a failure
part-way never leaves the daemon down. The reboot check compares the kernel
boot ID, and is skipped (`reboot-unverified`, no reboot) if it cannot be read
first. The "same tailnet IP" check applies when the probe can read an IPv4
tailnet address.

Use the device's **LAN address** as `host`. The update restarts tailscaled, so
an SSH session running over the tailnet would be cut.

```bash
swamp model method run kvm-a tailscale --input action=update                  # dry run
swamp model method run kvm-a tailscale --input action=update --input apply=true
```

## Setup

On the JetKVM: Settings → Advanced → Developer mode on, then paste the public
key of the machine running swamp. Confirm the host key fingerprint on the
device before trusting it.

```yaml
# models/@sntxrr/jetkvm/kvm-a.yaml
type: "@sntxrr/jetkvm"
name: kvm-a
globalArguments:
  host: 192.0.2.20
  hostKey: ssh-ed25519 AAAA...        # optional pin; else known_hosts must have it
  # sshKeyFile: /path/to/id_ed25519   # optional; default is the agent
  # tailnetIp: 198.51.100.7           # optional: probe the Tailscale path too
```

Requirements on the machine running swamp: `ssh` and `curl` on `PATH`, and
outbound HTTPS to pkgs.tailscale.com and api.jetkvm.com for the update checks.

## Scheduling

`health` is cheap: one HTTP GET, one SSH session, and two small HTTPS requests.
Hourly is reasonable. Alert on `verdict != "ok"` and on the age of the latest
`health` record, so a check that stops running is noticed too.

## Development

```bash
~/.swamp/deno/deno check jetkvm.ts
~/.swamp/deno/deno test --allow-read --allow-env --allow-write --allow-run=sh jetkvm_test.ts
```

The tests run against a scripted fake device through `transportFactory`. They
assert what the model does **not** send as well as what it does: health and
every dry run must leave the device untouched.
