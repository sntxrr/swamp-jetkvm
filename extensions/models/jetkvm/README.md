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

| Method            | Writes?    | What it does                                                    |
| ----------------- | ---------- | --------------------------------------------------------------- |
| `health`          | no         | Reachability, firmware and Tailscale currency, USB, disk, clock |
| `tailscale`       | no         | Tailscale status, or the plan for an update                     |
| `tailscaleUpdate` | **always** | Update Tailscale to the current stable or a pinned version      |

Reads and writes are separate methods (since 2026.10.19.1). Before that,
`tailscale` updated when passed `apply: true`; it now **refuses** `apply: true`
rather than ignoring it, so a caller written for the old method fails loudly
instead of silently becoming a dry run.

### `health`

Writes one `health` resource with a `verdict` of `ok`, `warn` or `fail` and a
list of `findings`. An unreachable device, an SSH denial or truncated probe
output is recorded as `fail`, not thrown, so a scheduled check always leaves a
record. Empty output from the device is never read as a pass: the probe ends
with a sentinel line, and output without it fails.

| Finding                         | Severity           | Meaning                                                     |
| ------------------------------- | ------------------ | ----------------------------------------------------------- |
| `ssh_failed`                    | fail               | SSH refused (dev mode off, key, host key); with `unreachable` too when `/metrics` is also down |
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
| `tailscale_unreachable`         | warn               | With `tailnetIp`: nothing answered on that address          |
| `tailscale_wrong_device`        | warn               | With `tailnetIp`: something other than this JetKVM answered |
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
global argument to have `health` also probe that address from the tailnet node
swamp runs behind. The probe runs before the SSH probe and is recorded even when
SSH on the LAN fails, which is what tells a dead device from a broken LAN.

It is anonymous, so a stale address that now belongs to another node learns
nothing: `/metrics` needs no login, and the identity check is an `ssh-keyscan`
that offers no key. It proves the answer came from this JetKVM: the page must
carry `jetkvm_build_info`, and with `hostKey` pinned the key on the tailnet
address must match it. `tailscale_unreachable` means nothing answered,
`tailscale_wrong_device` means something else did. A re-added node gets a new
address; `tailscale_ip_changed` names both, and the fix is updating `tailnetIp`.

### `tailscale`

`action: status` (default) records the installed version, daemon state, online
state and tailnet IP, and the current stable.

`action: update` records the plan for `tailscaleUpdate` with the same
arguments: every step it would take, or the refusal it would hit. It never
changes the device.

### `tailscaleUpdate`

Moves to `version`, or to the current stable when no version is given. It
refuses a downgrade unless `allowDowngrade: true` is passed. It also refuses
when Tailscale is not installed, when the boot script is missing, when
`/userdata` has less than 200 MB free, and (with `tailnetIp`) when the device
does not already answer over the tailnet from the swamp host: an update that
cannot be verified would only roll back. It:

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
   intact. With `tailnetIp` it must also **answer over the tailnet** from the
   swamp host (the anonymous probe `health` uses). The device's own report is
   not enough: after a swap, a JetKVM has reported `Running` and online while
   a peer's pings got no answer. The probe proves the path from wherever swamp
   runs, not from every peer.
5. If that does not happen within `rejoinTimeoutMs` (default 120 s), restores
   the backup, restarts the daemon, records `rolled-back` and fails. The
   restore ignores a dropped session and renames the binaries into place, so a
   daemon slow to stop cannot leave it half-done.
6. After a verified update, removes every backup except the one it just made
   (each is about 65 MB), so the version it replaced stays restorable.

The `outcome` says what happened, and which ones need a human:

| `outcome`           | Meaning                                                                   |
| ------------------- | ------------------------------------------------------------------------- |
| `done`              | Updated and rejoined (and, with `rebootAfter`, rejoined after a reboot)   |
| `unchanged`         | The swap exited before swapping; the device is as it was                  |
| `rolled-back`       | Swapped, did not rejoin (or did not answer over the tailnet), old binaries restored and running |
| `rollback-failed`   | **Needs a human**: the restore did not bring the old version back up      |
| `swap-unconfirmed`  | **Needs a human**: the swap was still running or unreadable at 2x timeout |
| `reboot-unverified` | Updated, but the reboot check did not pass; the backup is still there     |

The swap script records its PID and exit status, and on any exit it removes
its staging files and starts tailscaled if it is not running, so a failure
part-way never leaves the daemon down. The reboot check compares the kernel
boot ID, and is skipped (`reboot-unverified`, no reboot) if it cannot be read
first. The "same tailnet IP" check applies when the probe can read an IPv4
tailnet address.

Every `tailscale` record carries `tailnet`: the last tailnet probe (after the
swap, the rollback or the reboot; before it for a refusal), or null without
`tailnetIp`.

**Pre-flight checks.** `tailscaleUpdate` runs four checks first, all labeled
`live` and scoped to it alone (swamp runs an unscoped check before every
method). The first three share one SSH probe.

| Check                   | Fails when                                                        |
| ----------------------- | ----------------------------------------------------------------- |
| `tailscale-installed`   | Tailscale is missing or its version is unreadable                 |
| `tailscale-boot-script` | `S22tailscale` is missing                                         |
| `userdata-free-space`   | `/userdata` free space is unreadable or under 200 MB              |
| `tailnet-path`          | With `tailnetIp`: the device does not answer over the tailnet now |

A check that cannot probe the device fails rather than passes. The method
enforces the same conditions itself, so `--skip-check-label live` only skips
the early answer, never the guard. The downgrade refusal is not a check: it
depends on the `version` argument, which checks only see unvalidated.

Use the device's **LAN address** as `host`. The update restarts tailscaled, so
an SSH session running over the tailnet would be cut.

```bash
swamp model method run kvm-a tailscale --input action=update   # the plan; changes nothing
swamp model method run kvm-a tailscaleUpdate                   # update to the current stable
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

Requirements on the machine running swamp: `ssh`, `ssh-keyscan` and `curl` on `PATH`, and
outbound HTTPS to pkgs.tailscale.com and api.jetkvm.com for the update checks.

## Scheduling

`health` is cheap: one HTTP GET, one SSH session, and two small HTTPS requests.
With `tailnetIp` set, add one HTTP GET and one `ssh-keyscan` on that address,
each capped at 10 s.
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
