# swamp-jetkvm

A [swamp](https://swamp-club.com) extension repo for **JetKVM**, built with
Deno's standard library plus the `ssh` and `curl` binaries. It needs no vendor
SDK.

## Extensions

### [`@sntxrr/jetkvm`](./extensions/models/jetkvm/README.md)

Health checks and Tailscale updates for one JetKVM per model instance.

| Method      | Writes?          | What it does                                                    |
| ----------- | ---------------- | --------------------------------------------------------------- |
| `health`    | no               | Reachability, firmware and Tailscale currency, USB, disk, clock |
| `tailscale` | **with `apply`** | Status, or update Tailscale with verified rollback              |

JetKVM keeps almost everything behind a WebRTC data channel, and the device has
no CA store, so `tailscale update` cannot run on it. The
[extension README](./extensions/models/jetkvm/README.md) covers how this model
works around both.

## Quick start

```bash
swamp extension pull @sntxrr/jetkvm
swamp model create @sntxrr/jetkvm kvm-a --global-arg host=192.0.2.20
swamp model method run kvm-a health
swamp data get kvm-a health --json | jq '.content | {verdict, findings}'
```

## Layout

Model instances, vaults and workflows are site-specific, so they are
gitignored here. This repo is public; real instances live in a private repo.
