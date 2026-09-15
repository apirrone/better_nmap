# bnmap

Find the devices on your LAN in a couple of seconds, with fuzzy search on hostnames.
A tiny [ratatui](https://ratatui.rs) TUI, no root needed.

```
 bnmap  wlp3s0  192.168.10.0/24   33 hosts  (30 confirmed)
 > reachy▏
 ──────────────────────────────────────────────────────────────────────────────
   IP               HOSTNAME                  MAC                VENDOR
 ● 192.168.10.144   reachy-mini.local         88:a2:9e:3b:49:3d  Raspberry Pi
 ● 192.168.10.150   reachy-mini-2.local       88:a2:9e:78:46:8e  Raspberry Pi
 ● 192.168.10.162   reachy-mini-3.local       88:a2:9e:8d:a3:9c  Raspberry Pi
 ● 192.168.10.164   reachy-mini-ci.local      88:a2:9e:3b:47:18  Raspberry Pi
 ↑↓ move  enter print + copy ip  ctrl-r rescan  esc quit
```

## Install

```bash
curl -sSL https://raw.githubusercontent.com/apirrone/better_nmap/main/install.sh | sh
```

Linux x86_64, aarch64 and armv7. Or `cargo install --path .` from a clone.

## Usage

```bash
bnmap                    # interactive
bnmap reachy             # interactive, query prefilled
ssh $(bnmap)             # pick a host, ssh into it   (fish: ssh (bnmap))
ssh pi@$(bnmap -1 mini-3)   # non-interactive: IP of the best match
bnmap -l                 # print a table
bnmap -j                 # print JSON
bnmap -i eth0            # choose the interface
bnmap -r 10.0.4.0/22     # sweep a specific range
```

Enter also copies the IP to the clipboard, via `wl-copy` / `xclip` / `xsel` when available
and the OSC 52 terminal escape otherwise (works over SSH in most terminals).

The TUI draws on **stderr** and prints only the chosen IP on **stdout**, so it composes with
shell substitution like `fzf` does.

| Key | Action |
|---|---|
| type | fuzzy-filter on IP, hostname, vendor, MAC |
| `↑` `↓` / `ctrl-p` `ctrl-n` | move |
| `enter` | print selected IP, copy it to the clipboard, quit |
| `ctrl-r` | rescan |
| `esc` / `ctrl-c` | quit with no output |

## How it works

- **Discovery without root.** Sending a UDP datagram to every address in the subnet makes
  the kernel do the ARP resolution. A few hundred milliseconds later the neighbour table
  (`ip neigh`) lists every host that answered, with its MAC. No raw sockets, no libpcap,
  no sudo. Three rounds, about one second total.
- **Hostnames from three sources in parallel**, each with a 1.5 s budget:
  mDNS reverse lookups (plus passively heard announcements), NetBIOS node status for
  Windows machines, and the system resolver for networks whose router serves reverse DNS.
- **Vendor** from the IEEE MA-L registry embedded in the binary
  (`scripts/update_oui.sh` regenerates `data/oui.txt`). Randomized MACs show as `(private MAC)`.
- `●` means the kernel confirmed the host answered during this scan. `○` means it is in the
  neighbour table from earlier but has not been re-confirmed yet.

Subnets wider than a /23 are clipped around your own address to stay well below the
kernel's neighbour-table limit. Pass `-r` to sweep something else.

## Development

```bash
cargo build --release && ./target/release/bnmap
cargo test
```

Releases: push a tag `vX.Y.Z` and the GitHub Actions workflow cross-compiles the three
targets and publishes them, which is what `install.sh` downloads.

## License

MIT
