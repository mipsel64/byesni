# byesni

A small Linux gateway daemon that splits the first TLS ClientHello segment of
selected flows, so a DPI box that resets connections based on SNI never gets a
readable one.

It changes no bytes of the TLS handshake — only the TCP segment boundaries the
handshake is carried in. No TLS interception, no custom CA, no proxy, no
tunnel, and nothing installed on client devices.

## The mechanism

Many inspectors reassemble a TCP stream, but only start reassembling once they
have decided a flow is TLS — and they make that decision from the **first data
segment** of the connection. If that segment is too small to parse as a TLS
record, the flow is never classified, never reassembled, and never matched
against a blocklist.

So byesni does not try to hide the SNI across a boundary. It makes the first
segment too small to be worth parsing, and sends the rest immediately after:

```
before:  [ ClientHello: 16 03 01 ... SNI=blocked.example ... ]        -> RST

after:   [ 16 03 01 ]  [ ... SNI=blocked.example ... ]                -> ServerHello
         ^ 3 bytes     ^ remainder, same bytes, seq advanced by 3
```

The receiving TLS stack sees an identical byte stream, because TCP is a byte
stream and segment boundaries carry no meaning. No delay between the two
segments is required.

Splitting *inside* the hostname is a different, weaker trick, and against a
reassembling inspector it does not work. Measure before assuming — see below.

## Architecture

```
clients ──▶ [ Linux gateway ] ──▶ ISP ──▶ internet
                   │
        nftables postrouting, priority 99 (before srcnat)
                   │
     ┌─────────────┴─────────────┐
     │ first 8 packets of a      │       all other traffic, and all bulk
     │ TCP/443 flow from a       │   ──▶ data on the same connections:
     │ configured source         │       kernel fast path, untouched
     └─────────────┬─────────────┘
              NFQUEUE 200
                   │
            byesni (userspace)
                   ├─ not a ClientHello ────▶ ACCEPT
                   ├─ SNI not on hostlist ──▶ ACCEPT
                   └─ SNI on hostlist:
                        raw-send segment 1 (N bytes)
                        raw-send segment 2+ (remainder, chunked to MTU)
                        ────────────────────▶ DROP the original
```

Three details make this work:

**Priority 99, before source NAT.** Addresses at this hook are still pre-NAT,
so byesni's raw sends carry the same 5-tuple as the packet they replace.
Conntrack matches them to the existing entry and applies the identical
masquerade binding. Hooking after NAT instead would create a second, conflicting
conntrack entry.

**A firewall mark on the raw socket.** byesni's own packets re-enter the output
path and would be queued straight back to it. The mark (`0x40000000`) is checked
before the queue rule, so they pass through once.

**`queue ... bypass`.** If byesni is not running, matching packets are accepted
normally instead of dropped. The failure mode is "back to blocked", never "no
internet". byesni also enables fail-open on the queue itself, so when the
kernel queue is full packets pass through unsplit instead of being dropped.

Cost is bounded by the `ct original packets 1-8` window: at most eight packets
per new connection reach userspace, and only for flows from configured sources
to port 443. Bulk transfer never leaves the kernel.

## Measure before deploying

```sh
python3 tools/dpi-probe.py blocked.example
```

Run it from inside the affected network. It distinguishes the three causes that
look identical from a browser, and prints the value to configure:

- **DNS poisoning** — the local resolver returns an address the public one does
  not. byesni cannot help; fix the gateway's upstream resolver.
- **Destination IP blocked** — a known-good SNI to the same address also fails.
  byesni cannot help.
- **SNI-based reset** — a known-good SNI to the same address succeeds. byesni
  handles this, and the probe sweeps split positions to find which work.

Example output from a network where the inspector reassembles but skips flows
whose first segment is too small:

```
split@1    OK    split@40   RST
split@3    OK    split@64   RST
split@20   OK    split@128  RST
-> Use --split 3
```

These two blocks are independent and commonly appear together. A site can be
both DNS-poisoned and SNI-reset, in which case fixing only one changes nothing
observable.

## Build

Pure Rust, no C dependencies. Cross-compiles to a static binary from any host
with a Rust toolchain:

```sh
rustup target add aarch64-unknown-linux-musl
PATH="$PATH:$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin" \
  cargo build --release --target aarch64-unknown-linux-musl
```

The `PATH` addition exposes the bundled `rust-lld`, which `.cargo/config.toml`
uses as the linker so no cross GCC is needed. Use
`x86_64-unknown-linux-musl` for an amd64 gateway.

Tests cover the packet logic — SNI parsing against truncated input, stream
preservation across a split, checksums, MTU chunking — and run on any host:

```sh
cargo test
```

## Install

On the gateway, as root:

```sh
install -m755 byesni /usr/local/bin/byesni
install -d -m755 /etc/byesni
install -m644 examples/byesni.nft examples/hosts /etc/byesni/
install -m644 examples/byesni.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now byesni
```

The unit runs under `DynamicUser` with only `CAP_NET_RAW` and `CAP_NET_ADMIN`,
and drops the nftables table again on stop.

## Configure

| Where | What |
| --- | --- |
| `/etc/byesni/byesni.nft` | `$wan` — interface facing the ISP; `$sources` — client addresses to process |
| `/etc/byesni/hosts` | one hostname per line, suffix match, `#` comments; reloaded automatically when the file changes |
| `ExecStart` in the unit | `--split N` — bytes in the first segment; `--queue N` must match the nft rule; `--mtu N` — outgoing interface MTU, default 1500, set it to 1492 on a PPPoE WAN |

`--split` is the one value that is a property of someone else's equipment
rather than of this software. Whatever threshold the inspector uses can change,
so pick a value with margin on both sides of the working range, and re-run the
probe if resets come back. Changing it needs only a unit edit and a restart, no
rebuild.

## Verify

```sh
systemctl status byesni
journalctl -u byesni -f          # one line per split
nft list chain inet byesni outbound   # counter shows packets reaching the queue
python3 tools/dpi-probe.py blocked.example
```

Each split line records the hostname a LAN client reached, so the journal is a
record of visits to listed sites.

After deployment the probe's plain `whole ClientHello` test should succeed on
its own, because the gateway is now doing the splitting. A hostname *not* on the
list should show no log line at all — that is the check that scoping works.

## Rollback

```sh
systemctl disable --now byesni
```

The nftables table is removed on stop and traffic returns to ordinary
forwarding.

## Limits

- IPv4 and TCP port 443 only. IPv6 flows are returned untouched by the nft rule.
- Does nothing about DNS interference, blocked destination addresses, or
  QUIC/UDP. A browser that reaches a site over QUIC bypasses this entirely;
  blocked sites usually fall back to TCP, but verify rather than assume.
- Does not encrypt or hide the SNI. It only prevents one class of inspector
  from parsing it. An inspector that classifies flows by port alone, or that
  reassembles unconditionally, is unaffected.
- Effectiveness is a property of the specific network in front of you and can
  change without notice. The probe is the only answer to "does this work here".

## License

MIT, see LICENSE.
