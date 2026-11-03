# Packet Sniffer & Traffic Analyzer

A network packet sniffer and traffic analyzer written **from scratch in Python**,
using only the standard library. It reads frames straight from the Linux kernel
with `AF_PACKET` raw sockets, decodes protocol headers byte by byte with
`struct` and bitwise operations, and (in later milestones) feeds a
multi-threaded pipeline and a threat detection engine.

No Scapy, no libpcap, no third-party runtime dependencies.

## Status

| Milestone | Scope | Status |
|---|---|---|
| 1 | Raw `AF_PACKET` capture, Ethernet II + 802.1Q decoding, hex dump | ✅ Done |
| 2 | IPv4 header parsing, RFC 1071 checksum, fragments, options | ✅ Done |
| 3 | TCP / UDP / ICMP parsing, pseudo-header checksums, TCP options | ✅ Done |
| 4 | Threaded pipeline, bounded queues, drop accounting, JSON Lines logging | ✅ Done |
| 5 | Threat detection: SYN flood, port scans, JSON alerts | ⏳ Next |

## Architecture

```
 NIC ──► driver ──► kernel packet tap ──copy──► AF_PACKET socket
                                                     │ recvfrom()
                                                     ▼
                        capture.py   RawSocketCapture  (I/O, privileges)
                                                     │ RawFrame(bytes + kernel metadata)
                                                     ▼
                        protocols/   parse_ethernet()  (pure functions of bytes)
                                                     │ EthernetFrame ── EtherType 0x0800?
                                                     ▼
                        protocols/   parse_ipv4()      (validates lengths, RFC 1071 checksum)
                                                     │ IPv4Packet ── Protocol 6 / 17 / 1?
                                                     ▼
                        protocols/   parse_tcp() / parse_udp() / parse_icmp()
                                                     │
                        decode.py    decode_frame() → DecodedPacket (all layers + L4 checksum)

Milestone 4 runs that chain inside a threaded pipeline:

 [capture thread] --put_nowait--> bounded queue --> [decoder worker(s)] --> bounded queue --> [sink thread]
   recvfrom only     full? count the drop             PacketEvent (frozen)    backpressure     console / JSON Lines

                        cli.py       formatting, exit codes
```

Parsers never touch sockets, so the whole decoding layer is unit-tested with
hand-built byte strings and no root access.

## Requirements

* Linux (raw `AF_PACKET` sockets are Linux-only; Windows and macOS are out of scope for now)
* Python 3.10+
* Root, or the `CAP_NET_RAW` capability (plus `CAP_NET_ADMIN` for promiscuous mode)

## Usage

```bash
git clone https://github.com/23rob/raw-packet-analyzer.git
cd raw-packet-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Capture 10 frames on all interfaces
sudo .venv/bin/python -m sniffer -c 10

# One interface, promiscuous mode, with hex dumps
sudo .venv/bin/python -m sniffer -i eth0 -p -x

# Show the Ethernet layer under each IP packet
sudo .venv/bin/python -m sniffer -i eth0 -e

# Log every packet as JSON Lines (for jq, Splunk, Elastic) and report health every 5s
sudo .venv/bin/python -m sniffer -i eth0 -q --json packets.jsonl --stats 5
```

Example output (live capture; `-e` adds the Ethernet and full IPv4 lines):

```
#1  lo    OUTGOING  127.0.0.1:35998 -> 127.0.0.1:9 UDP len=5 ttl=64 chk=ok/partial
#3  lo    OUTGOING  127.0.0.1 -> 127.0.0.1 ICMP DEST_UNREACHABLE (port) len=33 ttl=64 chk=ok/ok
#5  eth0  OUTGOING  192.0.2.2:53844 -> 151.101.128.223:443 TCP [SYN] seq=3919551076 win=65280 mss=1360 len=0 ttl=64 chk=ok/partial
#6  eth0  HOST      151.101.128.223:443 -> 192.0.2.2:53844 TCP [SYN|ACK] seq=3580150793 ack=3919551077 win=43440 mss=1460 len=0 ttl=63 chk=ok/partial
```

`chk=` shows the IPv4 header checksum / the transport checksum:

| Label | Meaning |
|---|---|
| `ok` | Verified with RFC 1071 (TCP/UDP include the pseudo-header) |
| `BAD` | Failed verification on a received packet |
| `partial` | The field holds exactly the pseudo-header sum: the kernel's `CHECKSUM_PARTIAL` state, finished later by the NIC (common on loopback and virtual NICs) |
| `offload` | Failed on an outgoing packet, where hardware fills it in after capture |
| `n/a` | Cannot be checked: fragment, truncated capture, or UDP checksum 0 |

Running without privileges gives a clear error rather than a traceback:

```
ERROR: Raw sockets need the CAP_NET_RAW capability. Run with: sudo python -m sniffer ...
```

## Performance and drop accounting

Every frame is accounted for: `captured == queue_dropped + processed`, and the
kernel's own drop counter (`PACKET_STATISTICS`) is reported next to it, so
silent kernel drops are visible too.

Loopback flood benchmark (2.6 million UDP datagrams in 4 s, which loopback turns into about
10.5 million frames counting ICMP replies and both directions):

| Decoder workers | Frames captured | Kernel drops |
|---|---|---|
| 1 | 79,074 | 11.1 M |
| 2 | 69,559 | 10.8 M |
| 4 | 54,644 | 9.7 M |

Two lessons: the bottleneck is per-packet Python work on the capture path, not
the queue (it never filled); and adding threads *reduces* throughput because
they compete for the GIL. Kernel-side BPF filtering and `PACKET_MMAP` ring
buffers are the next steps for real line-rate capture.

`examples/race_demo.py` shows why shared counters use a lock: without one,
8 threads lose about a third of 160,000 increments.

## Development

```bash
pytest          # unit tests (no root needed)
ruff check .    # lint (PEP 8 + more)
ruff format .   # format
mypy            # strict static type checking
```

CI runs all four on Python 3.10, 3.12 and 3.13.

## Responsible use

Only capture traffic on networks you own or have **written permission** to
monitor. Intercepting other people's communications without authorization may
violate the U.S. federal Wiretap Act (18 U.S.C. § 2511), the Computer Fraud and
Abuse Act, equivalent laws elsewhere, and your school's or employer's
acceptable use policy. This project is developed and tested in an isolated
lab VM.

## License

MIT
