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
| 3 | TCP / UDP / ICMP parsing | ⏳ Next |
| 4 | Multi-threaded capture → queue → workers pipeline | ⬜ |
| 5 | Threat detection: SYN flood, port scans, JSON alerts | ⬜ |

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
                                                     │ IPv4Packet
                                                     ▼
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
```

Example output (`-e` adds the Ethernet line):

```
#1     16:01:07.596097 eth0     HOST      160.79.104.10 -> 192.0.2.2 TCP ttl=63 len=645 id=0xd06b [DF] chk=ok
                                         02:fc:00:00:00:05 -> 02:fc:00:00:00:01 type=IPV4 (0x0800) payload=645B
#2     16:01:07.596305 eth0     OUTGOING  192.0.2.2 -> 160.79.104.10 TCP ttl=64 len=52 id=0xea7c [DF] chk=ok
#5     16:01:07.827230 eth0     OUTGOING  192.0.2.2 -> 34.149.66.165 TCP ttl=64 len=6773 id=0xa993 [DF] chk=ok
```

Frame #5 is larger than the 1500-byte MTU: that is TCP Segmentation Offload.
The kernel hands the NIC one big segment and the hardware splits it, so the
sniffer sees the pre-split packet.

Running without privileges gives a clear error rather than a traceback:

```
ERROR: Raw sockets need the CAP_NET_RAW capability. Run with: sudo python -m sniffer ...
```

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
