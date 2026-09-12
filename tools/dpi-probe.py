#!/usr/bin/env python3
"""Classify how a network blocks a hostname, and find a working split position.

Run it from inside the affected network, before deploying byesni:

    python3 tools/dpi-probe.py store.steampowered.com

It answers three questions: is DNS being poisoned, is the block keyed on the
SNI or on the destination IP, and which --split value defeats the inspector.
Standard library only; no privileges needed.
"""

import argparse
import random
import socket
import ssl
import struct
import sys
import time

PUBLIC_RESOLVER = "1.1.1.1"


def dns(host, server):
    query = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    for label in host.split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\x00" + struct.pack(">HH", 1, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(2048)
    except OSError as e:
        return [f"<{type(e).__name__}>"]
    finally:
        sock.close()

    i, answers = 12, struct.unpack(">H", data[6:8])[0]
    while data[i]:
        i += data[i] + 1
    i += 5
    found = []
    for _ in range(answers):
        while data[i] >= 0xC0 or data[i]:
            if data[i] >= 0xC0:
                i += 2
                break
            i += data[i] + 1
        else:
            i += 1
        kind, _, _, length = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if kind == 1:
            found.append(socket.inet_ntoa(data[i:i + 4]))
        i += length
    return found or ["<no A record>"]


def system_resolver():
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except OSError:
        pass
    return None


def client_hello(host):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def attempt(ip, hello, split=None, delay=0.0):
    """Send a ClientHello, optionally as two segments, and report the outcome."""
    try:
        sock = socket.create_connection((ip, 443), 6)
    except OSError as e:
        return f"CONN-{type(e).__name__}"
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        if split is None:
            sock.sendall(hello)
        else:
            sock.sendall(hello[:split])
            if delay:
                time.sleep(delay)
            sock.sendall(hello[split:])
        sock.settimeout(6)
        reply = sock.recv(4096)
        if not reply:
            return "EOF"
        return "OK" if reply[0] == 0x16 else f"0x{reply[0]:02x}"
    except ConnectionResetError:
        return "RST"
    except socket.timeout:
        return "TIMEOUT"
    except OSError as e:
        return type(e).__name__
    finally:
        sock.close()


def trial(ip, hello, split, runs):
    results = [attempt(ip, hello, split) for _ in range(runs)]
    time.sleep(0.2)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", help="hostname suspected of being blocked")
    parser.add_argument("--benign", default="example.com",
                        help="a hostname known to work, for the SNI-vs-IP control")
    parser.add_argument("--runs", type=int, default=3, help="attempts per test")
    args = parser.parse_args()

    print(f"=== DNS: {args.host} ===")
    local = system_resolver()
    honest = dns(args.host, PUBLIC_RESOLVER)
    if local:
        poisoned = dns(args.host, local)
        print(f"  local resolver {local:<16} {poisoned}")
        print(f"  {PUBLIC_RESOLVER:<30} {honest}")
        if set(poisoned).isdisjoint(honest):
            print("  -> DNS POISONED. Splitting cannot fix this; change the")
            print("     gateway's upstream resolver as well.")
    else:
        print(f"  {PUBLIC_RESOLVER:<30} {honest}")

    ip = next((a for a in honest if not a.startswith("<")), None)
    if not ip:
        sys.exit("could not resolve an honest address; cannot probe TLS")

    hello = client_hello(args.host)
    offset = hello.find(args.host.encode())
    print(f"\n=== TLS to {ip} ===")
    print(f"  ClientHello {len(hello)} bytes, SNI at offset {offset}")

    whole = trial(ip, hello, None, args.runs)
    print(f"  {'whole ClientHello':<28} {' '.join(whole)}")
    control = trial(ip, client_hello(args.benign), None, args.runs)
    print(f"  {'SNI ' + args.benign + ' to same IP':<28} {' '.join(control)}")

    if all(r == "OK" for r in whole):
        print("  -> No SNI-based block on this path. If the site is still")
        print("     unreachable the cause is DNS or something else.")
        return
    if not any(r == "OK" for r in control):
        print("  -> The destination IP itself is blocked, not the SNI.")
        print("     ClientHello splitting will not help.")
        return
    print("  -> SNI-based block confirmed: same IP, benign SNI, no reset.")

    print("\n=== split positions ===")
    working = []
    for split in (1, 2, 3, 5, 10, 20, 40, 64, 128, max(1, offset - 1), offset + 5):
        results = trial(ip, hello, split, args.runs)
        ok = all(r == "OK" for r in results)
        if ok:
            working.append(split)
        print(f"  split@{split:<6} {' '.join(f'{r:<7}' for r in results)} {'OK' if ok else ''}")

    print()
    if not working:
        print("  No split position worked. The inspector reassembles fully;")
        print("  byesni will not defeat it on its own.")
        sys.exit(1)
    # Pick the middle of the working range so the value has margin on both
    # sides of whatever threshold the inspector actually uses.
    choice = working[len(working) // 2]
    print(f"  Working: {working}")
    print(f"  Use --split {choice}")


if __name__ == "__main__":
    main()
