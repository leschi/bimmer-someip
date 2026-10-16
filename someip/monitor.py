"""Live-Mitschnitt von SOME/IP ueber Multicast-Socket oder tshark."""
from __future__ import annotations

import socket
import struct
import subprocess
import sys
import time
from typing import Optional

from . import protocol as sip

SD_MCAST_DEFAULT = "239.192.255.251"
SD_PORT_DEFAULT = 30490


def _print_datagram(src: str, payload: bytes, t0: float) -> None:
    rel = time.time() - t0
    for hdr in sip.iter_messages(payload):
        if hdr.is_sd:
            sd = sip.parse_sd(hdr.payload)
            print(f"[{rel:8.3f}] SD from {src}: "
                  f"{len(sd.entries) if sd else 0} entries")
            for e in (sd.entries if sd else []):
                opts = "  ".join(str(o) for o in e.options)
                print(f"            {e.type_name:22} svc=0x{e.service_id:04x} "
                      f"inst=0x{e.instance_id:04x} ttl={e.ttl}"
                      + (f"  [{opts}]" if opts else ""))
        else:
            print(f"[{rel:8.3f}] MSG from {src}: svc=0x{hdr.service_id:04x} "
                  f"meth=0x{hdr.method_id:04x} {hdr.msg_type_name}")


def monitor_socket(group: str = SD_MCAST_DEFAULT, port: int = SD_PORT_DEFAULT,
                   iface_ip: str = "0.0.0.0") -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", port))
    except OSError as e:
        print(f"Bind auf Port {port} fehlgeschlagen: {e}", file=sys.stderr)
        return
    mreq = socket.inet_aton(group) + socket.inet_aton(iface_ip)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print(f"Lausche auf {group}:{port} (iface {iface_ip}) ... Strg+C zum Beenden")
    t0 = time.time()
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            _print_datagram(addr[0], data, t0)
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        sock.close()


def monitor_tshark(interface: str, ports=(30490, 30500),
                   tshark: str = "tshark") -> None:
    """Stream live frames via tshark and decode SOME/IP ourselves.

    tshark prints hex of the UDP payload; we parse it with our own decoder so
    no SOME/IP plugin configuration in Wireshark is required.
    """
    pf = " || ".join(f"udp.port=={p}" for p in ports)
    cmd = [tshark, "-i", interface, "-l", "-Y", pf,
           "-T", "fields", "-e", "ip.src", "-e", "frame.time_relative",
           "-e", "data.data", "-e", "udp.payload"]
    print("Starte: " + " ".join(cmd))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True,
                                 bufsize=1)
    except FileNotFoundError:
        print(f"tshark nicht gefunden ({tshark}). Pfad mit --tshark angeben.",
              file=sys.stderr)
        return
    try:
        for line in proc.stdout:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            src, trel = parts[0], parts[1]
            hexstr = (parts[3] if len(parts) > 3 and parts[3] else parts[2])
            hexstr = hexstr.replace(":", "")
            try:
                payload = bytes.fromhex(hexstr)
            except ValueError:
                continue
            for hdr in sip.iter_messages(payload):
                if hdr.is_sd:
                    sd = sip.parse_sd(hdr.payload)
                    print(f"[{trel:>10}] SD from {src}: "
                          f"{len(sd.entries) if sd else 0} entries")
                    for e in (sd.entries if sd else []):
                        print(f"            {e.type_name:22} "
                              f"svc=0x{e.service_id:04x} ttl={e.ttl}")
                else:
                    print(f"[{trel:>10}] MSG from {src}: "
                          f"svc=0x{hdr.service_id:04x} "
                          f"meth=0x{hdr.method_id:04x} {hdr.msg_type_name}")
    except KeyboardInterrupt:
        proc.terminate()
        print("\nBeendet.")
