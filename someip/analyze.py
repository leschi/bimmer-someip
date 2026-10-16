"""Offline analysis of a capture file: decode, stats, service matrix, VLAN list."""
from __future__ import annotations

import csv
import sys
from collections import defaultdict
from typing import Iterable, List, Optional

from . import protocol as sip
from . import catalog
from .pcapng import read_packets, Packet

# Default SOME/IP ports. SD uses 30490; many stacks use 30490/30500/3050x.
DEFAULT_PORTS = {30490, 30500, 30501}


def _is_someip(pkt: Packet, ports) -> bool:
    if pkt.proto not in (6, 17) or not pkt.l4_payload:
        return False
    if ports and (pkt.sport in ports or pkt.dport in ports):
        return True
    # heuristic: looks like SOME/IP header (length field plausible)
    if len(pkt.l4_payload) >= 16 and not ports:
        return True
    return False


def iter_someip(path: str, ports=DEFAULT_PORTS, vlan: Optional[int] = None):
    """Yield (Packet, SomeIpHeader) for every SOME/IP message in the file."""
    for pkt in read_packets(path):
        if vlan is not None and pkt.vlan != vlan:
            continue
        if not _is_someip(pkt, ports):
            continue
        for hdr in sip.iter_messages(pkt.l4_payload):
            yield pkt, hdr


def cmd_vlans(path: str) -> None:
    """Enumerate all VLAN IDs present and what rides on each (passive scan)."""
    seen = defaultdict(lambda: {"frames": 0, "ethertypes": set(),
                                "ports": set(), "src": set(), "dst": set()})
    for pkt in read_packets(path):
        key = pkt.vlan if pkt.vlan is not None else "untagged"
        s = seen[key]
        s["frames"] += 1
        s["ethertypes"].add(pkt.ethertype)
        if pkt.dport:
            s["ports"].add(pkt.dport)
        if pkt.ip_src:
            s["src"].add(pkt.ip_src)
        if pkt.ip_dst:
            s["dst"].add(pkt.ip_dst)
    print(f"VLANs in {path}:\n")
    for key in sorted(seen, key=lambda k: (k == "untagged", k)):
        s = seen[key]
        ets = ", ".join(f"0x{e:04x}" for e in sorted(s["ethertypes"]))
        label = f"VLAN {key}" if key != "untagged" else "untagged (native)"
        subnets = sorted({".".join(ip.split(".")[:3]) + ".0/24"
                          for ip in s["src"] if ip})
        someip = any(p in DEFAULT_PORTS for p in s["ports"])
        print(f"  {label:18} {s['frames']:6} Frames  ethertypes[{ets}]"
              + (f"  subnets{subnets}" if subnets else "")
              + ("  <SOME/IP>" if someip else ""))


def cmd_analyze(path: str, ports=DEFAULT_PORTS, vlan=None, limit=None,
                only_sd=False, service: Optional[int] = None) -> None:
    """Print a decoded, timestamped log of SOME/IP messages."""
    t0 = None
    count = 0
    for pkt, hdr in iter_someip(path, ports, vlan):
        if only_sd and not hdr.is_sd:
            continue
        if service is not None and hdr.service_id != service and not hdr.is_sd:
            continue
        if t0 is None:
            t0 = pkt.ts
        rel = pkt.ts - t0
        src = pkt.ip_src or pkt.eth_src
        dst = pkt.ip_dst or pkt.eth_dst
        if hdr.is_sd:
            sd = sip.parse_sd(hdr.payload)
            flags = []
            if sd and sd.reboot:
                flags.append("reboot")
            if sd and sd.unicast:
                flags.append("unicast")
            print(f"[{rel:8.3f}] SD   {src:15} -> {dst:15} "
                  f"({len(sd.entries) if sd else 0} entries, {','.join(flags)})")
            if sd:
                for e in sd.entries:
                    if service is not None and e.service_id != service:
                        continue
                    opts = "  ".join(str(o) for o in e.options)
                    print(f"            {e.type_name:22} svc=0x{e.service_id:04x} "
                          f"inst=0x{e.instance_id:04x} v{e.major_version}.{e.minor_version} "
                          f"ttl={e.ttl}"
                          + (f" egrp=0x{e.eventgroup_id:04x}" if e.is_eventgroup else "")
                          + (f"  [{opts}]" if opts else ""))
        else:
            kind = "EVT" if hdr.is_event else "MSG"
            print(f"[{rel:8.3f}] {kind}  {src:15} -> {dst:15} "
                  f"svc=0x{hdr.service_id:04x} meth=0x{hdr.method_id:04x} "
                  f"{hdr.msg_type_name} rc={hdr.return_code_name} "
                  f"len={hdr.length} client=0x{hdr.client_id:04x} "
                  f"sess=0x{hdr.session_id:04x}")
        count += 1
        if limit and count >= limit:
            break
    if count == 0:
        print("Keine SOME/IP-Nachrichten gefunden "
              "(ggf. --ports oder --vlan anpassen).", file=sys.stderr)


def cmd_matrix(paths: List[str], out: Optional[str] = None,
               ports=DEFAULT_PORTS) -> None:
    """Build an ECU x Service matrix (which IP offers which service IDs)."""
    # provider_ip -> service_id -> {instances, endpoint ports, count}
    data = defaultdict(lambda: defaultdict(lambda: {"inst": set(),
                                                    "endpoints": set(),
                                                    "count": 0}))
    for path in paths:
        for pkt, hdr in iter_someip(path, ports):
            if not hdr.is_sd:
                continue
            sd = sip.parse_sd(hdr.payload)
            if not sd:
                continue
            for e in sd.entries:
                if e.type != sip.SD_OFFER or e.ttl == 0:
                    continue
                cell = data[pkt.ip_src][e.service_id]
                cell["inst"].add(e.instance_id)
                cell["count"] += 1
                for o in e.options:
                    if o.ipv4 and o.port:
                        cell["endpoints"].add(f"{o.ipv4}:{o.port}")

    rows = []
    for ip in sorted(data):
        for svc in sorted(data[ip]):
            c = data[ip][svc]
            rows.append({
                "ecu_ip": ip,
                "ecu_note": catalog.note_for_ip(ip),
                "service_id": f"0x{svc:04x}",
                "instances": ",".join(f"0x{i:04x}" for i in sorted(c["inst"])),
                "endpoints": ";".join(sorted(c["endpoints"])),
                "offer_count": c["count"],
            })

    if out:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows
                               else ["ecu_ip", "service_id"])
            w.writeheader()
            w.writerows(rows)
        print(f"{len(rows)} Zeilen -> {out}")
    else:
        cur = None
        for r in rows:
            if r["ecu_ip"] != cur:
                cur = r["ecu_ip"]
                note = f"  ({r['ecu_note']})" if r["ecu_note"] else ""
                print(f"\n{cur}{note}")
            print(f"   {r['service_id']}  inst={r['instances']:8} "
                  f"{r['endpoints']}")
        print(f"\nGesamt: {len(rows)} ECU/Service-Kombinationen, "
              f"{len(data)} ECUs.")
