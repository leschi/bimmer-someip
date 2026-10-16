"""pcap/pcapng-Reader. Liefert dekodierte Ethernet-Frames, inkl. 802.1Q-VLAN."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

LINKTYPE_ETHERNET = 1


@dataclass
class Packet:
    ts: float                 # seconds (float)
    vlan: Optional[int]       # outer VLAN id, or None
    eth_src: str
    eth_dst: str
    ethertype: int
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    proto: Optional[int] = None    # IP protocol number
    sport: Optional[int] = None
    dport: Optional[int] = None
    l4_payload: bytes = b""        # UDP/TCP payload


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _decode_eth(frame: bytes, ts: float) -> Optional[Packet]:
    if len(frame) < 14:
        return None
    dst = _mac(frame[0:6])
    src = _mac(frame[6:12])
    off = 12
    ethertype = struct.unpack(">H", frame[off:off + 2])[0]
    vlan = None
    # strip one or more VLAN tags
    while ethertype in (0x8100, 0x88A8, 0x9100) and len(frame) >= off + 6:
        tci = struct.unpack(">H", frame[off + 2:off + 4])[0]
        if vlan is None:
            vlan = tci & 0x0FFF
        off += 4
        ethertype = struct.unpack(">H", frame[off:off + 2])[0]
    off += 2
    pkt = Packet(ts=ts, vlan=vlan, eth_src=src, eth_dst=dst, ethertype=ethertype)

    if ethertype == 0x0800 and len(frame) >= off + 20:  # IPv4
        ihl = (frame[off] & 0x0F) * 4
        proto = frame[off + 9]
        pkt.ip_src = ".".join(str(x) for x in frame[off + 12:off + 16])
        pkt.ip_dst = ".".join(str(x) for x in frame[off + 16:off + 20])
        pkt.proto = proto
        l4 = off + ihl
        if proto == 17 and len(frame) >= l4 + 8:      # UDP
            pkt.sport, pkt.dport, ulen = struct.unpack(">HHH", frame[l4:l4 + 6])
            pkt.l4_payload = frame[l4 + 8:l4 + max(8, ulen)]
        elif proto == 6 and len(frame) >= l4 + 20:     # TCP
            pkt.sport, pkt.dport = struct.unpack(">HH", frame[l4:l4 + 4])
            doff = (frame[l4 + 12] >> 4) * 4
            pkt.l4_payload = frame[l4 + doff:]
    return pkt


def _read_pcap(fh, bo: str, nano: bool) -> Iterator[Packet]:
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, caplen, origlen = struct.unpack(bo + "IIII", rec)
        data = fh.read(caplen)
        if len(data) < caplen:
            return
        ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
        pkt = _decode_eth(data, ts)
        if pkt is not None:
            yield pkt


def _read_pcapng(fh) -> Iterator[Packet]:
    # Interface timestamp resolution, default 1e6 (microseconds)
    if_tsresol = {}
    if_index = 0
    data = fh.read()
    off = 0
    n = len(data)
    bo = "<"
    while off + 12 <= n:
        block_type = struct.unpack("<I", data[off:off + 4])[0]
        # Section Header Block determines byte order via magic
        if block_type == 0x0A0D0D0A:
            magic = struct.unpack("<I", data[off + 8:off + 12])[0]
            bo = "<" if magic == 0x1A2B3C4D else ">"
        blen = struct.unpack(bo + "I", data[off + 4:off + 8])[0]
        if blen < 12 or off + blen > n:
            return
        body = data[off + 8:off + blen - 4]

        if block_type == 0x00000001:  # Interface Description Block
            # linktype(2) reserved(2) snaplen(4) options...
            resol = 6  # default: 10^-6
            o = 8
            while o + 4 <= len(body):
                code, olen = struct.unpack(bo + "HH", body[o:o + 4])
                val = body[o + 4:o + 4 + olen]
                if code == 0 and olen == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    r = val[0]
                    resol = r & 0x7F if not (r & 0x80) else r & 0x7F
                o += 4 + olen + ((4 - (olen % 4)) % 4)
            if_tsresol[if_index] = resol
            if_index += 1

        elif block_type == 0x00000006:  # Enhanced Packet Block
            iface, th, tl, caplen, origlen = struct.unpack(bo + "IIIII", body[:20])
            raw = body[20:20 + caplen]
            resol = if_tsresol.get(iface, 6)
            ticks = (th << 32) | tl
            ts = ticks / (10 ** resol)
            pkt = _decode_eth(raw, ts)
            if pkt is not None:
                yield pkt

        elif block_type == 0x00000003:  # Simple Packet Block
            origlen = struct.unpack(bo + "I", body[:4])[0]
            raw = body[4:4 + origlen]
            pkt = _decode_eth(raw, 0.0)
            if pkt is not None:
                yield pkt

        off += blen


def read_packets(path: str) -> Iterator[Packet]:
    """Open a .pcap or .pcapng file and yield decoded Packets."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(fh)
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                       b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
            nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
            fh.read(24)  # skip global header
            yield from _read_pcap(fh, "<" if little else ">", nano)
        else:
            raise ValueError(f"Unbekanntes Capture-Format (magic={magic!r})")
