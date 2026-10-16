"""Payload mehrfach interpretieren (uint/int/float, BE/LE) und Record-Stride suchen."""
from __future__ import annotations

import struct
from typing import List, Optional, Tuple


def _sane_float(v: float) -> bool:
    return v == 0.0 or (1e-6 < abs(v) < 1e6)


def classify_word(w: bytes) -> str:
    u = struct.unpack(">I", w)[0]
    f = struct.unpack(">f", w)[0]
    if u == 0:
        return "."          # null
    if u == 0x3F800000:
        return "1"          # 1.0
    if u == 0xBF800000:
        return "N"          # -1.0
    if f == f and 1e-4 < abs(f) < 1e6:
        return "F"          # plausibler float
    return "#"              # int / anderes


def float_fields(payload: bytes, endian: str = ">") -> List[Tuple[int, float]]:
    """Alle Offsets, an denen ein plausibler float32 steht."""
    out = []
    for off in range(0, len(payload) - 3, 4):
        v = struct.unpack(endian + "f", payload[off:off + 4])[0]
        if v == v and 1e-4 < abs(v) < 1e6:
            out.append((off, v))
    return out


def best_endian(payload: bytes) -> str:
    """Welche Byte-Reihenfolge liefert mehr sinnvolle floats? (SOME/IP ist
    big-endian, aber Payloads koennen anders kodiert sein.)"""
    def score(e):
        n = len(payload) // 4
        if not n:
            return 0
        vals = struct.unpack(e + "f" * n, payload[:n * 4])
        return sum(1 for v in vals if _sane_float(v))
    return ">" if score(">") >= score("<") else "<"


def detect_stride(payload: bytes, min_stride: int = 8,
                  max_stride: int = 512) -> Optional[int]:
    """Erkennt eine sich wiederholende Record-Groesse: sucht den Stride, bei
    dem die Float-Muster am besten uebereinstimmen."""
    n = len(payload)
    best, best_score = None, 0.0
    for stride in range(min_stride, min(max_stride, n // 2) + 1, 4):
        if n % stride:
            continue
        reps = n // stride
        if reps < 2:
            continue
        # vergleiche Wort-Klassen ueber die Wiederholungen
        match = total = 0
        for off in range(0, stride, 4):
            cls = [classify_word(payload[r * stride + off:
                                         r * stride + off + 4])
                   for r in range(reps)]
            for c in cls[1:]:
                total += 1
                if c == cls[0]:
                    match += 1
        score = match / total if total else 0
        # bevorzuge Strides mit vielen Wiederholungen und hoher Uebereinstimmung
        if score > best_score and score >= 0.7:
            best, best_score = stride, score
    return best


def view_bytes(payload: bytes, limit: int = 32) -> List[str]:
    """Byte-/16-bit-Sicht fuer kleine Payloads."""
    lines = ["  off  u8   i8   u16BE u16LE  hex"]
    for off in range(0, min(len(payload), limit)):
        u8 = payload[off]
        i8 = u8 - 256 if u8 > 127 else u8
        u16be = struct.unpack(">H", payload[off:off + 2])[0] if off + 2 <= len(payload) else 0
        u16le = struct.unpack("<H", payload[off:off + 2])[0] if off + 2 <= len(payload) else 0
        lines.append(f"  {off:3}  {u8:3}  {i8:4}  {u16be:5} {u16le:5}  {u8:02x}")
    return lines


def view_words(payload: bytes, endian: str = ">", only_interesting: bool = False) -> List[str]:
    """32-bit-Wortsicht: uint32/int32/float32 nebeneinander + Klasse."""
    e = endian
    lines = [f"  word  off   hex        u32({'BE' if e=='>' else 'LE'})       "
             f"i32          f32          cls"]
    n = len(payload) // 4
    for i in range(n):
        w = payload[i * 4:i * 4 + 4]
        cls = classify_word(w)
        if only_interesting and cls in (".", "#"):
            continue
        u = struct.unpack(e + "I", w)[0]
        s = struct.unpack(e + "i", w)[0]
        f = struct.unpack(e + "f", w)[0]
        fstr = f"{f:12.4f}" if _sane_float(f) else "         n/a"
        lines.append(f"  {i:4}  {i*4:4}  {w.hex():8}  {u:11}  {s:11}  "
                     f"{fstr}  {cls}")
    return lines


def decode_payload(payload: bytes, title: str = "") -> str:
    """Komplette Mehrfach-Interpretation einer Payload als Text."""
    out = []
    if title:
        out.append(title)
    out.append(f"Laenge: {len(payload)} Byte, hex: {payload[:24].hex()}"
               + ("..." if len(payload) > 24 else ""))
    if len(payload) == 0:
        return "\n".join(out)
    # Kleine Payload: Byte-Sicht
    if len(payload) <= 16:
        out += view_bytes(payload)
    # Wort-Sicht (bei grossen nur interessante Felder)
    e = best_endian(payload)
    out.append(f"\n32-bit-Sicht (beste Endianness: "
               f"{'big-endian' if e=='>' else 'little-endian'}):")
    big = len(payload) > 64
    out += view_words(payload, e, only_interesting=big)
    # Struktur
    ff = float_fields(payload, e)
    out.append(f"\nPlausible float32-Felder: {len(ff)} von {len(payload)//4} Woertern")
    stride = detect_stride(payload)
    if stride:
        out.append(f"Erkannte Record-Struktur: Stride {stride} Byte "
                   f"({len(payload)//stride} gleichartige Records)")
    return "\n".join(out)
