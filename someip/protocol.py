"""SOME/IP und SOME/IP-SD: parsen und bauen. Big-endian, rohe Nachrichtenbytes."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

# --- Message types -----------------------------------------------------------
MSG_TYPE = {
    0x00: "REQUEST",
    0x01: "REQUEST_NO_RETURN",
    0x02: "NOTIFICATION",
    0x40: "REQUEST_ACK",
    0x41: "REQUEST_NO_RETURN_ACK",
    0x42: "NOTIFICATION_ACK",
    0x80: "RESPONSE",
    0x81: "ERROR",
    0xC0: "RESPONSE_ACK",
    0xC1: "ERROR_ACK",
}

RETURN_CODE = {
    0x00: "E_OK",
    0x01: "E_NOT_OK",
    0x02: "E_UNKNOWN_SERVICE",
    0x03: "E_UNKNOWN_METHOD",
    0x04: "E_NOT_READY",
    0x05: "E_NOT_REACHABLE",
    0x06: "E_TIMEOUT",
    0x07: "E_WRONG_PROTOCOL_VERSION",
    0x08: "E_WRONG_INTERFACE_VERSION",
    0x09: "E_MALFORMED_MESSAGE",
    0x0A: "E_WRONG_MESSAGE_TYPE",
}

# SOME/IP-SD is carried in a SOME/IP message with this fixed Message ID.
SD_SERVICE_ID = 0xFFFF
SD_METHOD_ID = 0x8100
SD_MESSAGE_ID = (SD_SERVICE_ID << 16) | SD_METHOD_ID

# SD entry types
SD_FIND = 0x00
SD_OFFER = 0x01            # TTL==0 means StopOffer
SD_SUBSCRIBE = 0x06        # TTL==0 means StopSubscribe
SD_SUBSCRIBE_ACK = 0x07    # TTL==0 means SubscribeNack
SD_ENTRY_TYPE = {
    0x00: "FindService",
    0x01: "OfferService",
    0x06: "SubscribeEventgroup",
    0x07: "SubscribeEventgroupAck",
}

# SD option types
OPT_CONFIGURATION = 0x01
OPT_LOAD_BALANCING = 0x02
OPT_IPV4_ENDPOINT = 0x04
OPT_IPV6_ENDPOINT = 0x06
OPT_IPV4_MULTICAST = 0x14
OPT_IPV6_MULTICAST = 0x16
OPT_IPV4_SD_ENDPOINT = 0x24
L4PROTO = {0x06: "TCP", 0x11: "UDP"}


@dataclass
class SomeIpHeader:
    service_id: int
    method_id: int          # method or event id (>=0x8000 => event)
    length: int             # value of the Length field (covers 8 bytes + payload)
    client_id: int
    session_id: int
    proto_version: int
    iface_version: int
    message_type: int
    return_code: int
    payload: bytes = b""

    @property
    def message_id(self) -> int:
        return (self.service_id << 16) | self.method_id

    @property
    def is_sd(self) -> bool:
        return self.service_id == SD_SERVICE_ID and self.method_id == SD_METHOD_ID

    @property
    def is_event(self) -> bool:
        return self.method_id >= 0x8000

    @property
    def msg_type_name(self) -> str:
        return MSG_TYPE.get(self.message_type, f"0x{self.message_type:02x}")

    @property
    def return_code_name(self) -> str:
        return RETURN_CODE.get(self.return_code, f"0x{self.return_code:02x}")


@dataclass
class SdOption:
    type: int
    ipv4: Optional[str] = None
    port: Optional[int] = None
    l4proto: Optional[int] = None
    raw: bytes = b""

    def __str__(self) -> str:
        if self.type in (OPT_IPV4_ENDPOINT, OPT_IPV4_MULTICAST, OPT_IPV4_SD_ENDPOINT):
            proto = L4PROTO.get(self.l4proto, self.l4proto)
            kind = {OPT_IPV4_ENDPOINT: "endpoint",
                    OPT_IPV4_MULTICAST: "multicast",
                    OPT_IPV4_SD_ENDPOINT: "sd"}[self.type]
            return f"IPv4-{kind} {self.ipv4}:{self.port}/{proto}"
        if self.type == OPT_CONFIGURATION:
            return f"config {self.raw!r}"
        return f"option 0x{self.type:02x} ({len(self.raw)}B)"


@dataclass
class SdEntry:
    type: int
    service_id: int
    instance_id: int
    major_version: int
    ttl: int
    minor_version: int = 0      # service entries
    eventgroup_id: int = 0      # eventgroup entries
    counter: int = 0
    n_opt1: int = 0
    n_opt2: int = 0
    index1: int = 0
    index2: int = 0
    options: List[SdOption] = field(default_factory=list)

    @property
    def type_name(self) -> str:
        base = SD_ENTRY_TYPE.get(self.type, f"0x{self.type:02x}")
        if self.ttl == 0:
            if self.type == SD_OFFER:
                return "StopOfferService"
            if self.type == SD_SUBSCRIBE:
                return "StopSubscribeEventgroup"
        return base

    @property
    def is_eventgroup(self) -> bool:
        return self.type in (SD_SUBSCRIBE, SD_SUBSCRIBE_ACK)


@dataclass
class SdMessage:
    flags: int
    entries: List[SdEntry] = field(default_factory=list)

    @property
    def reboot(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def unicast(self) -> bool:
        return bool(self.flags & 0x40)


class ParseError(Exception):
    pass


def parse_header(data: bytes) -> Optional[SomeIpHeader]:
    """Parse one SOME/IP message from the start of *data*.

    Returns None if the buffer is too short to even hold a header.
    """
    if len(data) < 16:
        return None
    service_id, method_id, length, client_id, session_id = struct.unpack(
        ">HHIHH", data[:12])
    proto_v, iface_v, msg_type, ret_code = data[12], data[13], data[14], data[15]
    # Length covers everything after the Length field: 8 header bytes + payload.
    payload_len = max(0, length - 8)
    payload = data[16:16 + payload_len]
    return SomeIpHeader(service_id, method_id, length, client_id, session_id,
                        proto_v, iface_v, msg_type, ret_code, payload)


def iter_messages(data: bytes):
    """Yield consecutive SOME/IP messages from a UDP payload (magic for
    several messages concatenated in one datagram)."""
    off = 0
    while off + 16 <= len(data):
        hdr = parse_header(data[off:])
        if hdr is None:
            break
        total = 16 + max(0, hdr.length - 8)
        if total < 16 or off + total > len(data) + 7:  # tolerate small slack
            yield hdr
            break
        yield hdr
        off += total


def _parse_options(buf: bytes) -> List[SdOption]:
    opts: List[SdOption] = []
    off = 0
    while off + 3 <= len(buf):
        olen = struct.unpack(">H", buf[off:off + 2])[0]
        otype = buf[off + 2]
        body = buf[off + 3:off + 3 + olen]
        opt = SdOption(type=otype, raw=body)
        if otype in (OPT_IPV4_ENDPOINT, OPT_IPV4_MULTICAST, OPT_IPV4_SD_ENDPOINT) and len(body) >= 8:
            # reserved(1) ipv4(4) reserved(1) l4proto(1) port(2)
            ip = ".".join(str(b) for b in body[1:5])
            opt.ipv4 = ip
            opt.l4proto = body[6]
            opt.port = struct.unpack(">H", body[7:9])[0] if len(body) >= 9 else None
        opts.append(opt)
        off += 3 + olen
    return opts


def parse_sd(payload: bytes) -> Optional[SdMessage]:
    """Parse a SOME/IP-SD payload (everything after the SOME/IP header)."""
    if len(payload) < 12:
        return None
    flags = payload[0]
    entries_len = struct.unpack(">I", payload[4:8])[0]
    ea = payload[8:8 + entries_len]
    opts_off = 8 + entries_len
    if len(payload) < opts_off + 4:
        options: List[SdOption] = []
    else:
        opts_len = struct.unpack(">I", payload[opts_off:opts_off + 4])[0]
        options = _parse_options(payload[opts_off + 4:opts_off + 4 + opts_len])

    msg = SdMessage(flags=flags)
    off = 0
    while off + 16 <= len(ea):
        e = ea[off:off + 16]
        etype = e[0]
        index1, index2 = e[1], e[2]
        n_opt1 = e[3] >> 4
        n_opt2 = e[3] & 0x0F
        service_id, instance_id = struct.unpack(">HH", e[4:8])
        major = e[8]
        ttl = (e[9] << 16) | (e[10] << 8) | e[11]
        entry = SdEntry(type=etype, service_id=service_id, instance_id=instance_id,
                        major_version=major, ttl=ttl, n_opt1=n_opt1, n_opt2=n_opt2,
                        index1=index1, index2=index2)
        if etype in (SD_SUBSCRIBE, SD_SUBSCRIBE_ACK):
            entry.counter = e[13] & 0x0F
            entry.eventgroup_id = struct.unpack(">H", e[14:16])[0]
        else:
            entry.minor_version = struct.unpack(">I", e[12:16])[0]
        # resolve referenced options
        for i in range(n_opt1):
            idx = index1 + i
            if 0 <= idx < len(options):
                entry.options.append(options[idx])
        for i in range(n_opt2):
            idx = index2 + i
            if 0 <= idx < len(options):
                entry.options.append(options[idx])
        msg.entries.append(entry)
        off += 16
    return msg


# --- Builders (for the ECU simulator) ----------------------------------------

def build_header(service_id: int, method_id: int, payload: bytes = b"",
                 client_id: int = 0, session_id: int = 1,
                 proto_version: int = 1, iface_version: int = 1,
                 message_type: int = 0x02, return_code: int = 0) -> bytes:
    length = 8 + len(payload)
    return struct.pack(">HHIHHBBBB", service_id, method_id, length, client_id,
                       session_id, proto_version, iface_version, message_type,
                       return_code) + payload


def _ipv4_endpoint_option(ip: str, port: int, l4proto: int = 0x11,
                          opt_type: int = OPT_IPV4_ENDPOINT) -> bytes:
    octets = bytes(int(x) for x in ip.split("."))
    body = b"\x00" + octets + b"\x00" + bytes([l4proto]) + struct.pack(">H", port)
    return struct.pack(">H", len(body)) + bytes([opt_type]) + body


def build_offer(service_id: int, instance_id: int, ip: str, port: int,
                ttl: int = 3, major: int = 1, minor: int = 0,
                session_id: int = 1, reboot: bool = True, l4proto: int = 0x11,
                stop: bool = False) -> bytes:
    """Build a SOME/IP-SD OfferService (or StopOffer if ttl==0/stop=True)."""
    if stop:
        ttl = 0
    option = _ipv4_endpoint_option(ip, port, l4proto)
    entry = struct.pack(">BBBBHHB", SD_OFFER, 0, 0, 0x10, service_id,
                        instance_id, major)
    entry += bytes([(ttl >> 16) & 0xFF, (ttl >> 8) & 0xFF, ttl & 0xFF])
    entry += struct.pack(">I", minor)
    flags = 0xC0 if reboot else 0x40
    sd_payload = bytes([flags]) + b"\x00\x00\x00"
    sd_payload += struct.pack(">I", len(entry)) + entry
    sd_payload += struct.pack(">I", len(option)) + option
    return build_header(SD_SERVICE_ID, SD_METHOD_ID, sd_payload,
                        session_id=session_id, message_type=0x02)


def build_subscribe(service_id: int, eventgroup_id: int, ip: str, port: int,
                    instance_id: int = 0x0001, ttl: int = 3, major: int = 1,
                    counter: int = 0, session_id: int = 1, reboot: bool = True,
                    l4proto: int = 0x11, stop: bool = False) -> bytes:
    """Build a SOME/IP-SD SubscribeEventgroup. *ip:port* is OUR endpoint where
    the provider shall send the events (StopSubscribe if ttl==0/stop=True)."""
    if stop:
        ttl = 0
    option = _ipv4_endpoint_option(ip, port, l4proto)
    entry = struct.pack(">BBBBHHB", SD_SUBSCRIBE, 0, 0, 0x10, service_id,
                        instance_id, major)
    entry += bytes([(ttl >> 16) & 0xFF, (ttl >> 8) & 0xFF, ttl & 0xFF])
    # last 4 bytes: reserved(1), counter(low nibble of byte 13), eventgroup(2)
    entry += struct.pack(">BBH", 0, counter & 0x0F, eventgroup_id)
    flags = 0xC0 if reboot else 0x40
    sd_payload = bytes([flags]) + b"\x00\x00\x00"
    sd_payload += struct.pack(">I", len(entry)) + entry
    sd_payload += struct.pack(">I", len(option)) + option
    return build_header(SD_SERVICE_ID, SD_METHOD_ID, sd_payload,
                        session_id=session_id, message_type=0x02)


def build_request(service_id: int, method_id: int, payload: bytes = b"",
                  client_id: int = 0x0001, session_id: int = 1,
                  no_return: bool = False) -> bytes:
    """Build a SOME/IP REQUEST (or REQUEST_NO_RETURN)."""
    return build_header(service_id, method_id, payload, client_id=client_id,
                        session_id=session_id,
                        message_type=0x01 if no_return else 0x00)


def build_find(service_id: int, instance_id: int = 0xFFFF, ttl: int = 3,
               major: int = 0xFF, minor: int = 0xFFFFFFFF,
               session_id: int = 1, reboot: bool = True) -> bytes:
    """Build a SOME/IP-SD FindService entry (no options)."""
    entry = struct.pack(">BBBBHHB", SD_FIND, 0, 0, 0x00, service_id,
                        instance_id, major)
    entry += bytes([(ttl >> 16) & 0xFF, (ttl >> 8) & 0xFF, ttl & 0xFF])
    entry += struct.pack(">I", minor)
    flags = 0xC0 if reboot else 0x40
    sd_payload = bytes([flags]) + b"\x00\x00\x00"
    sd_payload += struct.pack(">I", len(entry)) + entry
    sd_payload += struct.pack(">I", 0)  # empty options array
    return build_header(SD_SERVICE_ID, SD_METHOD_ID, sd_payload,
                        session_id=session_id, message_type=0x02)
