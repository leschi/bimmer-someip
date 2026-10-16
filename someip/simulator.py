"""ECU-Simulator: zyklische OfferService-SD plus Request/Response-Endpoint."""
from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import protocol as sip


@dataclass
class OfferedService:
    service_id: int
    instance_id: int = 0x0001
    port: int = 30509
    major: int = 1
    minor: int = 0


@dataclass
class EcuSimulator:
    bind_ip: str                         # local IP announced in endpoint options
    services: List[OfferedService]
    sd_group: str = "239.192.255.251"
    sd_port: int = 30490
    offer_interval: float = 1.0
    ttl: int = 3
    answer_finds: bool = True
    _stop: threading.Event = field(default_factory=threading.Event)
    _session: int = 1

    def _sd_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        s.bind(("", self.sd_port))
        mreq = socket.inet_aton(self.sd_group) + socket.inet_aton(self.bind_ip)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            pass
        return s

    def _send_offer(self, sock: socket.socket, stop: bool = False) -> None:
        for svc in self.services:
            self._session = (self._session % 0xFFFF) + 1
            msg = sip.build_offer(svc.service_id, svc.instance_id, self.bind_ip,
                                  svc.port, ttl=0 if stop else self.ttl,
                                  major=svc.major, minor=svc.minor,
                                  session_id=self._session, stop=stop)
            sock.sendto(msg, (self.sd_group, self.sd_port))

    def _offer_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            self._send_offer(sock)
            self._stop.wait(self.offer_interval)

    def _find_responder(self, sock: socket.socket) -> None:
        offered = {s.service_id for s in self.services}
        while not self._stop.is_set():
            try:
                sock.settimeout(0.5)
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            for hdr in sip.iter_messages(data):
                if not hdr.is_sd:
                    continue
                sd = sip.parse_sd(hdr.payload)
                if not sd:
                    continue
                for e in sd.entries:
                    if e.type == sip.SD_FIND and e.service_id in offered:
                        print(f"  <- FindService 0x{e.service_id:04x} von "
                              f"{addr[0]} -> sende Offer")
                        self._send_offer(sock)

    def _service_endpoint(self, svc: OfferedService) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.bind_ip, svc.port))
        except OSError as e:
            print(f"  Endpoint-Bind {self.bind_ip}:{svc.port} fehlgeschlagen: {e}")
            return
        s.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            for hdr in sip.iter_messages(data):
                if hdr.service_id != svc.service_id:
                    continue
                if hdr.message_type in (0x00, 0x40):  # REQUEST
                    print(f"  <- REQUEST svc=0x{hdr.service_id:04x} "
                          f"meth=0x{hdr.method_id:04x} von {addr[0]}:{addr[1]}")
                    resp = sip.build_header(
                        hdr.service_id, hdr.method_id, payload=hdr.payload,
                        client_id=hdr.client_id, session_id=hdr.session_id,
                        message_type=0x80, return_code=0x00)
                    s.sendto(resp, addr)
                    print("  -> RESPONSE E_OK gesendet")
        s.close()

    def notify(self, service_id: int, event_id: int, payload: bytes,
               dst_ip: str, dst_port: int) -> None:
        """Send a single NOTIFICATION event to a destination."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        msg = sip.build_header(service_id, event_id, payload,
                               message_type=0x02, session_id=self._session)
        s.sendto(msg, (dst_ip, dst_port))
        s.close()

    def run(self) -> None:
        print(f"ECU-Simulator startet auf {self.bind_ip}")
        for svc in self.services:
            print(f"  bietet Service 0x{svc.service_id:04x} "
                  f"inst=0x{svc.instance_id:04x} @ {self.bind_ip}:{svc.port}")
        sd = self._sd_socket()
        threads = [
            threading.Thread(target=self._offer_loop, args=(sd,), daemon=True),
        ]
        if self.answer_finds:
            threads.append(threading.Thread(target=self._find_responder,
                                            args=(sd,), daemon=True))
        for svc in self.services:
            threads.append(threading.Thread(target=self._service_endpoint,
                                            args=(svc,), daemon=True))
        for t in threads:
            t.start()
        print("Sende zyklische Offers ... Strg+C zum sauberen Stop (StopOffer).")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nSende StopOffer ...")
            self._stop.set()
            try:
                self._send_offer(sd, stop=True)
            except OSError:
                pass
            time.sleep(0.3)
            sd.close()
            print("Gestoppt.")
