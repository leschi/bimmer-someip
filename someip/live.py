"""Live-Node: Service-Registry plus Senden (Find/Subscribe/Request/Offer)."""
from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import protocol as sip
from . import catalog

SD_GROUP = "239.192.255.251"
SD_PORT = 30490


def _hexsp(b: bytes, maxlen: int = 32) -> str:
    """Hex mit Leerzeichen, auf maxlen Bytes gekuerzt."""
    h = " ".join(f"{x:02x}" for x in b[:maxlen])
    return h + (" ..." if len(b) > maxlen else "")


@dataclass
class ServiceRecord:
    service_id: int
    instance_id: int
    ip: str
    port: int
    l4proto: int
    major: int
    minor: int
    ttl: int
    provider_ip: str
    last_seen: float

    def __str__(self) -> str:
        proto = sip.L4PROTO.get(self.l4proto, self.l4proto)
        note = catalog.note_for_ip(self.provider_ip)
        return (f"svc=0x{self.service_id:04x} inst=0x{self.instance_id:04x} "
                f"@ {self.ip}:{self.port}/{proto} v{self.major}.{self.minor} "
                f"ttl={self.ttl} von {self.provider_ip}"
                + (f" [{note}]" if note else ""))


class LiveNode:
    def __init__(self, bind_ip: str = "0.0.0.0", sd_group: str = SD_GROUP,
                 sd_port: int = SD_PORT, unicast_port: int = 30509,
                 log: Optional[Callable[[str], None]] = None,
                 verbose: bool = False, rx: str = "socket",
                 interface: Optional[str] = None,
                 tshark: str = "tshark"):
        self.bind_ip = bind_ip
        self.sd_group = sd_group
        self.sd_port = sd_port
        self.unicast_port = unicast_port
        self.verbose = verbose
        self.rx = rx                 # "socket" oder "tshark"
        self.interface = interface
        self.tshark = tshark
        self.log = log or (lambda s: print(s))
        self.registry: Dict[Tuple[int, int], ServiceRecord] = {}
        self._reg_lock = threading.Lock()
        self._stop = threading.Event()
        self._session = 0
        self._sd_sock: Optional[socket.socket] = None
        self._uni_sock: Optional[socket.socket] = None
        self._tshark_proc = None
        self._seen_ident: set = set()   # schon geloggte Identitaeten (VIN etc.)
        self.identities: Dict[str, str] = {}   # hostname -> src (fuer Anzeige)
        self.vin: Optional[str] = None
        self.stats = {"sd": 0, "events": 0, "responses": 0}
        # Event-Tracking fuer Byte-Diff: (service_id, method_id) -> state
        self.events: Dict[Tuple[int, int], dict] = {}
        self._csv = None
        self._csv_file = None
        self.record_path: Optional[str] = None
        # Autoscan
        self._autoscan_on = False
        self._autoscanned: set = set()          # schon abonnierte (svc,inst)
        self._acked: set = set()                # bestaetigte (svc, eventgroup)
        self._mcast_socks: List = []            # beigetretene Event-Multicasts
        self._joined_groups: set = set()
        # vom Benutzer dauerhaft gehaltene Abos (Checkbox) + Renewal
        self.active_subs: set = set()           # (service_id, eventgroup_id)
        self._renew_started = False
        # pending request (client_id,session_id) -> response holder
        self._pending: Dict[Tuple[int, int], List] = {}
        self._offers: List[Tuple[int, int, int]] = []  # (svc, inst, port)

    # --- sockets -------------------------------------------------------------
    def start(self) -> None:
        self._sd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                      socket.IPPROTO_UDP)
        self._sd_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sd_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        self._sd_sock.bind(("", self.sd_port))
        mreq = socket.inet_aton(self.sd_group) + socket.inet_aton(self.bind_ip)
        try:
            self._sd_sock.setsockopt(socket.IPPROTO_IP,
                                     socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            self.log(f"! Multicast-Join fehlgeschlagen: {e}")

        self._uni_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._uni_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._uni_sock.bind((self.bind_ip, self.unicast_port))
        except OSError as e:
            self.log(f"! Unicast-Bind {self.bind_ip}:{self.unicast_port}: {e}")

        if self.rx == "tshark":
            threading.Thread(target=self._rx_tshark, daemon=True).start()
            self.log(f"LiveNode aktiv (RX=tshark auf '{self.interface}', "
                     f"TX {self.bind_ip})")
        else:
            threading.Thread(target=self._rx_sd, daemon=True).start()
            threading.Thread(target=self._rx_uni, daemon=True).start()
            self.log(f"LiveNode aktiv: SD {self.sd_group}:{self.sd_port}, "
                     f"Unicast {self.bind_ip}:{self.unicast_port}")

    def stop(self) -> None:
        self._stop.set()
        if self._tshark_proc:
            try:
                self._tshark_proc.terminate()
            except Exception:
                pass
        for s in [self._sd_sock, self._uni_sock] + self._mcast_socks:
            try:
                if s:
                    s.close()
            except OSError:
                pass

    def _next_session(self) -> int:
        self._session = (self._session % 0xFFFF) + 1
        return self._session

    # --- receive -------------------------------------------------------------
    def _rx_sd(self) -> None:
        while not self._stop.is_set():
            try:
                self._sd_sock.settimeout(0.5)
                data, addr = self._sd_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._handle_sd(data, addr[0])

    def _rx_uni(self) -> None:
        while not self._stop.is_set():
            try:
                self._uni_sock.settimeout(0.5)
                data, addr = self._uni_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            for hdr in sip.iter_messages(data):
                self._handle_message(hdr, addr[0])

    def _join_event_mcast(self, group: str, port: int) -> None:
        key = (group, port)
        if key in self._joined_groups:
            return
        self._joined_groups.add(key)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                              socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", port))
            mreq = socket.inet_aton(group) + socket.inet_aton(self.bind_ip)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self._mcast_socks.append(s)
            threading.Thread(target=self._rx_mcast, args=(s,),
                             daemon=True).start()
            self.log(f"* Event-Multicast beigetreten: {group}:{port}")
        except OSError as e:
            self.log(f"! Multicast-Join {group}:{port} fehlgeschlagen: {e}")

    def _rx_mcast(self, s: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                s.settimeout(0.5)
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._route_payload(data, addr[0])

    def _route_payload(self, payload: bytes, src: str) -> None:
        """Route one UDP payload (SD -> Offers/Finds, sonst Message)."""
        for hdr in sip.iter_messages(payload):
            if hdr.is_sd:
                sd = sip.parse_sd(hdr.payload)
                if not sd:
                    continue
                self.stats["sd"] += 1
                for e in sd.entries:
                    if e.type == sip.SD_OFFER:
                        self._record_offer(e, src)
                    elif self.verbose and e.type == sip.SD_FIND:
                        self.log(f"  (find von {src}: svc=0x{e.service_id:04x})")
                    elif e.type == sip.SD_SUBSCRIBE_ACK:
                        ok = e.ttl > 0
                        if ok:
                            self._acked.add((e.service_id, e.eventgroup_id))
                            # Multicast-Events: Gruppe beitreten (Socket-Modus)
                            if self.rx == "socket":
                                for o in e.options:
                                    if (o.type == sip.OPT_IPV4_MULTICAST and
                                            o.ipv4 and o.port):
                                        self._join_event_mcast(o.ipv4, o.port)
                        self.log(f"{'+' if ok else '-'} Subscribe"
                                 f"{'Ack' if ok else 'Nack'} von {src}: "
                                 f"svc=0x{e.service_id:04x} "
                                 f"egrp=0x{e.eventgroup_id:04x}"
                                 + ("  (Eventgroup gueltig!)" if ok else ""))
                    elif self.verbose and e.is_eventgroup:
                        self.log(f"  (subscribe {e.type_name} von {src}: "
                                 f"svc=0x{e.service_id:04x} "
                                 f"egrp=0x{e.eventgroup_id:04x})")
            else:
                self._handle_message(hdr, src)

    def _log_identity(self, hostname: str, src: str) -> None:
        """Logge DHCP-Hostnamen (enthaelt u.a. VIN/Diag-Adressen) einmalig."""
        if not hostname or hostname in self._seen_ident:
            return
        self._seen_ident.add(hostname)
        self.identities[hostname] = src
        # VIN extrahieren (BMW: 17-stellig, beginnt oft mit WBA/WBS...)
        import re
        m = re.search(r"VIN([A-HJ-NPR-Z0-9]{17})", hostname) or \
            re.search(r"\b(W[A-HJ-NPR-Z0-9]{16})\b", hostname)
        if m and not self.vin:
            self.vin = m.group(1)
        tag = "VIN/IDENT" if ("VIN" in hostname or "BMW" in hostname) else "IDENT"
        self.log(f"* {tag} von {src}: {hostname}")

    def _rx_tshark(self) -> None:
        import subprocess
        # Breiter Portbereich: SD (30490), Methoden-/Event-Endpoints (3050x,
        # 325xx, ...) und unser eigener Unicast-Port. Plus DHCP fuer die VIN.
        lo, hi = 30490, 32700
        up = self.unicast_port
        pf = (f"(udp.port >= {lo} && udp.port <= {hi}) || udp.port == {up} "
              f"|| dhcp")
        cmd = [self.tshark, "-i", self.interface or "", "-l", "-n", "-Y", pf,
               "-T", "fields", "-E", "separator=|",
               "-e", "ip.src", "-e", "udp.dstport", "-e", "udp.srcport",
               "-e", "udp.payload", "-e", "data.data",
               "-e", "dhcp.option.hostname"]

        def _is_someip_port(p: str) -> bool:
            if not p.isdigit():
                return False
            v = int(p)
            return (lo <= v <= hi) or v == up
        try:
            self._tshark_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                bufsize=1)
        except FileNotFoundError:
            self.log(f"! tshark nicht gefunden ({self.tshark}) - Pfad mit "
                     f"--tshark angeben.")
            return
        for line in self._tshark_proc.stdout:
            if self._stop.is_set():
                break
            parts = line.rstrip("\n").split("|")
            src = parts[0] if parts else ""
            dport = parts[1] if len(parts) > 1 else ""
            sport = parts[2] if len(parts) > 2 else ""
            hexstr = (parts[3] if len(parts) > 3 and parts[3] else
                      (parts[4] if len(parts) > 4 else ""))
            hostname = parts[5] if len(parts) > 5 else ""
            if hostname:
                self._log_identity(hostname, src or "?")
                continue   # DHCP: nur Identitaet, nicht als SOME/IP routen
            if not hexstr or not (_is_someip_port(dport) or
                                  _is_someip_port(sport)):
                continue
            try:
                payload = bytes.fromhex(hexstr.replace(":", ""))
            except ValueError:
                continue
            self._route_payload(payload, src or "?")

    def _handle_sd(self, data: bytes, src: str) -> None:
        for hdr in sip.iter_messages(data):
            if not hdr.is_sd:
                continue
            sd = sip.parse_sd(hdr.payload)
            if not sd:
                continue
            for e in sd.entries:
                if e.type == sip.SD_OFFER:
                    self._record_offer(e, src)
                elif self.verbose and e.type == sip.SD_FIND:
                    self.log(f"  (find von {src}: svc=0x{e.service_id:04x})")
                elif self.verbose and e.is_eventgroup:
                    self.log(f"  (subscribe {e.type_name} von {src}: "
                             f"svc=0x{e.service_id:04x} egrp=0x{e.eventgroup_id:04x})")

    def _record_offer(self, e: sip.SdEntry, src: str) -> None:
        ep = next((o for o in e.options
                   if o.type == sip.OPT_IPV4_ENDPOINT and o.ipv4), None)
        if not ep:
            return
        key = (e.service_id, e.instance_id)
        new = key not in self.registry
        with self._reg_lock:
            if e.ttl == 0:
                self.registry.pop(key, None)
                self.log(f"- StopOffer svc=0x{e.service_id:04x}")
                return
            self.registry[key] = ServiceRecord(
                service_id=e.service_id, instance_id=e.instance_id,
                ip=ep.ipv4, port=ep.port or 0, l4proto=ep.l4proto or 0x11,
                major=e.major_version, minor=e.minor_version, ttl=e.ttl,
                provider_ip=src, last_seen=time.time())
        if new:
            self.log(f"+ neu entdeckt: {self.registry[key]}")

    def _handle_message(self, hdr: sip.SomeIpHeader, src: str) -> None:
        if hdr.is_sd:
            return
        key = (hdr.client_id, hdr.session_id)
        if hdr.message_type in (0x80, 0x81):  # RESPONSE / ERROR
            holder = self._pending.get(key)
            if holder is not None:
                holder.append(hdr)
            self.stats["responses"] += 1
            self.log(f"<- RESPONSE von {src}: svc=0x{hdr.service_id:04x} "
                     f"meth=0x{hdr.method_id:04x} rc={hdr.return_code_name} "
                     f"payload={hdr.payload.hex()}")
        elif hdr.message_type == 0x02 or hdr.is_event:
            # NOTIFICATION = Datenpush (bei BMW oft Method-ID < 0x8000, deshalb
            # ueber den Message-Typ erkennen, nicht nur ueber die ID).
            self.stats["events"] += 1
            changed = self._track_event(hdr, src)
            diff = (" Δ@[" + ",".join(str(i) for i in changed) + "]"
                    if changed else "")
            self.log(f"<- EVENT von {src}: svc=0x{hdr.service_id:04x} "
                     f"evt=0x{hdr.method_id:04x} len={len(hdr.payload)}{diff} "
                     f"payload={_hexsp(hdr.payload)}")
        else:
            self.log(f"<- MSG von {src}: svc=0x{hdr.service_id:04x} "
                     f"meth=0x{hdr.method_id:04x} {hdr.msg_type_name} "
                     f"payload={_hexsp(hdr.payload)}")

    def _track_event(self, hdr: sip.SomeIpHeader, src: str) -> List[int]:
        """Vergleicht die Event-Payload mit der letzten und liefert die
        geaenderten Byte-Offsets zurueck. Schreibt bei aktivem Record in CSV."""
        key = (hdr.service_id, hdr.method_id)
        st = self.events.get(key)
        payload = hdr.payload
        changed: List[int] = []
        if st is None:
            self.events[key] = {"last": payload, "count": 1,
                                "changed": set(range(len(payload))),
                                "src": src, "first": time.time()}
        else:
            last = st["last"]
            n = max(len(last), len(payload))
            for i in range(n):
                a = last[i] if i < len(last) else None
                b = payload[i] if i < len(payload) else None
                if a != b:
                    changed.append(i)
            st["last"] = payload
            st["count"] += 1
            st["changed"].update(changed)
        if self._csv:
            try:
                self._csv.writerow([f"{time.time():.3f}", src,
                                    f"0x{hdr.service_id:04x}",
                                    f"0x{hdr.method_id:04x}", len(payload),
                                    " ".join(str(i) for i in changed),
                                    payload.hex()])
                self._csv_file.flush()
            except Exception:
                pass
        return changed

    def start_record(self, path: str) -> None:
        import csv
        self._csv_file = open(path, "w", newline="", encoding="utf-8")
        self._csv = csv.writer(self._csv_file)
        self._csv.writerow(["time", "src", "service", "event", "len",
                            "changed_offsets", "payload_hex"])
        self.record_path = path
        self.log(f"* Aufzeichnung gestartet -> {path}")

    def stop_record(self) -> None:
        if self._csv_file:
            self._csv_file.close()
        self._csv = self._csv_file = None
        self.log(f"* Aufzeichnung gestoppt ({self.record_path})")
        self.record_path = None

    # --- send ----------------------------------------------------------------
    def send_find(self, service_id: int, instance_id: int = 0xFFFF) -> None:
        msg = sip.build_find(service_id, instance_id,
                             session_id=self._next_session())
        self._sd_sock.sendto(msg, (self.sd_group, self.sd_port))
        self.log(f"-> FindService svc=0x{service_id:04x}")

    def subscribe(self, service_id: int, eventgroup_id: int,
                  instance_id: int = 0x0001, quiet: bool = False,
                  stop: bool = False) -> None:
        rec = self.registry.get((service_id, instance_id))
        provider = rec.provider_ip if rec else self.sd_group
        major = rec.major if rec else 1   # Major-Version muss zum Offer passen
        msg = sip.build_subscribe(service_id, eventgroup_id, self.bind_ip,
                                  self.unicast_port, instance_id=instance_id,
                                  major=major, session_id=self._next_session(),
                                  stop=stop)
        # subscribe is sent unicast to the provider's SD port when known
        dst = (provider, self.sd_port) if rec else (self.sd_group, self.sd_port)
        self._sd_sock.sendto(msg, dst)
        if not quiet:
            self.log(f"-> SubscribeEventgroup svc=0x{service_id:04x} "
                     f"egrp=0x{eventgroup_id:04x} an {dst[0]}")

    def start_autoscan(self, csv_path: str = "autoscan.csv",
                       eg_lo: int = 1, eg_hi: int = 4) -> None:
        """Abonniert automatisch Eventgroups eg_lo..eg_hi ALLER (auch neu
        auftauchender) Services, zeichnet alle Events in CSV auf und erneuert
        bestaetigte Abos selbststaendig (TTL-Renewal)."""
        if self._autoscan_on:
            self.log("* Autoscan laeuft bereits")
            return
        self._autoscan_on = True
        self._autoscanned.clear()
        if not self.record_path:
            self.start_record(csv_path)
        self.log(f"* AUTOSCAN an: abonniere egrp 0x{eg_lo:04x}..0x{eg_hi:04x} "
                 f"aller Services, Aufzeichnung -> {self.record_path}")
        threading.Thread(target=self._autoscan_loop, args=(eg_lo, eg_hi),
                         daemon=True).start()

    def stop_autoscan(self) -> None:
        if not self._autoscan_on:
            return
        self._autoscan_on = False
        if self.record_path:
            self.stop_record()
        self.log(f"* AUTOSCAN aus. Bestaetigte Eventgroups: {len(self._acked)}")

    def _autoscan_loop(self, eg_lo: int, eg_hi: int) -> None:
        while self._autoscan_on and not self._stop.is_set():
            # 1) neu entdeckte Services abonnieren
            for key in list(self.registry):
                if key in self._autoscanned or not self._autoscan_on:
                    continue
                svc, inst = key
                for eg in range(eg_lo, eg_hi + 1):
                    if not self._autoscan_on:
                        break
                    try:
                        self.subscribe(svc, eg, instance_id=inst, quiet=True)
                    except OSError:
                        pass
                    time.sleep(0.015)
                self._autoscanned.add(key)
            # 2) bestaetigte Abos erneuern (damit Events weiterlaufen)
            for (svc, eg) in list(self._acked):
                if not self._autoscan_on:
                    break
                try:
                    self.subscribe(svc, eg, quiet=True)
                except OSError:
                    pass
                time.sleep(0.01)
            # 3) kurz warten (neue Offers kommen zwischenzeitlich rein)
            for _ in range(20):
                if not self._autoscan_on or self._stop.is_set():
                    break
                time.sleep(0.1)

    def subscribe_range(self, service_id: int, lo: int, hi: int,
                        instance_id: int = 0x0001, delay: float = 0.05) -> None:
        """Abonniert nacheinander Eventgroups lo..hi, um gueltige zu finden
        (SubscribeAck = gueltig). Ohne FIBEX das Mittel, Events zum Fliessen
        zu bringen. Laeuft in einem eigenen Thread."""
        def _run():
            for eg in range(lo, hi + 1):
                if self._stop.is_set():
                    break
                self.subscribe(service_id, eg, instance_id=instance_id)
                time.sleep(delay)
            self.log(f"* Subscribe-Scan 0x{service_id:04x} "
                     f"egrp 0x{lo:04x}..0x{hi:04x} fertig")
        threading.Thread(target=_run, daemon=True).start()

    def responsive_targets(self) -> List[dict]:
        """Wo haben wir eine Antwort erhalten? Liefert die bestaetigten
        (Service, Eventgroup)-Paare samt Event-Zaehler je Service."""
        ev_by_svc: dict = {}
        for (svc, _evt), st in self.events.items():
            ev_by_svc[svc] = ev_by_svc.get(svc, 0) + st["count"]
        out = []
        for (svc, eg) in sorted(self._acked):
            rec = next((r for (s, i), r in self.registry.items() if s == svc), None)
            out.append({
                "service": svc, "eventgroup": eg,
                "active": (svc, eg) in self.active_subs,
                "events": ev_by_svc.get(svc, 0),
                "provider": rec.provider_ip if rec else "?",
            })
        return out

    def toggle_sub(self, service_id: int, eventgroup_id: int) -> bool:
        """Abo fuer (Service, Eventgroup) an/aus. Rueckgabe: neuer Zustand."""
        key = (service_id, eventgroup_id)
        if key in self.active_subs:
            self.active_subs.discard(key)
            try:
                self.subscribe(service_id, eventgroup_id, stop=True, quiet=True)
            except OSError:
                pass
            self.log(f"- Abo beendet: svc=0x{service_id:04x} "
                     f"egrp=0x{eventgroup_id:04x}")
            return False
        self.active_subs.add(key)
        try:
            self.subscribe(service_id, eventgroup_id, quiet=True)
        except OSError:
            pass
        self._ensure_renew()
        self.log(f"+ Abo gehalten: svc=0x{service_id:04x} "
                 f"egrp=0x{eventgroup_id:04x}")
        return True

    def _ensure_renew(self) -> None:
        if self._renew_started:
            return
        self._renew_started = True
        threading.Thread(target=self._renew_loop, daemon=True).start()

    def _renew_loop(self) -> None:
        """Haelt die aktiv gehaltenen Abos per periodischem Re-Subscribe am
        Leben (SOME/IP-Abos laufen nach TTL ab)."""
        while not self._stop.is_set():
            for (svc, eg) in list(self.active_subs):
                try:
                    self.subscribe(svc, eg, quiet=True)
                except OSError:
                    pass
                time.sleep(0.01)
            for _ in range(20):   # ~2 s
                if self._stop.is_set():
                    return
                time.sleep(0.1)

    def call(self, service_id: int, method_id: int, payload: bytes = b"",
             instance_id: int = 0x0001, timeout: float = 2.0,
             client_id: int = 0x0001) -> Optional[sip.SomeIpHeader]:
        rec = self.registry.get((service_id, instance_id))
        if not rec:
            self.log(f"! Service 0x{service_id:04x} nicht entdeckt "
                     f"(erst 'find 0x{service_id:04x}' oder abwarten).")
            return None
        session = self._next_session()
        key = (client_id, session)
        holder: List = []
        self._pending[key] = holder
        msg = sip.build_request(service_id, method_id, payload,
                                client_id=client_id, session_id=session)
        self._uni_sock.sendto(msg, (rec.ip, rec.port))
        self.log(f"-> REQUEST svc=0x{service_id:04x} meth=0x{method_id:04x} "
                 f"an {rec.ip}:{rec.port} payload={payload.hex()}")
        deadline = time.time() + timeout
        while time.time() < deadline and not holder:
            time.sleep(0.02)
        self._pending.pop(key, None)
        if holder:
            return holder[0]
        self.log("! keine Antwort (Timeout)")
        return None

    def services(self) -> List[ServiceRecord]:
        with self._reg_lock:
            return sorted(self.registry.values(), key=lambda r: r.service_id)
