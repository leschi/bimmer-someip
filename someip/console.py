"""REPL-Konsole fuer den LiveNode (Fallback ohne TUI)."""
from __future__ import annotations

import cmd
import threading

from .live import LiveNode, SD_GROUP, SD_PORT


def _parse_int(tok: str) -> int:
    return int(tok, 0)


class SomeIpConsole(cmd.Cmd):
    intro = ("\nSOME/IP Live-Konsole. 'help' fuer Befehle, 'quit' zum Beenden.\n"
             "Entdeckte Services erscheinen automatisch, sobald Offers eintreffen.\n")
    prompt = "someip> "

    def __init__(self, node: LiveNode):
        super().__init__()
        self.node = node

    # --- commands ------------------------------------------------------------
    def do_services(self, arg):
        """services  - zeigt alle aktuell entdeckten Services."""
        recs = self.node.services()
        if not recs:
            print("(noch keine Services entdeckt)")
            return
        for r in recs:
            print("  " + str(r))
        print(f"  -- {len(recs)} Services")

    def do_find(self, arg):
        """find <service_id>  - sendet FindService (z.B. find 0x4010)."""
        try:
            svc = _parse_int(arg.strip())
        except ValueError:
            print("Nutzung: find 0x4010")
            return
        self.node.send_find(svc)

    def do_sub(self, arg):
        """sub <service_id> <eventgroup_id>  - SubscribeEventgroup."""
        parts = arg.split()
        if len(parts) != 2:
            print("Nutzung: sub 0x4010 0x0001")
            return
        self.node.subscribe(_parse_int(parts[0]), _parse_int(parts[1]))

    def do_call(self, arg):
        """call <service_id> <method_id> [hexpayload]  - REQUEST senden.

        Beispiel: call 0x4010 0x0010 deadbeef"""
        parts = arg.split()
        if len(parts) < 2:
            print("Nutzung: call 0x4010 0x0010 [hexpayload]")
            return
        svc = _parse_int(parts[0])
        meth = _parse_int(parts[1])
        payload = bytes.fromhex(parts[2]) if len(parts) > 2 else b""
        self.node.call(svc, meth, payload)

    def do_subrange(self, arg):
        """subrange <service_id> <von_egrp> <bis_egrp>  - Eventgroups scannen.

        Abonniert nacheinander alle Eventgroups im Bereich, um gueltige zu
        finden (SubscribeAck). Beispiel: subrange 0x4010 1 16"""
        parts = arg.split()
        if len(parts) != 3:
            print("Nutzung: subrange 0x4010 1 16")
            return
        self.node.subscribe_range(_parse_int(parts[0]), _parse_int(parts[1]),
                                  _parse_int(parts[2]))

    def do_rec(self, arg):
        """rec [datei.csv]  - Event-Aufzeichnung starten/stoppen (CSV)."""
        if self.node.record_path:
            self.node.stop_record()
        else:
            self.node.start_record(arg.strip() or "events.csv")

    def do_autoscan(self, arg):
        """autoscan [datei.csv] [bis_egrp]  - ALLES automatisch scannen.

        Abonniert Eventgroups 1..bis_egrp aller (auch neuer) Services und
        zeichnet alle Events in CSV auf. Nochmal aufrufen = stoppen."""
        if self.node._autoscan_on:
            self.node.stop_autoscan()
        else:
            parts = arg.split()
            path = parts[0] if parts else "autoscan.csv"
            hi = int(parts[1], 0) if len(parts) > 1 else 4
            self.node.start_autoscan(path, 1, hi)

    def do_offer(self, arg):
        """offer <service_id> [port]  - diesen Service selbst anbieten (ECU).

        Startet einen Simulator-Thread, der zyklisch Offers sendet."""
        parts = arg.split()
        if not parts:
            print("Nutzung: offer 0x3003 [30509]")
            return
        from .simulator import EcuSimulator, OfferedService
        svc = _parse_int(parts[0])
        port = _parse_int(parts[1]) if len(parts) > 1 else 30509
        sim = EcuSimulator(bind_ip=self.node.bind_ip,
                           services=[OfferedService(svc, port=port)],
                           sd_group=self.node.sd_group,
                           sd_port=self.node.sd_port)
        t = threading.Thread(target=sim.run, daemon=True)
        t.start()
        print(f"Biete Service 0x{svc:04x} auf {self.node.bind_ip}:{port} an "
              f"(laeuft im Hintergrund).")

    def do_verbose(self, arg):
        """verbose on|off  - Find/Subscribe-Fremdverkehr mitloggen."""
        self.node.verbose = arg.strip().lower() in ("on", "1", "true", "ja")
        print(f"verbose = {self.node.verbose}")

    def do_quit(self, arg):
        """quit  - Konsole beenden."""
        print("Beende ...")
        self.node.stop()
        return True

    do_EOF = do_quit
    do_exit = do_quit


def run_console(bind_ip="0.0.0.0", sd_group=SD_GROUP, sd_port=SD_PORT,
                unicast_port=30509, verbose=False, rx="socket",
                interface=None, tshark="tshark"):
    node = LiveNode(bind_ip=bind_ip, sd_group=sd_group, sd_port=sd_port,
                    unicast_port=unicast_port, verbose=verbose, rx=rx,
                    interface=interface, tshark=tshark)
    node.start()
    try:
        SomeIpConsole(node).cmdloop()
    except KeyboardInterrupt:
        node.stop()
        print("\nBeendet.")
