"""Command line interface.

    python -m someip analyze  <file.pcapng> [--vlan 73] [--sd] [--service 0x3003] [--limit N]
    python -m someip vlans    <file.pcapng>
    python -m someip matrix   <file.pcapng> [more...] [--csv out.csv]
    python -m someip monitor  --socket [--group 239.192.255.251] [--port 30490] [--iface-ip x]
    python -m someip monitor  --tshark -i "Ethernet 4" [--tshark "C:\\Program Files\\Wireshark\\tshark.exe"]
    python -m someip simulate --ip 169.254.97.44 --service 0x3003 [--service 0xb00d] [--port 30509]
"""
from __future__ import annotations

import argparse
import sys

# UTF-8-Ausgabe erzwingen (Windows-Konsole ist sonst cp1252 und bricht bei
# Zeichen wie Delta/Blockcursor/Ellipse ab).
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from . import analyze, monitor
from .simulator import EcuSimulator, OfferedService


def _int0(s: str) -> int:
    return int(s, 0)


def _ports(s: str):
    return {int(p, 0) for p in s.split(",") if p.strip()}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    from . import config as _cfgmod
    cfg = _cfgmod.load()
    ap = argparse.ArgumentParser(prog="someip", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("analyze", help="Capture dekodieren und anzeigen")
    p.add_argument("file")
    p.add_argument("--vlan", type=int, default=None)
    p.add_argument("--ports", type=_ports, default=analyze.DEFAULT_PORTS)
    p.add_argument("--sd", action="store_true", help="nur Service Discovery")
    p.add_argument("--service", type=_int0, default=None,
                   help="nur diese Service-ID (z.B. 0x3003)")
    p.add_argument("--limit", type=int, default=None)

    p = sub.add_parser("vlans", help="alle VLAN-IDs im Capture auflisten")
    p.add_argument("file")

    p = sub.add_parser("matrix", help="ECU-x-Service-Matrix (Tabelle/CSV)")
    p.add_argument("file", nargs="+")
    p.add_argument("--csv", default=None, help="Ausgabedatei")
    p.add_argument("--ports", type=_ports, default=analyze.DEFAULT_PORTS)

    p = sub.add_parser("monitor", help="live mithören")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--socket", action="store_true",
                   help="per Multicast-Socket (gleiches Segment/VLAN noetig)")
    g.add_argument("--tshark", nargs="?", const="tshark",
                   help="per tshark sniffen (sieht alle VLANs)")
    p.add_argument("--group", default=monitor.SD_MCAST_DEFAULT)
    p.add_argument("--port", type=int, default=monitor.SD_PORT_DEFAULT)
    p.add_argument("--iface-ip", default="0.0.0.0")
    p.add_argument("-i", "--interface", default=None, help="tshark-Interface")

    p = sub.add_parser("decode", help="eine Payload mehrfach interpretieren")
    p.add_argument("hex", nargs="?", help="Payload als Hex (z.B. 407cdd31...)")
    p.add_argument("--csv", help="Payload aus autoscan-CSV ziehen")
    p.add_argument("--service", type=_int0, help="Service-ID-Filter fuer --csv")
    p.add_argument("--event", type=_int0, help="Event-ID-Filter fuer --csv")

    p = sub.add_parser("live", help="interaktive Live-GUI (mithoeren + senden)")
    # Defaults aus gespeicherter Config -> ohne Argumente startbar.
    p.add_argument("--bind-ip", default=cfg["bind_ip"],
                   help="lokale IP auf dem Fahrzeug-VLAN (z.B. 160.48.199.200)")
    p.add_argument("--rx", choices=("socket", "tshark"), default=cfg["rx"],
                   help="Empfang: socket oder tshark (sieht alles)")
    p.add_argument("-i", "--interface", default=cfg["interface"] or None,
                   help="tshark-Interface, z.B. \"Ethernet 4\" (nur --rx tshark)")
    p.add_argument("--tshark", default=cfg["tshark"], help="Pfad zu tshark.exe")
    p.add_argument("--group", default=cfg["group"])
    p.add_argument("--sd-port", type=int, default=cfg["sd_port"])
    p.add_argument("--unicast-port", type=int, default=cfg["unicast_port"])
    p.add_argument("--plain", action="store_true",
                   help="einfache Zeilen-Konsole statt Terminal-GUI")
    p.add_argument("-v", "--verbose", action="store_true", default=cfg["verbose"])

    p = sub.add_parser("simulate", help="Steuergeraet (ECU) simulieren")
    p.add_argument("--ip", required=True, help="lokale IP fuer Endpoint-Options")
    p.add_argument("--service", action="append", type=_int0, required=True,
                   dest="services", help="angebotene Service-ID (mehrfach moeglich)")
    p.add_argument("--instance", type=_int0, default=0x0001)
    p.add_argument("--port", type=int, default=30509, help="Service-Endpoint-Port")
    p.add_argument("--group", default="239.192.255.251")
    p.add_argument("--sd-port", type=int, default=30490)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--ttl", type=int, default=3)

    args = ap.parse_args(argv)

    if args.cmd == "analyze":
        analyze.cmd_analyze(args.file, ports=args.ports, vlan=args.vlan,
                            limit=args.limit, only_sd=args.sd,
                            service=args.service)
    elif args.cmd == "decode":
        from . import decode as dec
        payload = None
        title = ""
        if args.csv:
            import csv as _csv
            want_s = f"0x{args.service:04x}" if args.service is not None else None
            want_e = f"0x{args.event:04x}" if args.event is not None else None
            with open(args.csv, encoding="utf-8") as fh:
                for r in _csv.DictReader(fh):
                    if want_s and r.get("service") != want_s:
                        continue
                    if want_e and r.get("event") != want_e:
                        continue
                    payload = bytes.fromhex(r["payload_hex"])
                    title = f"{r.get('service')}/{r.get('event')} @ {r.get('time')}"
            if payload is None:
                print("Keine passende Zeile in der CSV gefunden.", file=sys.stderr)
                return 1
        elif args.hex:
            payload = bytes.fromhex(args.hex.replace(":", "").replace(" ", ""))
        else:
            print("Entweder <hex> oder --csv angeben.", file=sys.stderr)
            return 2
        print(dec.decode_payload(payload, title))
    elif args.cmd == "vlans":
        analyze.cmd_vlans(args.file)
    elif args.cmd == "matrix":
        analyze.cmd_matrix(args.file, out=args.csv, ports=args.ports)
    elif args.cmd == "monitor":
        if args.socket:
            monitor.monitor_socket(args.group, args.port, args.iface_ip)
        else:
            if not args.interface:
                print("--tshark braucht -i/--interface", file=sys.stderr)
                return 2
            monitor.monitor_tshark(args.interface, ports=(30490, 30500),
                                   tshark=args.tshark)
    elif args.cmd == "live":
        # effektive Werte (CLI ueberschreibt Config) zurueck in cfg
        cfg.update(bind_ip=args.bind_ip, rx=args.rx, interface=args.interface or "",
                   tshark=args.tshark, group=args.group, sd_port=args.sd_port,
                   unicast_port=args.unicast_port, verbose=args.verbose)
        kw = dict(bind_ip=args.bind_ip, sd_group=args.group,
                  sd_port=args.sd_port, unicast_port=args.unicast_port,
                  verbose=args.verbose, rx=args.rx,
                  interface=args.interface, tshark=args.tshark)
        if args.rx == "tshark" and not args.interface:
            print("Hinweis: --rx tshark braucht ein Interface "
                  "(in der GUI unter F2 Einstellungen setzbar).", file=sys.stderr)
        if args.plain:
            from . import console
            console.run_console(**kw)
        else:
            from . import tui
            tui.run_tui(kw, cfg)
    elif args.cmd == "simulate":
        svcs = [OfferedService(service_id=s, instance_id=args.instance,
                               port=args.port) for s in args.services]
        sim = EcuSimulator(bind_ip=args.ip, services=svcs, sd_group=args.group,
                           sd_port=args.sd_port, offer_interval=args.interval,
                           ttl=args.ttl)
        sim.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
