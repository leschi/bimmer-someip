"""Terminal-GUI: ECU-Liste, Service-Details, Log, Eingabe, Einstellungen."""
from __future__ import annotations

import os
import sys
import time
import threading
from collections import deque

from .live import LiveNode
from . import catalog, config

try:
    import msvcrt
    _HAVE_MSVCRT = True
except ImportError:
    _HAVE_MSVCRT = False

ESC = "\x1b"
RESET = f"{ESC}[0m"
BOLD = f"{ESC}[1m"
REV = f"{ESC}[7m"
DIM = f"{ESC}[2m"


def _c(n):
    return f"{ESC}[38;5;{n}m"


CYAN, GREEN, YELL, RED, GREY, BLUE, WHITE = (_c(44), _c(42), _c(220), _c(203),
                                             _c(240), _c(75), _c(252))
CLR_EOL = f"{ESC}[K"


def _enable_vt():
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        k.GetConsoleMode(h, ctypes.byref(mode))
        k.SetConsoleMode(h, mode.value | 0x0004)
    except Exception:
        pass


def _trunc(s, w):
    if w <= 0:
        return ""
    return s if len(s) <= w else s[:max(0, w - 1)] + "…"


def _pad(s, w):
    s = _trunc(s, w)
    return s + " " * (w - len(s))


def _box(title, tcolor, items, w, h):
    """Rendert ein umrahmtes Panel als Liste von h Zeilen (Breite w).
    items: Liste von (text, color). Fehlende Zeilen werden leer gefuellt."""
    if w < 4 or h < 2:
        return [" " * w for _ in range(max(0, h))]
    t = _trunc(title, w - 6)
    dashes = max(0, w - 5 - len(t))
    out = [f"{GREY}┌─ {RESET}{tcolor}{BOLD}{t}{RESET}"
           f"{GREY} {'─' * dashes}┐{RESET}"]
    inner_rows = h - 2
    for i in range(inner_rows):
        if i < len(items):
            text, col = items[i]
        else:
            text, col = "", ""
        cell = _pad(" " + text, w - 2)
        out.append(f"{GREY}│{RESET}{col}{cell}{RESET}{GREY}│{RESET}")
    out.append(f"{GREY}└{'─' * (w - 2)}┘{RESET}")
    return out


class LiveTUI:
    def __init__(self, node: LiveNode, cfg: dict):
        self.node = node
        self.cfg = cfg
        self.logbuf: deque = deque(maxlen=1000)
        self.loglock = threading.Lock()
        self.cmd = ""
        self.status = "bereit"
        self.mode = "main"           # main | targets | settings
        self.ecu_sel = 0
        self.show_help = True
        self._running = True
        # targets
        self.tcursor = 0
        # settings
        self.set_sel = 0
        self.set_vals = {}
        node.log = self._on_log

    # --- Log -----------------------------------------------------------------
    def _on_log(self, line):
        with self.loglock:
            self.logbuf.append((time.strftime("%H:%M:%S"), line))

    # --- Daten: ECUs gruppieren ---------------------------------------------
    def _ecus(self):
        groups = {}
        for r in self.node.services():
            groups.setdefault(r.provider_ip, []).append(r)
        return sorted(groups.items(),
                      key=lambda kv: (-len(kv[1]), kv[0]))

    # --- Eingabe -------------------------------------------------------------
    def _poll(self):
        if not _HAVE_MSVCRT:
            return
        while msvcrt.kbhit():
            ch = msvcrt.getwch()
            if self.mode == "settings":
                self._keys_settings(ch)
            elif self.mode == "targets":
                self._keys_targets(ch)
            else:
                self._keys_main(ch)

    def _keys_main(self, ch):
        if ch in ("\x11", "\x03"):            # ^Q / ^C
            self._running = False
        elif ch == "\x01":                    # ^A Autoscan
            self._toggle_autoscan()
        elif ch == "\x14":                    # ^T Targets
            self.mode, self.tcursor = "targets", 0
        elif ch == "\x0c":                    # ^L Clear
            with self.loglock:
                self.logbuf.clear()
        elif ch in ("\x00", "\xe0"):
            fn = msvcrt.getwch()
            if fn == "<":                     # F2 Einstellungen
                self._open_settings()
            elif fn == ";":                   # F1 Hilfe
                self.show_help = not self.show_help
            elif fn == "H":                   # hoch
                self.ecu_sel = max(0, self.ecu_sel - 1)
            elif fn == "P":                   # runter
                self.ecu_sel += 1
        elif ch in ("\r", "\n"):
            self._dispatch(self.cmd.strip())
            self.cmd = ""
        elif ch in ("\x08", "\x7f"):
            self.cmd = self.cmd[:-1]
        elif ch.isprintable():
            self.cmd += ch

    def _toggle_autoscan(self):
        if self.node._autoscan_on:
            self.node.stop_autoscan()
        else:
            self.node.start_autoscan(self.cfg.get("autoscan_csv", "autoscan.csv"),
                                     1, int(self.cfg.get("autoscan_eg_hi", 4)))

    def _dispatch(self, line):
        if not line:
            return
        p = line.split()
        c = p[0].lower()
        try:
            if c in ("quit", "exit", "q"):
                self._running = False
            elif c == "clear":
                with self.loglock:
                    self.logbuf.clear()
            elif c in ("settings", "set"):
                self._open_settings()
            elif c in ("targets", "t"):
                self.mode, self.tcursor = "targets", 0
            elif c == "autoscan":
                self._toggle_autoscan()
            elif c == "find" and len(p) >= 2:
                self.node.send_find(int(p[1], 0))
            elif c == "sub" and len(p) >= 3:
                self.node.subscribe(int(p[1], 0), int(p[2], 0))
            elif c == "subrange" and len(p) >= 4:
                self.node.subscribe_range(int(p[1], 0), int(p[2], 0), int(p[3], 0))
            elif c == "call" and len(p) >= 3:
                pl = bytes.fromhex(p[3]) if len(p) > 3 else b""
                threading.Thread(target=self.node.call,
                                 args=(int(p[1], 0), int(p[2], 0), pl),
                                 daemon=True).start()
            elif c == "rec":
                if self.node.record_path:
                    self.node.stop_record()
                else:
                    self.node.start_record(p[1] if len(p) > 1 else "events.csv")
            elif c == "decode" and len(p) >= 3:
                from . import decode as dec
                st = self.node.events.get((int(p[1], 0), int(p[2], 0)))
                if st:
                    for ln in dec.decode_payload(st["last"]).split("\n"):
                        self.node.log(ln)
                else:
                    self.status = "kein Event empfangen"
            elif c == "verbose":
                self.node.verbose = len(p) > 1 and p[1].lower() in ("on", "1", "ja")
            else:
                self.status = f"unbekannt: {line}"
        except Exception as e:
            self.status = f"Fehler: {e}"

    # --- Settings ------------------------------------------------------------
    def _open_settings(self):
        self.set_vals = {k: config.as_text(k, self.cfg.get(k)) for k, _ in config.FIELDS}
        self.set_sel = 0
        self.mode = "settings"

    def _keys_settings(self, ch):
        n = len(config.FIELDS)
        if ch == "\x1b":                      # ESC abbrechen
            self.mode = "main"
        elif ch in ("\x00", "\xe0"):
            fn = msvcrt.getwch()
            if fn == "H":
                self.set_sel = (self.set_sel - 1) % n
            elif fn == "P":
                self.set_sel = (self.set_sel + 1) % n
            elif fn == "<":                   # F2 schliessen
                self.mode = "main"
        elif ch in ("\r", "\n"):              # Enter = speichern
            for k, _ in config.FIELDS:
                self.cfg[k] = config.coerce(k, self.set_vals.get(k, ""))
            ok = config.save(self.cfg)
            self.node.verbose = bool(self.cfg.get("verbose"))
            self.mode = "main"
            self.node.log("* Einstellungen gespeichert"
                          + (" (Neustart fuer Netzwerk-Parameter)" if ok
                             else " - SPEICHERN FEHLGESCHLAGEN"))
        elif ch in ("\x08", "\x7f"):
            k = config.FIELDS[self.set_sel][0]
            self.set_vals[k] = self.set_vals.get(k, "")[:-1]
        elif ch.isprintable():
            k = config.FIELDS[self.set_sel][0]
            self.set_vals[k] = self.set_vals.get(k, "") + ch

    # --- Targets -------------------------------------------------------------
    def _keys_targets(self, ch):
        targets = self.node.responsive_targets()
        if ch in ("\x1b", "\r", "\n"):
            self.mode = "main"
        elif ch == "\x03":
            self._running = False
        elif ch in ("\x00", "\xe0"):
            fn = msvcrt.getwch()
            if fn == "H":
                self.tcursor = max(0, self.tcursor - 1)
            elif fn == "P":
                self.tcursor = min(max(0, len(targets) - 1), self.tcursor + 1)
        elif ch == " ":
            if 0 <= self.tcursor < len(targets):
                t = targets[self.tcursor]
                self.node.toggle_sub(t["service"], t["eventgroup"])
        elif ch.lower() == "a":
            for t in targets:
                if not t["active"]:
                    self.node.toggle_sub(t["service"], t["eventgroup"])

    # --- Render --------------------------------------------------------------
    def _size(self):
        try:
            c, r = os.get_terminal_size()
        except OSError:
            c, r = 120, 34
        return max(80, c), max(20, r)

    def _header(self, w):
        n = self.node
        vin = n.vin or "-"
        s = (f" SOME/IP LIVE   bind {n.bind_ip}   RX {n.rx}   "
             f"SD {n.stats['sd']}  EVT {n.stats['events']}  "
             f"RSP {n.stats['responses']}   VIN {vin}")
        rec = "  ● REC" if n.record_path else ""
        au = "  ● AUTOSCAN" if n._autoscan_on else ""
        return REV + _pad(s + rec + au, w) + RESET

    def _keybar(self, w):
        keys = ("  F2 Einstellungen  │  ^A Autoscan  │  ^T Targets  "
                "│  ^L Clear  │  ↑↓ ECU  │  ^Q Beenden  "
                "│  Befehle: find/sub/call/rec/decode ")
        return GREEN + _pad(keys, w) + RESET

    def _render(self):
        w, h = self._size()
        if self.mode == "settings":
            self._render_settings(w, h)
            return
        if self.mode == "targets":
            self._render_targets(w, h)
            return

        out = [f"{ESC}[H", self._header(w)]
        body_h = h - 2
        bot_h = max(8, body_h // 3)
        top_h = body_h - bot_h
        lw = max(34, w // 3)
        rw = w - lw

        ecus = self._ecus()
        if ecus:
            self.ecu_sel = max(0, min(self.ecu_sel, len(ecus) - 1))

        # --- STEUERGERAETE (oben links) ---
        a_items = []
        for i, (ip, recs) in enumerate(ecus):
            kind = catalog.kind_for_ip(ip)
            base = (GREEN if kind == "ok" else YELL if kind == "hyp"
                    else BLUE if kind == "self" else GREY)
            short = (catalog.note_for_ip(ip).split("·")[0].strip()
                     or "unbekannt")
            txt = f"● {ip:15} {short}  ({len(recs)})"
            col = (REV + base) if i == self.ecu_sel else base
            a_items.append((txt, col))
        if not ecus:
            a_items.append(("(warte auf Offers …)", GREY))
        boxA = _box(f"STEUERGERAETE ({len(ecus)})", CYAN, a_items, lw, top_h)

        # --- DETAILS (oben rechts) ---
        b_items = []
        if ecus:
            ip, recs = ecus[self.ecu_sel]
            kind = catalog.kind_for_ip(ip)
            kc = (GREEN if kind == "ok" else YELL if kind == "hyp"
                  else BLUE if kind == "self" else GREY)
            tag = {"ok": "[belegt]", "hyp": "[Hypothese]",
                   "self": "[dieser PC]"}.get(kind, "[unbekannt]")
            b_items.append((f"{ip}   {tag}", BOLD + kc))
            b_items.append((catalog.note_for_ip(ip) or "unbekannt", kc))
            ep = next((f"{r.ip}:{r.port}/"
                       f"{'UDP' if r.l4proto == 0x11 else 'TCP'}"
                       for r in recs if r.port), "")
            if ep:
                b_items.append((f"Endpoint  {ep}", GREY))
            b_items.append(("", ""))
            b_items.append((f"Services ({len(recs)}):", CYAN))
            # Service-IDs umbrochen, mit Bezeichnung falls bekannt
            svcs = sorted({r.service_id for r in recs})
            line, used = "", rw - 4
            for s in svcs:
                name = catalog.service_name(s)
                tok = f"0x{s:04x}" + (f" {name}" if name else "")
                add = (tok + "   ")
                if len(line) + len(add) > used:
                    b_items.append(("  " + line.rstrip(), WHITE))
                    line = ""
                line += add
            if line:
                b_items.append(("  " + line.rstrip(), WHITE))
        boxB = _box("DETAILS", CYAN, b_items, rw, top_h)

        # --- EINGABE (unten links) ---
        c_items = [("", ""), (f"> {self.cmd}█", BOLD + GREEN), ("", ""),
                   (self.status, GREY)]
        boxC = _box("EINGABE", CYAN, c_items, lw, bot_h)

        # --- DATEN / EVENTS (unten rechts) ---
        with self.loglock:
            lines = list(self.logbuf)[-(bot_h - 2):]
        d_items = []
        for ts, ln in lines:
            col = (YELL if ln.startswith("*") else
                   GREEN if "RESPONSE" in ln else
                   CYAN if "EVENT" in ln else
                   GREY if ln[:1] in ("+", "-", " ") else WHITE)
            d_items.append((f"{ts} {ln}", col))
        boxD = _box("DATEN / EVENTS", CYAN, d_items, rw, bot_h)

        for i in range(top_h):
            out.append(boxA[i] + boxB[i])
        for i in range(bot_h):
            out.append(boxC[i] + boxD[i])
        out.append(self._keybar(w))
        sys.stdout.write("\n".join(out) + f"{ESC}[J")
        sys.stdout.flush()

    def _render_settings(self, w, h):
        out = [f"{ESC}[H", self._header(w)]
        body_h = h - 2
        items = []
        items.append(("Werte aendern, dann ENTER = speichern.  ESC = abbrechen.",
                      GREY))
        items.append(("", ""))
        for i, (k, label) in enumerate(config.FIELDS):
            val = self.set_vals.get(k, "")
            cur = (i == self.set_sel)
            marker = "▸ " if cur else "  "
            line = f"{marker}{label:38} {val}" + ("█" if cur else "")
            items.append((line, (REV + WHITE) if cur else WHITE))
        items.append(("", ""))
        items.append((f"Config-Datei: {config.PATH}", GREY))
        box = _box("EINSTELLUNGEN", YELL, items, w, body_h)
        out += box
        out.append(GREEN + _pad("  ↑↓ Feld   │   tippen = aendern"
                                "   │   ENTER Speichern   │   ESC "
                                "Abbrechen", w) + RESET)
        sys.stdout.write("\n".join(out) + f"{ESC}[J")
        sys.stdout.flush()

    def _render_targets(self, w, h):
        out = [f"{ESC}[H", self._header(w)]
        body_h = h - 2
        targets = self.node.responsive_targets()
        if self.tcursor >= len(targets):
            self.tcursor = max(0, len(targets) - 1)
        items = []
        if not targets:
            items.append(("(noch keine bestaetigten Abos – erst Autoscan "
                          "laufen lassen, bis + SubscribeAck erscheint)", YELL))
        area = body_h - 2
        start = max(0, self.tcursor - area + 2)
        for i, t in enumerate(targets[start:start + area]):
            idx = start + i
            box_ = "[x]" if t["active"] else "[ ]"
            note = catalog.note_for_ip(t["provider"]) or t["provider"]
            row = (f"{box_}  svc 0x{t['service']:04x}   egrp 0x{t['eventgroup']:04x}"
                   f"   events {t['events']:4}   {note}")
            cur = (idx == self.tcursor)
            col = (REV + GREEN) if cur else (GREEN if t["active"] else WHITE)
            items.append((("▸ " if cur else "  ") + row, col))
        box = _box(f"ANTWORTENDE ZIELE ({len(targets)})   "
                   f"aktive Abos: {len(self.node.active_subs)}", CYAN,
                   items, w, body_h)
        out += box
        out.append(GREEN + _pad("  ↑↓ waehlen   │   LEERTASTE "
                                "abonnieren   │   a = alle   │   ESC "
                                "zurueck", w) + RESET)
        sys.stdout.write("\n".join(out) + f"{ESC}[J")
        sys.stdout.flush()

    # --- Lauf ----------------------------------------------------------------
    def run(self):
        _enable_vt()
        self.node.start()
        sys.stdout.write(f"{ESC}[2J{ESC}[?25l")
        sys.stdout.flush()
        try:
            while self._running:
                self._poll()
                self._render()
                time.sleep(0.05)
        except KeyboardInterrupt:
            pass
        finally:
            self.node.stop()
            sys.stdout.write(f"{ESC}[?25h{RESET}\n")
            sys.stdout.flush()
            print("Beendet.")


def run_tui(node_kwargs: dict, cfg: dict):
    node = LiveNode(**node_kwargs)
    if not _HAVE_MSVCRT or not sys.stdout.isatty():
        from .console import SomeIpConsole
        node.start()
        print("(Keine TUI moeglich - einfache Konsole. 'help' fuer Befehle.)")
        try:
            SomeIpConsole(node).cmdloop()
        finally:
            node.stop()
        return
    LiveTUI(node, cfg).run()
