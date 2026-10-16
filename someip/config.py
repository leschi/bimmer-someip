"""Einstellungen in JSON laden/speichern (~/.someip_tool.json)."""
from __future__ import annotations

import json
import os

PATH = os.path.expanduser("~/.someip_tool.json")

DEFAULTS = {
    "bind_ip": "0.0.0.0",
    "rx": "socket",                 # socket | tshark
    "interface": "",                # tshark-Interface, z.B. "Ethernet 4"
    "tshark": "tshark",             # Pfad zu tshark.exe
    "group": "239.192.255.251",
    "sd_port": 30490,
    "unicast_port": 30509,
    "verbose": False,
    "autoscan_eg_hi": 4,
    "autoscan_csv": "autoscan.csv",
}

# Reihenfolge + Anzeigenamen fuer den Einstellungs-Screen
FIELDS = [
    ("bind_ip", "Bind-IP (lokale IP auf VLAN 73)"),
    ("rx", "Empfang: socket / tshark"),
    ("interface", "tshark-Interface (nur bei rx=tshark)"),
    ("tshark", "Pfad zu tshark.exe"),
    ("group", "SD-Multicast-Gruppe"),
    ("sd_port", "SD-Port"),
    ("unicast_port", "Unicast-Port (eigener Endpoint)"),
    ("verbose", "Verbose Find/Subscribe (0/1)"),
    ("autoscan_eg_hi", "Autoscan: Eventgroups 1..N"),
    ("autoscan_csv", "Autoscan: CSV-Datei"),
]

_INT_KEYS = {"sd_port", "unicast_port", "autoscan_eg_hi"}
_BOOL_KEYS = {"verbose"}


def load() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cfg.update({k: data[k] for k in data if k in DEFAULTS})
    except Exception:
        pass
    return cfg


def save(cfg: dict) -> bool:
    try:
        clean = {k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS}
        with open(PATH, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2)
        return True
    except Exception:
        return False


def coerce(key: str, value):
    """String aus dem Settings-Screen in den richtigen Typ wandeln."""
    try:
        if key in _INT_KEYS:
            return int(str(value).strip() or 0)
        if key in _BOOL_KEYS:
            return str(value).strip().lower() in ("1", "true", "on", "ja", "yes")
    except Exception:
        return DEFAULTS.get(key)
    return value


def as_text(key: str, value) -> str:
    if key in _BOOL_KEYS:
        return "1" if value else "0"
    return str(value)
