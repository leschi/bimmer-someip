# ECU-Zuordnungen (IP -> Label, MAC-OUI -> Hersteller).
# kind: ok = ueber DHCP/MAC belegt, hyp = Vermutung, self = dieser PC.

# IP -> (Label, kind)
ECU_BY_IP = {
    "160.48.199.99":  ("Alps  ·  DIAGADR80  ·  VIN-Sender", "ok"),
    "160.48.199.96":  ("Bosch  ·  INTEGRITY1", "ok"),
    "160.48.199.16":  ("Visteon  ·  DIAGADR10", "ok"),
    "160.48.199.64":  ("Visteon  ·  (Port 2 von .16)", "ok"),
    "160.48.199.55":  ("Texas Instruments", "ok"),
    "160.48.199.69":  ("Aptiv", "ok"),
    "160.48.199.97":  ("Peiker  ·  TCB? (Telematik)", "hyp"),
    "160.48.199.34":  ("ZF TRW  ·  SAS? (ADAS-Fusion)", "hyp"),
    "160.48.199.117": ("lokal-admin  ·  Switch/Compute?", "hyp"),
    "160.48.199.6":   ("lokal-admin  ·  (Port 2 von .117)", "hyp"),
    "160.48.199.200": ("DIESER PC", "self"),
}

# MAC-OUI (lowercase, colon) -> Hersteller
OUI = {
    "14:61:02": "Alps Alpine",
    "f8:55:cd": "Visteon",
    "a8:5b:6c": "Robert Bosch",
    "24:76:25": "Texas Instruments",
    "28:63:bd": "Aptiv",
    "00:52:c2": "Peiker acustic",
    "68:58:c5": "ZF TRW",
    "78:21:84": "Espressif (aftermarket)",
    "00:e0:4c": "Realtek (Capture-PC)",
}

# Service-ID -> Bezeichnung. Noch keine BELEGTEN Namen (ohne FIBEX). Hypothesen
# bewusst mit '?' markiert, damit nichts als Fakt erscheint. Frei erweiterbar.
SERVICE_NAMES = {
    # 0xb00d: "Objektliste? (ADAS-Fusion)",
}


def supplier_for_mac(mac: str) -> str:
    return OUI.get(mac.lower()[:8], "")


def note_for_ip(ip: str) -> str:
    rec = ECU_BY_IP.get(ip)
    return rec[0] if rec else ""


def kind_for_ip(ip: str) -> str:
    rec = ECU_BY_IP.get(ip)
    return rec[1] if rec else "unknown"


def service_name(service_id: int) -> str:
    return SERVICE_NAMES.get(service_id, "")
