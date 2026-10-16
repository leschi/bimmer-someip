# bimmer-someip

Kleines Tool, um den SOME/IP-Verkehr im Automotive-Ethernet eines BMW
mitzulesen, Services zu entdecken und auch selbst welche anzubieten. Dazu ein
paar Helfer, um Wireshark-Mitschnitte auszuwerten.

Getestet an einem BMW G11 (745e, G-Serie). Der Laptop hängt über einen
**NXP RDDRONE-T1ADAPT** (RJ45 <-> 100BASE-T1) am Fahrzeug-Backbone, VLAN 73.

Python 3.12, keine zusätzlichen Pakete. tshark (aus Wireshark) wird nur für den
Capture-Empfang und die Offline-Analyse gebraucht.

## Start

```
python -m someip live
```

Beim ersten Mal die Werte unter **F2** setzen (Bind-IP, Interface, tshark-Pfad)
und speichern – danach reicht der Befehl oben ohne Argumente.

Mitschnitt offline ansehen:

```
python -m someip analyze capture.pcapng --vlan 73 --sd
python -m someip matrix  capture.pcapng --csv services.csv
```

## Hinweis

Nur am eigenen Fahrzeug, auf eigene Gefahr. Senden kann Fahrzeugfunktionen
beeinflussen – im Zweifel nur mitlesen. Nicht mit BMW affiliiert, keine
Fahrzeug- oder Diagnosedaten im Repo.
