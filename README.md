# bimmer-someip

Small tool to watch the SOME/IP traffic on a BMW's automotive Ethernet, discover
services and offer your own. Plus a few helpers to pick apart Wireshark captures.

Tested on a BMW G11 (745e, G series). The laptop sits on the vehicle backbone
through an **NXP RDDRONE-T1ADAPT** (RJ45 <-> 100BASE-T1), on VLAN 73.

Python 3.12, no extra packages. tshark (from Wireshark) is only needed for live
capture and the offline analysis.

## Start

```
python -m someip live
```

On first run set the values under **F2** (bind IP, interface, tshark path) and
save them – after that the command above works without arguments.

Look at a capture offline:

```
python -m someip analyze capture.pcapng --vlan 73 --sd
python -m someip matrix  capture.pcapng --csv services.csv
```

## Note

Only on your own car, at your own risk. Sending can affect vehicle functions –
when in doubt just listen. Not affiliated with BMW, no vehicle or diagnostic
data in this repo.
