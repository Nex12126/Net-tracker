# Net-Tracker

Net-Tracker is a portable Windows packet viewer. It starts capturing metadata from the default network interface on launch and can also open PCAP and PCAPNG files. Packet payloads are not displayed in the UI. If you explicitly save a live capture, the PCAPNG file contains the full captured packets, including payloads. Processing and saved files stay on the local computer; the application does not send captured data to a remote service.

## Features

- Live packet list with source, destination, protocol, length, and timestamp
- Live table follows new packets only while already at the bottom, so scrolling up does not snap back
- Header metadata for Ethernet, IPv4, IPv6, TCP, UDP, and ICMP
- Text filter across visible packet fields
- IP-pair grouping is enabled by default and collapses repeated packets into packet and byte totals
- Save an active live capture to a local PCAPNG file
- Live capture uses the default interface without promiscuous mode
- Live view keeps the most recent 20,000 packets in memory
- PCAP and PCAPNG file viewer

Live capture on Windows requires Npcap. The application does not install drivers or request elevation; capture permissions depend on the Npcap installation and current Windows account.

Use **Save capture** during a live session to choose a PCAPNG destination. Select **Stop saving** to close the file cleanly. Saved captures may contain sensitive packet payloads.

## Run from source

Requirements: Windows and Python 3.10 or later. Install Npcap to use live capture.

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe main.py
```

## Build the portable EXE

Run in PowerShell from the project directory:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1
```

The single-file executable is created at `dist\Net-Tracker.exe`. Build the executable on Windows.

Credits: Nex12126

## License

Net-Tracker's original source code is released under the MIT License. See [LICENSE](LICENSE).

Runtime dependencies are distributed under their own licenses. Scapy is GPL-2.0-only. PySide6 is available under LGPL-3.0-only, GPL-2.0-only, GPL-3.0-only, or commercial terms. The portable EXE bundles these dependencies, so review and meet their applicable redistribution requirements before publishing the binary. The MIT license in this repository does not relicense third-party software.