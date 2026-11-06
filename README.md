# 🦉 OExfilSim

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Attack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OExfilSim** — Exfiltration channel detector + offline simulator — pcap, Zeek, flows, DNS/ICMP/cloud/chunking ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OExfilSim — Exfiltration channel detector + offline simulator — pcap, Zeek, flows, DNS/ICMP/cloud/chunking. Exfiltration channel detector + offline channel simulator. Finds data exfiltration in packet captures (pcap/pcapng), Zeek logs and flow exports: DNS tunnelling, ICMP payload channels, uploads to file-drop / paste / webhook / tunnel services, bulk egress over alternative protocols, periodic chunked transfers.

---

## ✨ Features

- Detect exfiltration channels from pcap, Zeek and flow inputs
- Offline simulator covering DNS, ICMP, cloud and chunking patterns
- Beaconing, volume and destination anomaly signals
- Safe lab simulation without live attacker infrastructure
- Structured findings with severity grading
- Export detections for blue-team playbooks

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OExfilSim OExfilSim.go
./OExfilSim --help
./OExfilSim --input capture.pcap
./OExfilSim --input flows.log --format json
./OExfilSim --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
