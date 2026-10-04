
<div align="center">

# 🛡️ allben-ngfw-ml-firewall

### *Next-Generation Firewall with ML-Based Traffic Classification & Automated Threat Response*

[![Live Demo](https://img.shields.io/badge/🌐_Live_Demo-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://allben-ngfw-ml-firewall.streamlit.app/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)
[![iptables](https://img.shields.io/badge/iptables-Compatible-blue?style=for-the-badge&logo=linux&logoColor=white)]()
[![pfSense](https://img.shields.io/badge/pfSense-Compatible-orange?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)

**A production-grade Next-Generation Firewall built by [Allben Rakgoale](https://github.com/allben09) that classifies network traffic using Machine Learning, generates real firewall rules, and automatically blocks malicious IPs — moving from detection to prevention.**

 [📊 Architecture](#-architecture) · [🚀 Quick Start](#-quick-start) · [🧠 ML Model](#-ml-model-details) · [📸 Screenshots](#-screenshots)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [The NGFW Problem](#-the-ngfw-problem)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [How It Works](#-how-it-works)
- [ML Model Details](#-ml-model-details)
- [Attack Classes Detected](#-attack-classes-detected)
- [Firewall Rule Engine](#-firewall-rule-engine)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Docker Deployment](#-docker-deployment)
- [Cloud Deployment](#-cloud-deployment)
- [Screenshots](#-screenshots)
- [Metrics & Performance](#-metrics--performance)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🔍 Overview

**allben-ngfw-ml-firewall** is a production-grade Next-Generation Firewall that goes beyond simple rule-based filtering. It combines **multi-class Machine Learning** with an **automated rule engine** to:

- 🎯 **Classify** every network flow into `normal`, `port_scan`, `ddos`, or `exfiltration`
- 🧠 **Score** threats with confidence percentages
- 🛡️ **Generate** real iptables / pfSense rules automatically
- 🚫 **Block** malicious IPs with zero human intervention
- 📊 **Visualize** the entire defence pipeline in real-time

Built for **SOC teams, network engineers, and security automation**, this project demonstrates the complete **detection → classification → response** lifecycle that every modern enterprise needs.

---

## 🎯 The NGFW Problem

> *"Traditional firewalls block based on static rules — but attackers adapt. Modern threats require ML-driven, adaptive defence."*

| Challenge | Why Traditional Firewalls Fail |
| :--- | :--- |
| **Attackers use legitimate ports** | Rules can't distinguish valid from malicious traffic on port 443 |
| **Signatures are always behind** | Zero-day attacks bypass signature databases |
| **Manual rule tuning is slow** | SOC analysts can't react to threats in seconds |
| **Encrypted traffic is opaque** | 90%+ of traffic is TLS-encrypted; content inspection fails |
| **Volume is overwhelming** | 100,000+ flows/day — impossible to analyse manually |

**Solution:** ML-based flow classification that operates at **wire speed** and **auto-deploys rules** in milliseconds.

---

## ✨ Key Features

<table>
<tr>
<td width="50%">

### 🤖 ML Classification Layer

- **Multi-class Random Forest** (4 attack types)
- **200 decision trees** with balanced class weights
- **9 engineered flow features**: packet size, duration, flags, entropy
- **Real-time inference** — < 50ms per flow
- **Confidence scoring** — every prediction includes reliability

</td>
<td width="50%">

### 🛡️ Automated Rule Engine

- **iptables** script generation (Linux)
- **pfSense** rule generation (BSD)
- **Configurable confidence threshold** (default 80%)
- **IP deduplication** — no duplicate block rules
- **Executable export** — download `.sh` scripts

</td>
</tr>
<tr>
<td width="50%">

### 🎭 Real Attack Simulation

- **Port Scanning** — SYN-only random probes
- **DDoS** — SYN flood with massive packets
- **Data Exfiltration** — 50–500 MB long sessions
- **Realistic normal traffic** — weighted protocols, typical ports
- **24-hour time window** with millisecond precision

</td>
<td width="50%">

### 🚀 Production-Ready

- **Streamlit Cloud** deployed
- **Dockerised** — one-command deployment
- **Live attack simulation** button
- **CSV + shell script export**
- **Interactive feature importance**

</td>
</tr>
</table>

---

## 🏗️ Architecture
