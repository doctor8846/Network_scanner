# 🛰️ Network Scanner (Tkinter + Scapy)

A simple Python-based **Network Scanner** with a **Tkinter GUI**, designed for educational and authorized network auditing purposes.

---

## 🚀 Features
- ARP-based **network discovery** using [Scapy](https://scapy.net/)
- **TCP port scanning** (common ports) using Python sockets
- **Tkinter GUI** with input box and scrollable results
- Works with **single IP** or **CIDR ranges** (e.g., `192.168.1.0/24`)

---

## 📦 Requirements
- Python **3.8+**
- [Scapy](https://scapy.net/)
- Tkinter (usually bundled with Python)
- Administrator / root privileges

---

## ⚡ Installation
Clone this repository and install the dependencies:

```bash
git clone https://github.com/yourusername/network-scanner-tkinter.git
cd network-scanner-tkinter
python -m venv venv
source venv/bin/activate   # On Linux/macOS
venv\Scripts\activate      # On Windows

pip install -r requirements.txt

