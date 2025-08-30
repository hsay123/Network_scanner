# 🛰️ Network Scanner Tool

A simple Python tool to scan your local network and detect connected devices with open ports.  
Built using **Scapy** (for ARP scanning) and **Sockets** (for port scanning).  

---

## ⚡ Features
- Scans the local network for connected devices (IP + MAC)
- Shows total number of connected devices
- Lets user select a target device
- Scans common open ports on the target

---

## 🚀 Installation
1. Clone this repository:+
   ```bash
   git clone https://github.com/hsay123/Network_scanner.git
   cd Network_scanner

2.Install dependencies:
pip install scapy




Usage

Run the tool with sudo (needed for ARP scanning):

sudo python3 INscanner.py


When prompted, enter your network range:
Enter network range (e.g. 192.168.1.0/24)

📌 Example Output
[*] Devices found: 3
IP                MAC
----------------------------------------
[0] 192.168.1.1   aa:bb:cc:dd:ee:ff
[1] 192.168.1.10  11:22:33:44:55:66
[2] 192.168.1.20  77:88:99:aa:bb:cc

Select target device index to scan ports: 1
[+] Open ports on 192.168.1.10: [22, 80, 443]



⚠️ Disclaimer

This tool is for educational and authorized testing only.
Do not use on networks you don’t own or have permission to scan.
  
