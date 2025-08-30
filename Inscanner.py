from scapy.all import ARP, Ether, srp
import socket
import threading

# Function to scan network and list devices
def network_scan(target_ip):
    print(f"\n[*] Scanning network {target_ip} ...")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

# Function to scan ports
def port_scan(target, ports=[21,22,23,25,53,80,110,135,139,143,443,445,3389]):
    print(f"\n[*] Scanning ports on {target} ...")
    open_ports = []

    def scan_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            s.close()

    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return open_ports


if __name__ == "__main__":
    # Example: Scan 192.168.1.0/24
    target_range = input("Enter network range (e.g. 192.168.1.0/24): ")
    devices = network_scan(target_range)

    print(f"\n[*] Devices found: {len(devices)}")
    print("IP" + " " * 18 + "MAC")
    print("-" * 40)
    for i, device in enumerate(devices):
        print(f"[{i}] {device['ip']:15}  {device['mac']}")

    if len(devices) > 0:
        choice = int(input("\nSelect target device index to scan ports: "))
        target_ip = devices[choice]['ip']

        open_ports = port_scan(target_ip)
        if open_ports:
            print(f"\n[+] Open ports on {target_ip}: {open_ports}")
        else:
            print(f"\n[-] No open ports found on {target_ip}")
