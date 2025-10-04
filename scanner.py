import socket

import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
import threading
import ipaddress


def scan_ports(ip, ports=None, timeout=0.5):
    if ports is None:
        # Common ports for demonstration
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports

def scan(ip_range):
    # ARP scan to discover devices in the network
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        # Scan for open ports on each discovered device
        open_ports = scan_ports(ip)
        device_dict = {"ip": ip, "mac": mac, "ports": open_ports}
        devices.append(device_dict)
    return devices


def validate_ip_range(ip_range):
    try:
        # Accepts both single IP and CIDR
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def scan_thread(ip_range):
    try:
        devices = scan(ip_range)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "ARP Scan Results (IP, MAC, Open Ports)\n")
        result_text.insert(tk.END, "IP Address\t\tMAC Address\t\tOpen Ports\n")
        result_text.insert(tk.END, "---------------------------------------------------------------\n")
        if devices:
            for device in devices:
                ports_str = ', '.join(str(p) for p in device['ports']) if device['ports'] else 'None'
                result_text.insert(tk.END, f"{device['ip']}\t\t{device['mac']}\t\t{ports_str}\n")
        else:
            result_text.insert(tk.END, "No devices found.\n")
    except PermissionError:
        result_text.delete(1.0, tk.END)
        messagebox.showerror("Permission Error", "You must run this script as Administrator/root.")
    except Exception as e:
        result_text.delete(1.0, tk.END)
        messagebox.showerror("Error", f"Scan failed: {e}")
    finally:
        scan_button.config(state=tk.NORMAL)

def start_scan():
    ip_range = entry_ip.get().strip()
    if not ip_range or not validate_ip_range(ip_range):
        messagebox.showerror("Error", "Please enter a valid IP range (e.g., 192.168.1.1/24)")
        return
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Scanning...\n")
    scan_button.config(state=tk.DISABLED)
    # Start scan in a new thread
    threading.Thread(target=scan_thread, args=(ip_range,), daemon=True).start()

# Create the main Tkinter window
root = tk.Tk()
root.title("Network Scanner")
root.geometry("600x400")

# Create and place UI elements

# Label to indicate ARP scanning
label_ip = tk.Label(root, text="Enter IP Range (e.g., 192.168.1.1/24) for ARP Scan:")
label_ip.pack(pady=10)


entry_ip = tk.Entry(root, width=30)
entry_ip.pack(pady=5)
entry_ip.bind('<Return>', lambda event: start_scan())

scan_button = tk.Button(root, text="Scan Network", command=start_scan)
scan_button.pack(pady=10)

result_text = scrolledtext.ScrolledText(root, width=60, height=15, wrap=tk.WORD)
result_text.pack(pady=10)

# Start the Tkinter event loop
root.mainloop()