import tkinter as tk
from tkinter import ttk, messagebox
import socket
from scapy.all import ARP, Ether, srp
import threading
import ipaddress
import netifaces
import requests

def get_local_ip_and_subnet():
    """Gets the local IP address and subnet mask of the active interface."""
    try:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                netmask = addrs[netifaces.AF_INET][0]['netmask']
                if ip != "127.0.0.1":
                    return ip, netmask
        return None, None
    except Exception as e:
        return None, f"Error retrieving IP or netmask: {e}"

def get_public_ip_and_isp():
    """Gets the public IP address and ISP using a third-party service."""
    try:
        response = requests.get("https://ipinfo.io/json")
        data = response.json()
        public_ip = data.get("ip", "N/A")
        isp = data.get("org", "N/A")
        return public_ip, isp
    except Exception as e:
        return "Error", f"Error retrieving public IP/ISP: {e}"

def get_device_manufacturer(mac_address):
    """Gets the manufacturer of the device based on its MAC address."""
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Manufacturer"
    except Exception:
        return "Error retrieving manufacturer"

def get_hostname(ip):
    """Gets the hostname for an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown Hostname"

def scan_network(local_ip, subnet_mask):
    """Scans the network to find hosts, their MAC addresses, manufacturers, and hostnames."""
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
        hosts = []
        total_hosts = len(list(network.hosts()))  # Total number of hosts
        progress_step = 100 / total_hosts  # Progress per host
        progress_value = 0

        arp_request = ARP(pdst=str(network))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        result = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        for sent, received in result:
            manufacturer = get_device_manufacturer(received.hwsrc)
            hostname = get_hostname(received.psrc)
            host = {
                "IP": received.psrc,
                "MAC": received.hwsrc,
                "Manufacturer": manufacturer,
                "Hostname": hostname,
            }
            hosts.append(host)
            update_treeview_live(host)
            progress_value += progress_step
            update_progress_bar(min(progress_value, 100))

        update_progress_bar(100)
        return hosts
    except Exception as e:
        messagebox.showerror("Error", f"Error scanning the network: {e}")
        return []

def update_treeview_live(host):
    """Updates the TreeView live with a detected host."""
    tree.insert("", "end", values=(host["IP"], host["MAC"], host["Manufacturer"], host["Hostname"]))

def update_progress_bar(value):
    """Updates the progress bar value."""
    progress_bar["value"] = value
    progress_label.config(text=f"Progress: {int(value)}%")
    window.update_idletasks()

def display_hosts():
    """Starts network scanning and displays detected hosts live."""
    local_ip, netmask = get_local_ip_and_subnet()
    if local_ip is None or netmask is None:
        messagebox.showerror("Error", "Failed to retrieve local IP or subnet mask.")
        return

    # Display warning message before starting
    messagebox.showinfo("Notice", "The scan might take a few minutes. Please be patient.")

    scan_button.config(state=tk.DISABLED)
    tree.delete(*tree.get_children())  # Clear TreeView
    update_progress_bar(0)

    threading.Thread(target=scan_network, args=(local_ip, netmask)).start()
    scan_button.config(state=tk.NORMAL)

def scan_ports():
    """Scans open ports for the selected host."""
    selected_item = tree.focus()
    if not selected_item:
        messagebox.showwarning("Warning", "Please select a host to scan ports.")
        return

    host_ip = tree.item(selected_item, "values")[0]
    ports_text.delete("1.0", tk.END)
    ports_text.insert(tk.END, f"Scanning open ports on {host_ip}...\n\n")

    def port_scan_thread():
        open_ports = []
        progress_step = 100 / 1024
        progress_value = 0

        for port in range(1, 1025):  # Scan the first 1024 ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    open_ports.append(port)
                    ports_text.insert(tk.END, f"Open port: {port}\n")
                sock.close()
            except Exception as e:
                ports_text.insert(tk.END, f"Error scanning port {port}: {e}\n")
            progress_value += progress_step
            update_progress_bar(min(progress_value, 100))

        update_progress_bar(100)
        ports_text.insert(tk.END, f"\nOpen ports for {host_ip}: {open_ports}\n")

    threading.Thread(target=port_scan_thread).start()

def display_public_ip_and_isp():
    """Displays the public IP and ISP."""
    public_ip, isp = get_public_ip_and_isp()
    messagebox.showinfo("Network Information", f"Public IP: {public_ip}\nInternet Provider: {isp}")

# Create the main window
window = tk.Tk()
window.title("GNU-NetworkMonitor")
window.geometry("1300x900")

# Display local IP and subnet mask
local_ip, netmask = get_local_ip_and_subnet()
local_ip_label = tk.Label(window, text=f"Local IP: {local_ip}\nSubnet Mask: {netmask}", font=("Arial", 12))
local_ip_label.pack(pady=10)

# Create a button to scan the network
scan_button = tk.Button(window, text="Scan Network", command=display_hosts)
scan_button.pack(pady=10)

# Treeview to display the hosts
tree_frame = tk.Frame(window)
tree_frame.pack(pady=10)
tree_scroll = tk.Scrollbar(tree_frame)
tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

tree = ttk.Treeview(tree_frame, columns=("IP", "MAC", "Manufacturer", "Hostname"), show="headings", yscrollcommand=tree_scroll.set)
tree.heading("IP", text="IP Address")
tree.heading("MAC", text="MAC Address")
tree.heading("Manufacturer", text="Manufacturer")
tree.heading("Hostname", text="Hostname")
tree.column("IP", width=150)
tree.column("MAC", width=150)
tree.column("Manufacturer", width=200)
tree.column("Hostname", width=200)
tree.pack()
tree_scroll.config(command=tree.yview)

# Progress bar
progress_frame = tk.Frame(window)
progress_frame.pack(pady=10)
progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=500, mode="determinate")
progress_bar.pack()
progress_label = tk.Label(progress_frame, text="Progress: 0%")
progress_label.pack()

# Button to display public IP and ISP
public_ip_button = tk.Button(window, text="View Public IP and ISP", command=display_public_ip_and_isp)
public_ip_button.pack(pady=10)

# Button to scan ports
port_button = tk.Button(window, text="Scan Ports", command=scan_ports)
port_button.pack(pady=10)

# Text area to display port scan results
ports_text = tk.Text(window, wrap=tk.WORD, width=80, height=10)
ports_text.pack(pady=10)

# Exit button
exit_button = tk.Button(window, text="Exit", command=window.quit, bg="red", fg="white")
exit_button.pack(pady=10)

# Run the Tkinter event loop
window.mainloop()
