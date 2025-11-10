import tkinter as tk
from tkinter import ttk, messagebox
import socket
from scapy.all import ARP, Ether, srp
import threading
import ipaddress
import netifaces
import requests
from concurrent.futures import ThreadPoolExecutor
import time
import subprocess
import platform

# ----------------------- Configuración global -----------------------
dark_mode = True
mac_cache = {}
host_status = {}

# ----------------------- Traducciones ------------------------------
lang_dict = {
    "en": {
        "title": "GNU-NetworkMonitor",
        "dark_theme": "White Theme / Dark Theme",
        "scan_network": "Scan Network",
        "scan_ports": "Scan Ports",
        "check_ip": "Check Public IP",
        "exit": "Exit",
        "progress": "Progress: {}%",
        "estimated_time": "Estimated time remaining: {}s",
        "notice_scan": "The scan might take a few minutes.",
        "select_host_warning": "Please select a host.",
        "error_ip": "Failed to retrieve local IP or subnet mask.",
        "public_ip_info": "Public IP & ISP",
        "scan_complete": "✅ Scan complete!",
    },
    "es": {
        "title": "GNU-NetworkMonitor",
        "dark_theme": "Tema Claro / Oscuro",
        "scan_network": "Escanear Red",
        "scan_ports": "Escanear Puertos",
        "check_ip": "Comprobar IP Pública",
        "exit": "Salir",
        "progress": "Progreso: {}%",
        "estimated_time": "Tiempo estimado restante: {}s",
        "notice_scan": "El escaneo puede tardar unos minutos.",
        "select_host_warning": "Por favor, selecciona un host.",
        "error_ip": "No se pudo obtener la IP local o la máscara de subred.",
        "public_ip_info": "IP Pública y Proveedor",
        "scan_complete": "✅ Escaneo completado!",
    }
}

current_lang = "en"  # Idioma por defecto

# ----------------------- Funciones de idioma -----------------------
def set_language(event=None):
    global current_lang
    current_lang = lang_combo.get()
    
    window.title(lang_dict[current_lang]["title"])
    theme_button.config(text=lang_dict[current_lang]["dark_theme"])
    scan_button.config(text=lang_dict[current_lang]["scan_network"])
    port_button.config(text=lang_dict[current_lang]["scan_ports"])
    check_ip_button.config(text=lang_dict[current_lang]["check_ip"])
    exit_button.config(text=lang_dict[current_lang]["exit"])

# ----------------------- Funciones de tema --------------------------
def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode

    if dark_mode:
        bg_color = "#121212"
        fg_color = "#E0E0E0"
        accent = "#0A84FF"
        button_bg = "#1E1E1E"
        button_fg = "#E0E0E0"
        entry_bg = "#1A1A1A"
        tree_bg = "#1B1B1B"
        tree_fg = "#FFFFFF"
        window.title("GNU-NetworkMonitor (Dark Theme)")
        style.theme_use("clam")
        style.configure("Treeview", background=tree_bg, fieldbackground=tree_bg,
                        foreground=tree_fg, bordercolor=accent, rowheight=25)
        style.map("Treeview", background=[("selected", accent)])
    else:
        bg_color = "#F5F5F5"
        fg_color = "#000000"
        accent = "#0078D7"
        button_bg = "#E8E8E8"
        button_fg = "#000000"
        entry_bg = "#FFFFFF"
        tree_bg = "#FFFFFF"
        tree_fg = "#000000"
        window.title("GNU-NetworkMonitor (Light Theme)")
        style.theme_use("default")
        style.configure("Treeview", background=tree_bg, fieldbackground=tree_bg,
                        foreground=tree_fg, rowheight=25)
        style.map("Treeview", background=[("selected", accent)])

    # Actualiza colores
    window.configure(bg=bg_color)
    local_ip_label.config(bg=bg_color, fg=fg_color)
    progress_label.config(bg=bg_color, fg=fg_color)
    ports_text.config(bg=entry_bg, fg=fg_color, insertbackground=fg_color,
                      relief="flat", bd=2, highlightbackground=accent)
    
    for button in [scan_button, check_ip_button, port_button, exit_button, theme_button]:
        button.config(bg=button_bg, fg=button_fg,
                      activebackground=accent, activeforeground="#FFFFFF",
                      relief="flat", bd=2, highlightbackground=accent)

# ----------------------- Funciones de red ---------------------------
def get_local_ip_and_subnet():
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                netmask = addrs[netifaces.AF_INET][0]['netmask']
                if ip != "127.0.0.1":
                    return ip, netmask
        return None, None
    except Exception as e:
        return None, f"Error: {e}"

def get_public_ip_and_isp():
    try:
        response = requests.get("https://ipinfo.io/json", timeout=5)
        data = response.json()
        return data.get("ip", "N/A"), data.get("org", "N/A")
    except:
        return "Error", "Error retrieving public IP/ISP"

def get_device_manufacturer(mac):
    oui = mac.upper()[0:8]
    if oui in mac_cache:
        return mac_cache[oui]
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            mac_cache[oui] = response.text
            return response.text
        else:
            mac_cache[oui] = "Unknown"
            return "Unknown"
    except:
        mac_cache[oui] = "Error"
        return "Error"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown Hostname"

def get_own_mac(ip):
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            if addrs[netifaces.AF_INET][0]['addr'] == ip:
                return addrs[netifaces.AF_LINK][0]['addr']
    return "Unknown"

def get_os(ip):
    """Detección aproximada de OS basada en TTL de ping."""
    try:
        param = "-n" if platform.system().lower()=="windows" else "-c"
        result = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True)
        output = result.stdout
        ttl_line = [line for line in output.splitlines() if "TTL=" in line.upper() or "ttl=" in line.lower()]
        if ttl_line:
            ttl_str = ttl_line[0].split("TTL=")[-1].split()[0] if "TTL=" in ttl_line[0] else ttl_line[0].split("ttl=")[-1].split()[0]
            ttl = int(ttl_str)
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown/Other"
        return "Unknown"
    except:
        return "Unknown"

# ----------------------- Escaneo de red ----------------------------
def scan_network(local_ip, subnet_mask):
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
        arp_req = ARP(pdst=str(network))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_req
        result = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        total_hosts = len(result) + 1
        progress_step = 100 / max(total_hosts, 1)
        progress_value = 0

        # --- Añadir el propio host ---
        own_mac = get_own_mac(local_ip)
        manufacturer = get_device_manufacturer(own_mac)
        os_name = get_os(local_ip)
        own_host = {"IP": local_ip, "MAC": own_mac,
                    "Manufacturer": manufacturer, "Hostname": socket.gethostname(),
                    "OS": os_name}
        host_status[local_ip] = True
        window.after(0, lambda h=own_host: update_treeview_live(h))
        progress_value += progress_step

        # --- Añadir los demás hosts ---
        for sent, received in result:
            manufacturer = get_device_manufacturer(received.hwsrc)
            hostname = get_hostname(received.psrc)
            os_name = get_os(received.psrc)
            host = {"IP": received.psrc, "MAC": received.hwsrc,
                    "Manufacturer": manufacturer, "Hostname": hostname,
                    "OS": os_name}
            host_status[received.psrc] = True
            window.after(0, lambda h=host: update_treeview_live(h))
            progress_value += progress_step
            window.after(0, lambda v=min(progress_value,100): update_progress_bar(v))

        window.after(0, lambda: update_progress_bar(100))
    except Exception as e:
        window.after(0, lambda: messagebox.showerror("Error", f"Network scan error: {e}"))

def update_treeview_live(host):
    tag = "online" if host_status.get(host["IP"], False) else "offline"
    tree.insert("", "end", values=(host["IP"], host["MAC"], host["Manufacturer"], host["Hostname"], host["OS"]), tags=(tag,))
    tree.tag_configure("online", background="#1e3d1e", foreground="#00ff00")
    tree.tag_configure("offline", background="#3d1e1e", foreground="#ff4444")

def update_progress_bar(value):
    progress_bar["value"] = value
    progress_label.config(text=lang_dict[current_lang]["progress"].format(int(value)))
    window.update_idletasks()

def display_hosts():
    local_ip, netmask = get_local_ip_and_subnet()
    if not local_ip:
        messagebox.showerror("Error", lang_dict[current_lang]["error_ip"])
        return
    messagebox.showinfo(lang_dict[current_lang]["notice_scan"], lang_dict[current_lang]["notice_scan"])
    scan_button.config(state=tk.DISABLED)
    tree.delete(*tree.get_children())
    update_progress_bar(0)
    threading.Thread(target=scan_network, args=(local_ip, netmask), daemon=True).start()
    scan_button.config(state=tk.NORMAL)

# ----------------------- Escaneo de puertos -----------------------
def scan_ports():
    selected_item = tree.focus()
    if not selected_item:
        messagebox.showwarning(lang_dict[current_lang]["select_host_warning"], lang_dict[current_lang]["select_host_warning"])
        return
    host_ip = tree.item(selected_item, "values")[0]
    ports_text.delete("1.0", tk.END)
    ports_text.insert(tk.END, f"Scanning all ports (1-65535) on {host_ip}...\n\n")

    start_time = time.time()
    total_ports = 65535
    scanned_ports = 0

    def scan_port(port):
        nonlocal scanned_ports
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            result = sock.connect_ex((host_ip, port))
            sock.close()
            if result == 0:
                window.after(0, lambda p=port: ports_text.insert(tk.END, f"Open port: {p}\n"))
        except:
            pass
        scanned_ports += 1
        if scanned_ports % 100 == 0:
            elapsed = time.time() - start_time
            remaining = (elapsed / scanned_ports) * (total_ports - scanned_ports)
            window.after(0, lambda r=int(remaining): ports_label.config(text=lang_dict[current_lang]["estimated_time"].format(r)))

    def thread_scan():
        with ThreadPoolExecutor(max_workers=200) as executor:
            executor.map(scan_port, range(1, 65536))
        window.after(0, lambda: ports_text.insert(tk.END, f"\n{lang_dict[current_lang]['scan_complete']}\n"))
        window.after(0, lambda: ports_label.config(text=lang_dict[current_lang]["estimated_time"].format(0)))

    threading.Thread(target=thread_scan, daemon=True).start()

# ----------------------- IP pública -------------------------
def display_public_ip_and_isp():
    public_ip, isp = get_public_ip_and_isp()
    messagebox.showinfo(lang_dict[current_lang]["public_ip_info"], f"Public IP: {public_ip}\nISP: {isp}")

# ----------------------- Interfaz Tkinter -------------------------
window = tk.Tk()
window.title("GNU-NetworkMonitor")
window.geometry("1300x980")
style = ttk.Style()

local_ip, netmask = get_local_ip_and_subnet()

# Etiqueta IP local
local_ip_label = tk.Label(window, text=f"Local IP: {local_ip}\nSubnet Mask: {netmask}", font=("Arial", 12))
local_ip_label.pack(pady=10)

# Selector de idioma
lang_label = tk.Label(window, text="Language / Idioma:", font=("Arial", 10))
lang_label.pack(pady=5)
lang_combo = ttk.Combobox(window, values=["en", "es"], state="readonly")
lang_combo.set(current_lang)
lang_combo.pack()
lang_combo.bind("<<ComboboxSelected>>", set_language)

check_ip_button = tk.Button(window, text=lang_dict[current_lang]["check_ip"], command=display_public_ip_and_isp)
check_ip_button.pack(pady=5)

scan_button = tk.Button(window, text=lang_dict[current_lang]["scan_network"], command=display_hosts)
scan_button.pack(pady=10)

tree_frame = tk.Frame(window)
tree_frame.pack(pady=10)
tree_scroll = tk.Scrollbar(tree_frame)
tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

tree = ttk.Treeview(tree_frame, columns=("IP","MAC","Manufacturer","Hostname","OS"), show="headings",
                    yscrollcommand=tree_scroll.set)
tree.heading("IP", text="IP Address")
tree.heading("MAC", text="MAC Address")
tree.heading("Manufacturer", text="Manufacturer")
tree.heading("Hostname", text="Hostname")
tree.heading("OS", text="OS")
tree.column("IP", width=150)
tree.column("MAC", width=150)
tree.column("Manufacturer", width=200)
tree.column("Hostname", width=200)
tree.column("OS", width=150)
tree.pack()
tree_scroll.config(command=tree.yview)

progress_frame = tk.Frame(window)
progress_frame.pack(pady=10)
progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=500, mode="determinate")
progress_bar.pack()
progress_label = tk.Label(progress_frame, text=lang_dict[current_lang]["progress"].format(0))
progress_label.pack()

port_button = tk.Button(window, text=lang_dict[current_lang]["scan_ports"], command=scan_ports)
port_button.pack(pady=10)

ports_label = tk.Label(window, text=lang_dict[current_lang]["estimated_time"].format(0))
ports_label.pack()
ports_text = tk.Text(window, wrap=tk.WORD, width=80, height=10)
ports_text.pack(pady=10)

exit_button = tk.Button(window, text=lang_dict[current_lang]["exit"], command=window.quit, bg="red", fg="white")
exit_button.pack(pady=10)

theme_button = tk.Button(window, text=lang_dict[current_lang]["dark_theme"], command=toggle_theme)
theme_button.pack(pady=10)

# Activar tema oscuro por defecto
toggle_theme()

window.mainloop()
