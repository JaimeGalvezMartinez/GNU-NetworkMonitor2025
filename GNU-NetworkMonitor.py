
import tkinter as tk
from tkinter import ttk, messagebox
import socket
# scapy se usa solo para el escaneo ARP, ya no para Wi-Fi, por lo que las importaciones son mínimas.
from scapy.all import ARP, Ether, srp 
import threading
import ipaddress
import netifaces
import requests
from concurrent.futures import ThreadPoolExecutor
import time
import subprocess
import platform
import re 

# ----------------------- Configuration & Translations -----------------------

LANG_DICT = {
    "en": {
        "title": "GNU-NetworkMonitor",
        "dark_theme": "Light Theme / Dark Theme",
        "scan_network": "Scan Network (ARP)",
        "scan_ports": "Scan Ports",
        "check_ip": "Check Public IP",
        "exit": "Exit",
        "progress": "Progress: {}%",
        "estimated_time": "Estimated time remaining: {}s",
        "notice_scan": "The scan might take a few minutes.",
        "select_host_warning": "Please select a host.",
        "error_ip": "Failed to retrieve local IP or subnet mask.",
        "public_ip_info": "Public IP & ISP",
        "scan_complete": "✅ Port scan complete!",
        "ip_address": "IP Address",
        "mac_address": "MAC Address",
        "manufacturer": "Manufacturer",
        "hostname": "Hostname",
        "os": "OS",
        "language": "Language / Idioma:",
        "advanced_mode": "Advanced Mode (WiFi Scan)",
        "select_interface": "Select Interface:",
        "start_wifi_scan": "Start WiFi Scan", 
        "wifi_scan_complete": "✅ WiFi Scan Complete!",
        "wifi_channel": "Channel",
        "wifi_mac": "BSSID/MAC",
        "wifi_encryption": "Encryption",
        "wifi_signal": "Signal (dBm)", 
        "wifi_ssid": "Network Name (SSID)",
        "error_interface": "Could not retrieve network interfaces.",
        "error_wifi_scan": "Error scanning. Ensure NetworkManager is active and the system is Linux.",
        "linux_only": "This feature is only compatible with Linux (nmcli)."
    },
    "es": {
        "title": "GNU-NetworkMonitor",
        "dark_theme": "Tema Claro / Oscuro",
        "scan_network": "Escanear Red (ARP)",
        "scan_ports": "Escanear Puertos",
        "check_ip": "Comprobar IP Pública",
        "exit": "Salir",
        "progress": "Progreso: {}%",
        "estimated_time": "Tiempo estimado restante: {}s",
        "notice_scan": "El escaneo puede tardar unos minutos.",
        "select_host_warning": "Por favor, selecciona un host.",
        "error_ip": "No se pudo obtener la IP local o la máscara de subred.",
        "public_ip_info": "IP Pública y Proveedor",
        "scan_complete": "✅ Escaneo de puertos completado!",
        "ip_address": "Dirección IP",
        "mac_address": "Dirección MAC",
        "manufacturer": "Fabricante",
        "hostname": "Nombre de Host",
        "os": "SO",
        "language": "Language / Idioma:",
        "advanced_mode": "Modo Avanzado (Escanear WiFi)",
        "select_interface": "Seleccionar Interfaz:",
        "start_wifi_scan": "Iniciar Escaneo WiFi",
        "wifi_scan_complete": "✅ Escaneo WiFi Completado!",
        "wifi_channel": "Canal",
        "wifi_mac": "BSSID/MAC",
        "wifi_encryption": "Cifrado",
        "wifi_signal": "Señal (dBm)",
        "wifi_ssid": "Nombre de Red (SSID)",
        "error_interface": "No se pudieron obtener las interfaces de red.",
        "error_wifi_scan": "Error al escanear. Asegúrate de que NetworkManager esté activo y el sistema sea Linux.",
        "linux_only": "Esta función solo es compatible con Linux (nmcli)."
    }
}

# ----------------------- Network Monitor Class ------------------------------

class NetworkMonitorApp:
    def __init__(self, master):
        self.master = master
        self.current_lang = "es"
        self.dark_mode = False
        self.mac_cache = {}
        self.host_status = {}
        self.local_ip, self.netmask = self._get_local_ip_and_subnet()
        self.wifi_networks = {} 
        self.monitor_interface = None 
        
        # UI Setup
        self._setup_style()
        self._create_widgets()
        
        # Apply initial settings
        self.toggle_theme(initial=True) 
        self.toggle_theme() 
        self.set_language() 

    # ----------------------- Setup & Helpers -----------------------

    def _get_local_ip_and_subnet(self):
        """Recupera la IP local y la máscara de subred."""
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    netmask = addrs[netifaces.AF_INET][0]['netmask']
                    if ip != "127.0.0.1":
                        return ip, netmask
            return None, None
        except Exception:
            return None, None

    def _setup_style(self):
        """Inicializa el estilo ttk."""
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
    def _create_widgets(self):
        """Crea y empaqueta todos los elementos de la GUI."""
        self.master.geometry("1300x980")

        # --- Información de IP Local ---
        ip_info_text = f"IP Local: {self.local_ip}\nMáscara de Subred: {self.netmask}"
        self.local_ip_label = tk.Label(self.master, text=ip_info_text, font=("Arial", 12))
        self.local_ip_label.pack(pady=10)

        # --- Selector de Idioma ---
        tk.Label(self.master, text=LANG_DICT[self.current_lang]["language"], font=("Arial", 10)).pack(pady=5)
        self.lang_combo = ttk.Combobox(self.master, values=list(LANG_DICT.keys()), state="readonly")
        self.lang_combo.set(self.current_lang)
        self.lang_combo.pack()
        self.lang_combo.bind("<<ComboboxSelected>>", self.set_language)

        # --- Botones de Acción Principal ---
        self.check_ip_button = tk.Button(self.master, text="", command=self.display_public_ip_and_isp)
        self.check_ip_button.pack(pady=5)
        
        self.scan_button = tk.Button(self.master, text="", command=self._start_network_scan)
        self.scan_button.pack(pady=10)
        
        self.advanced_button = tk.Button(self.master, text="", command=self._open_advanced_mode)
        self.advanced_button.pack(pady=10)

        # --- Treeview para Hosts de Red ---
        tree_frame = tk.Frame(self.master)
        tree_frame.pack(pady=10)
        tree_scroll = tk.Scrollbar(tree_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        columns = ("IP", "MAC", "Manufacturer", "Hostname", "OS")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", yscrollcommand=tree_scroll.set)
        for col in columns:
             self.tree.heading(col, text="")
        self.tree.column("IP", width=150)
        self.tree.column("MAC", width=150)
        self.tree.column("Manufacturer", width=200)
        self.tree.column("Hostname", width=200)
        self.tree.column("OS", width=150)
        self.tree.pack()
        tree_scroll.config(command=self.tree.yview)

        # --- Barra de Progreso ---
        progress_frame = tk.Frame(self.master)
        progress_frame.pack(pady=10)
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=500, mode="determinate")
        self.progress_bar.pack()
        self.progress_label = tk.Label(progress_frame, text=LANG_DICT[self.current_lang]["progress"].format(0))
        self.progress_label.pack()

        # --- Sección de Escaneo de Puertos ---
        self.port_button = tk.Button(self.master, text="", command=self.scan_ports)
        self.port_button.pack(pady=10)

        self.ports_label = tk.Label(self.master, text=LANG_DICT[self.current_lang]["estimated_time"].format(0))
        self.ports_label.pack()
        self.ports_text = tk.Text(self.master, wrap=tk.WORD, width=80, height=10)
        self.ports_text.pack(pady=10)

        # --- Botones de Pie de Página ---
        self.exit_button = tk.Button(self.master, text="", command=self.master.quit, bg="red", fg="white")
        self.exit_button.pack(pady=10)

        self.theme_button = tk.Button(self.master, text="", command=self.toggle_theme)
        self.theme_button.pack(pady=10)

    # ----------------------- Theme/Language Methods -----------------------

    def set_language(self, event=None):
        """Actualiza todo el texto de la GUI basado en el idioma seleccionado."""
        self.current_lang = self.lang_combo.get() if event else self.current_lang
        
        tr = LANG_DICT[self.current_lang]
        self.master.title(tr["title"])
        self.theme_button.config(text=tr["dark_theme"])
        self.scan_button.config(text=tr["scan_network"])
        self.port_button.config(text=tr["scan_ports"])
        self.check_ip_button.config(text=tr["check_ip"])
        self.exit_button.config(text=tr["exit"])
        self.advanced_button.config(text=tr["advanced_mode"])
        self.progress_label.config(text=tr["progress"].format(int(self.progress_bar["value"])))
        self.ports_label.config(text=tr["estimated_time"].format(0))

        headings = ["ip_address", "mac_address", "manufacturer", "hostname", "os"]
        columns = ("IP", "MAC", "Manufacturer", "Hostname", "OS")
        for i, col in enumerate(columns):
            self.tree.heading(col, text=tr[headings[i]])
            
    def toggle_theme(self, initial=False):
        """Alterna entre el tema oscuro y el claro."""
        if not initial:
            self.dark_mode = not self.dark_mode

        if self.dark_mode:
            bg_color, fg_color, accent = "#121212", "#E0E0E0", "#0A84FF"
            button_bg, button_fg, entry_bg = "#1E1E1E", "#E0E0E0", "#1A1A1A"
            tree_bg, tree_fg = "#1B1B1B", "#FFFFFF"
            self.master.title(f"{LANG_DICT[self.current_lang]['title']} (Tema Oscuro)")
            self.style.theme_use("clam")
            
            self.style.configure("Treeview", background=tree_bg, fieldbackground=tree_bg,
                                foreground=tree_fg, bordercolor=accent, rowheight=25)
            self.style.map("Treeview", background=[("selected", accent)])
            self.style.configure("Treeview.Heading", background="#1E1E1E", foreground="#FFFFFF")
        else:
            bg_color, fg_color, accent = "#F5F5F5", "#000000", "#0078D7"
            button_bg, button_fg, entry_bg = "#E8E8E8", "#000000", "#FFFFFF"
            tree_bg, tree_fg = "#FFFFFF", "#000000"
            self.master.title(f"{LANG_DICT[self.current_lang]['title']} (Tema Claro)")
            self.style.theme_use("default")
            
            self.style.configure("Treeview", background=tree_bg, fieldbackground=tree_bg,
                                foreground=tree_fg, rowheight=25)
            self.style.map("Treeview", background=[("selected", accent)])
            self.style.configure("Treeview.Heading", background="#D3D3D3", foreground="#000000")

        self.master.configure(bg=bg_color)
        for widget in [self.local_ip_label, self.progress_label, self.ports_label] + self.master.winfo_children()[2:4]:
            if isinstance(widget, (tk.Label, ttk.Label)):
                widget.config(bg=bg_color, fg=fg_color)
                
        self.ports_text.config(bg=entry_bg, fg=fg_color, insertbackground=fg_color,
                               relief="flat", bd=2, highlightbackground=accent)
        
        for button in [self.scan_button, self.check_ip_button, self.port_button, self.exit_button, self.theme_button, self.advanced_button]:
            button.config(bg=button_bg, fg=button_fg, activebackground=accent, activeforeground="#FFFFFF",
                          relief="flat", bd=2, highlightbackground=accent)
        self.exit_button.config(bg="red", fg="white") 

    # ----------------------- Network Helper Methods -----------------------

    def _get_public_ip_and_isp(self):
        """Recupera la IP pública y la información del proveedor (ISP)."""
        try:
            response = requests.get("https://ipinfo.io/json", timeout=5)
            data = response.json()
            return data.get("ip", "N/A"), data.get("org", "N/A")
        except:
            return "Error", "Error retrieving public IP/ISP"

    def _get_device_manufacturer(self, mac):
        """Recupera el fabricante a partir de la dirección MAC (OUI)."""
        oui = mac.upper()[0:8]
        if len(oui) < 8 or mac == "ff:ff:ff:ff:ff:ff":
            return "Broadcast/Unknown"
            
        if oui in self.mac_cache:
            return self.mac_cache[oui]
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            manufacturer = response.text.strip() if response.status_code == 200 else "Unknown"
            self.mac_cache[oui] = manufacturer
            return manufacturer
        except:
            self.mac_cache[oui] = "Error"
            return "Error"

    def _get_hostname(self, ip):
        """Realiza una búsqueda DNS inversa."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown Hostname"

    def _get_own_mac(self, ip):
        """Encuentra la dirección MAC de la máquina local para una IP dada."""
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs and netifaces.AF_LINK in addrs:
                if addrs[netifaces.AF_INET][0]['addr'] == ip:
                    return addrs[netifaces.AF_LINK][0]['addr']
        return "Unknown"

    def _get_os(self, ip):
        """Detección aproximada del SO basada en el TTL de ping."""
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            result = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True, timeout=1)
            output = result.stdout
            for line in output.splitlines():
                if "TTL=" in line.upper() or "ttl=" in line.lower():
                    ttl_str = line.split("TTL=")[-1].split()[0] if "TTL=" in line else line.split("ttl=")[-1].split()[0]
                    ttl = int(ttl_str)
                    if ttl <= 64: return "Linux/Unix"
                    elif ttl <= 128: return "Windows"
                    else: return "Unknown/Other"
            return "Unknown"
        except:
            return "Unknown"
            
    def display_public_ip_and_isp(self):
        """Obtiene y muestra la IP pública/ISP en un cuadro de mensaje."""
        tr = LANG_DICT[self.current_lang]
        public_ip, isp = self._get_public_ip_and_isp()
        messagebox.showinfo(tr["public_ip_info"], f"IP Pública: {public_ip}\nISP: {isp}")

    # ----------------------- Network Scan (ARP) Logic ----------------------------
    
    def _start_network_scan(self):
        """Prepara e inicia el escaneo de red en un hilo separado."""
        if not self.local_ip or not self.netmask:
            messagebox.showerror("Error", LANG_DICT[self.current_lang]["error_ip"])
            return

        messagebox.showinfo(LANG_DICT[self.current_lang]["notice_scan"], LANG_DICT[self.current_lang]["notice_scan"])
        self.scan_button.config(state=tk.DISABLED)
        self.tree.delete(*self.tree.get_children())
        self._update_progress_bar(0)
        
        threading.Thread(target=self._run_network_scan, daemon=True).start()

    def _run_network_scan(self):
        """Realiza el escaneo ARP y recopila los detalles del host. (Requiere Sudo)"""
        try:
            network = ipaddress.IPv4Network(f"{self.local_ip}/{self.netmask}", strict=False)
            arp_req = ARP(pdst=str(network))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_req
            
            # srp requiere root/administrador
            result = srp(arp_request_broadcast, timeout=2, verbose=False, retry=2)[0] 
            
            # --- Incluir el host propio ---
            own_mac = self._get_own_mac(self.local_ip)
            manufacturer = self._get_device_manufacturer(own_mac)
            os_name = self._get_os(self.local_ip)
            own_host = {"IP": self.local_ip, "MAC": own_mac, 
                        "Manufacturer": manufacturer, "Hostname": socket.gethostname(), "OS": os_name}
            self.host_status[self.local_ip] = True
            
            hosts_to_process = [(None, own_host)] + [(sent, received) for sent, received in result]
            total_hosts = len(hosts_to_process)
            progress_step = 100 / max(total_hosts, 1)
            progress_value = 0

            self._update_treeview_live(own_host)
            progress_value += progress_step
            self.master.after(0, lambda v=min(progress_value,100): self._update_progress_bar(v))

            for i, (sent, received) in enumerate(hosts_to_process[1:]):
                ip = received.psrc
                mac = received.hwsrc
                manufacturer = self._get_device_manufacturer(mac)
                hostname = self._get_hostname(ip)
                os_name = self._get_os(ip)
                
                host = {"IP": ip, "MAC": mac, "Manufacturer": manufacturer, "Hostname": hostname, "OS": os_name}
                self.host_status[ip] = True
                
                self.master.after(0, lambda h=host: self._update_treeview_live(h))
                progress_value += progress_step
                self.master.after(0, lambda v=min(progress_value,100): self._update_progress_bar(v))
            
            self.master.after(0, lambda: self._update_progress_bar(100))

        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Error de escaneo de red: Asegúrate de usar Sudo. (Detalle: {e})"))
        finally:
            self.master.after(0, lambda: self.scan_button.config(state=tk.NORMAL))

    def _update_treeview_live(self, host):
        """Inserta un host en el Treeview con etiquetas de color."""
        tag = "online" if self.host_status.get(host["IP"], False) else "offline"
        self.tree.insert("", "end", values=(host["IP"], host["MAC"], host["Manufacturer"], host["Hostname"], host["OS"]), tags=(tag,))
        self.tree.tag_configure("online", background="#1e3d1e", foreground="#00ff00")
        self.tree.tag_configure("offline", background="#3d1e1e", foreground="#ff4444")

    def _update_progress_bar(self, value):
        """Actualiza la barra de progreso y la etiqueta."""
        self.progress_bar["value"] = value
        self.progress_label.config(text=LANG_DICT[self.current_lang]["progress"].format(int(value)))
        self.master.update_idletasks()

    # ----------------------- Port Scan Logic ------------------------------
    
    def scan_ports(self):
        """Inicia el escaneo de puertos multi-hilo."""
        selected_item = self.tree.focus()
        if not selected_item:
            messagebox.showwarning(LANG_DICT[self.current_lang]["select_host_warning"], LANG_DICT[self.current_lang]["select_host_warning"])
            return
            
        host_ip = self.tree.item(selected_item, "values")[0]
        self.ports_text.delete("1.0", tk.END)
        self.ports_text.insert(tk.END, f"Escaneando todos los puertos (1-65535) en {host_ip}...\n\n")

        self.start_time = time.time()
        self.total_ports = 65535
        self.scanned_ports = 0
        
        threading.Thread(target=self._thread_port_scan, args=(host_ip,), daemon=True).start()
        
    def _scan_single_port(self, host_ip, port):
        """Escanea un solo puerto y actualiza la GUI si está abierto."""
        self.scanned_ports += 1
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    self.master.after(0, lambda p=port: self.ports_text.insert(tk.END, f"Puerto Abierto: {p}\n"))
        except Exception:
            pass
        
        if self.scanned_ports % 100 == 0:
            elapsed = time.time() - self.start_time
            if self.scanned_ports > 0:
                remaining = (elapsed / self.scanned_ports) * (self.total_ports - self.scanned_ports)
                self.master.after(0, lambda r=int(remaining): self.ports_label.config(text=LANG_DICT[self.current_lang]["estimated_time"].format(r)))
            
    def _thread_port_scan(self, host_ip):
        """Gestiona el pool de hilos para el escaneo de puertos."""
        with ThreadPoolExecutor(max_workers=200) as executor:
            scan_func = lambda port: self._scan_single_port(host_ip, port)
            executor.map(scan_func, range(1, self.total_ports + 1))
            
        self.master.after(0, lambda: self.ports_text.insert(tk.END, f"\n{LANG_DICT[self.current_lang]['scan_complete']}\n"))
        self.master.after(0, lambda: self.ports_label.config(text=LANG_DICT[self.current_lang]["estimated_time"].format(0)))


    # ----------------------- Advanced Mode (NUEVA LÓGICA SIN MODO MONITOR) -----------------------

    def _run_system_command(self, command, check_error=True):
        """Ejecuta un comando del sistema y maneja la salida."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=check_error, shell=True)
            return result.stdout.strip(), result.returncode
        except subprocess.CalledProcessError as e:
            return e.stderr.strip(), e.returncode
        except FileNotFoundError:
            return "Comando no encontrado.", 1
    
    def _get_all_interfaces(self):
        """Obtiene todas las interfaces de red del sistema, filtrando solo Wi-Fi si es Linux."""
        try:
            if platform.system() == "Linux":
                output, code = self._run_system_command("nmcli device status | grep wifi", check_error=False)
                if code == 0:
                    return [line.split()[0] for line in output.splitlines() if 'wifi' in line.split()]
            
            interfaces = [i for i in netifaces.interfaces() if not i.startswith(("lo", "docker", "veth"))]
            return interfaces
        except Exception:
            return []


    def _open_advanced_mode(self):
        """Crea la ventana del Modo Avanzado."""
        tr = LANG_DICT[self.current_lang]
        
        advanced_window = tk.Toplevel(self.master)
        advanced_window.title(tr["advanced_mode"])
        advanced_window.geometry("850x600")
        
        bg_color = "#121212" if self.dark_mode else "#F5F5F5"
        fg_color = "#E0E0E0" if self.dark_mode else "#000000"
        
        advanced_window.configure(bg=bg_color)
        
        # --- Selector de Interfaz y Botón de Escaneo ---
        interface_frame = tk.Frame(advanced_window, bg=bg_color)
        interface_frame.pack(pady=10)
        
        tk.Label(interface_frame, text=tr["select_interface"], bg=bg_color, fg=fg_color).pack(side=tk.LEFT, padx=5)
        
        interfaces = self._get_all_interfaces()
        
        self.interface_combo = ttk.Combobox(interface_frame, values=interfaces, state="readonly", width=12)
        self.interface_combo.set(interfaces[0] if interfaces else "")
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        scan_button = tk.Button(interface_frame, text=tr["start_wifi_scan"], 
                                command=lambda: self._start_wifi_scan_thread(self.interface_combo.get(), advanced_window))
        scan_button.pack(side=tk.LEFT, padx=15)
        
        # --- Treeview para Redes WiFi ---
        tree_frame = tk.Frame(advanced_window)
        tree_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        tree_scroll = tk.Scrollbar(tree_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        wifi_columns = ("SSID", "BSSID", "Channel", "Signal", "Encryption", "Manufacturer")
        self.wifi_tree = ttk.Treeview(tree_frame, columns=wifi_columns, show="headings", yscrollcommand=tree_scroll.set)
        
        self.wifi_tree.heading("SSID", text=tr["wifi_ssid"]); self.wifi_tree.column("SSID", width=150)
        self.wifi_tree.heading("BSSID", text=tr["wifi_mac"]); self.wifi_tree.column("BSSID", width=120)
        self.wifi_tree.heading("Channel", text=tr["wifi_channel"]); self.wifi_tree.column("Channel", width=80)
        self.wifi_tree.heading("Signal", text=tr["wifi_signal"]); self.wifi_tree.column("Signal", width=80)
        self.wifi_tree.heading("Encryption", text=tr["wifi_encryption"]); self.wifi_tree.column("Encryption", width=100)
        self.wifi_tree.heading("Manufacturer", text=tr["manufacturer"]); self.wifi_tree.column("Manufacturer", width=120)
        
        self.wifi_tree.pack(fill=tk.BOTH, expand=True)
        tree_scroll.config(command=self.wifi_tree.yview)

        self.wifi_tree.tag_configure("available", background="#2a522a", foreground="#a0ffb0") 
        self.wifi_tree.tag_configure("unknown", background="#4a4a4a", foreground="#cccccc") 

    def _start_wifi_scan_thread(self, interface, window):
        """Inicia el escaneo Wi-Fi en un hilo separado."""
        tr = LANG_DICT[self.current_lang]
        if not interface or platform.system() != "Linux":
            messagebox.showerror("Error", tr["linux_only"])
            return

        self.wifi_networks = {}
        self.wifi_tree.delete(*self.wifi_tree.get_children())
        
        threading.Thread(target=self._run_wifi_scan, args=(interface, window), daemon=True).start()

    def _run_wifi_scan(self, interface, window):
        """Escanea la red Wi-Fi usando nmcli (Linux) y actualiza la GUI. NO REQUIERE SUDO."""
        tr = LANG_DICT[self.current_lang]
        
        # 1. Iniciar escaneo con nmcli
        self._run_system_command(f"nmcli device wifi rescan ifname {interface}", check_error=False)

        # 2. Obtener la lista de redes
        output, code = self._run_system_command(f"nmcli device wifi list ifname {interface}", check_error=False)
        
        if code != 0 or not output:
             window.after(0, lambda: messagebox.showerror(tr["advanced_mode"], f"{tr['error_wifi_scan']}"))
             return
        
        lines = output.splitlines()
        
        if len(lines) < 2:
            window.after(0, lambda: messagebox.showinfo(tr["advanced_mode"], "No se encontraron redes."))
            return
            
        for line in lines[1:]:
            parts = line.split()
            # Patrones de nmcli típicos: BSSID RATE SIGNAL BARS CHANNEL FREQ TYPE SECURITY SSID
            # Los campos son variables, necesitamos una forma robusta de extraerlos
            if len(parts) < 8:
                continue

            try:
                # Intento de parseo fijo basado en el formato nmcli list, sin usar regex para simplificar
                bssid = parts[0]
                signal = parts[2] 
                channel = parts[4]
                # Seguridad puede ser un campo o varios. Simplificamos a uno de los últimos
                encryption = parts[6]
                ssid = " ".join(parts[8:]) 
            except IndexError:
                # Si el formato cambia, saltamos esta línea.
                continue
                
            if bssid in self.wifi_networks:
                continue
                
            manufacturer = self._get_device_manufacturer(bssid)
            
            details = {
                "SSID": ssid if ssid else "<Hidden/Unknown>",
                "BSSID": bssid,
                "Channel": channel,
                "Signal": signal,
                "Encryption": encryption,
                "Manufacturer": manufacturer
            }
            self.wifi_networks[bssid] = details
            
            self.master.after(0, lambda d=details: self._update_wifi_treeview(d))

        window.after(0, lambda: messagebox.showinfo(tr["advanced_mode"], tr["wifi_scan_complete"]))


    def _update_wifi_treeview(self, details):
        """Inserta la red Wi-Fi en el Treeview, pintándola de verde si tiene un SSID."""
        
        tag = "available" if details["SSID"] not in ["<Hidden/Unknown>", "<Hidden SSID>"] else "unknown"
        
        self.wifi_tree.insert("", "end", 
                              values=(details["SSID"], details["BSSID"], details["Channel"], 
                                      details["Signal"], details["Encryption"], details["Manufacturer"]), 
                              tags=(tag,))

# ----------------------- Main Execution ---------------------------------

if __name__ == "__main__":
    # NOTA: El Escaneo ARP (parte de la funcionalidad principal) AÚN requiere permisos de root/sudo para Scapy.
    # El Escaneo Wi-Fi ya NO los requiere, pero sigue siendo conveniente ejecutar con sudo para usar todas las funciones.
    
    window = tk.Tk()
    app = NetworkMonitorApp(window)
    window.mainloop()
