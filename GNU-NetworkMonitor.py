import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
# **NOTA:** scapy solo se usa si platform.system() == "Linux" o si el usuario lo instala.
try:
    from scapy.all import ARP, Ether, srp 
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    
import threading
import ipaddress
import netifaces
import requests
from concurrent.futures import ThreadPoolExecutor
import time
import subprocess
import platform
import re 
import csv 
import os 

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
        "notice_scan": "The scan might take a few minutes. (Requires Npcap on Windows/Sudo on Linux)",
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
        "stop_scan": "Stop Scan",
        "wifi_scan_complete": "✅ WiFi Scan Complete!",
        "wifi_scan_stopped": "🛑 WiFi Scan Stopped by User.",
        "wifi_channel": "Channel",
        "wifi_mac": "BSSID/MAC",
        "wifi_encryption": "Encryption",
        "wifi_signal": "Signal", 
        "wifi_ssid": "Network Name (SSID)",
        "error_interface": "Could not retrieve network interfaces.",
        "error_wifi_scan": "Error scanning. This feature is fully supported only on Linux.",
        "linux_only": "WiFi Scan is fully functional only with Linux (nmcli). On Windows, try updating your IP/Mask on the main screen.",
        "export_csv": "Export to CSV", 
        "csv_success": "Wi-Fi data successfully exported to: {}"
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
        "notice_scan": "El escaneo puede tardar unos minutos. (Requiere Npcap en Windows/Sudo en Linux)",
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
        "stop_scan": "Detener Escaneo",
        "wifi_scan_complete": "✅ Escaneo WiFi Completado!",
        "wifi_scan_stopped": "🛑 Escaneo WiFi Detenido por el Usuario.",
        "wifi_channel": "Canal",
        "wifi_mac": "BSSID/MAC",
        "wifi_encryption": "Cifrado",
        "wifi_signal": "Señal", 
        "wifi_ssid": "Nombre de Red (SSID)",
        "error_interface": "No se pudieron obtener las interfaces de red.",
        "error_wifi_scan": "Error al escanear. Esta función solo es totalmente compatible con Linux.",
        "linux_only": "El escaneo WiFi solo es completamente funcional con Linux (nmcli). En Windows, intenta actualizar tu IP/Máscara en la pantalla principal.",
        "export_csv": "Exportar a CSV", 
        "csv_success": "Datos Wi-Fi exportados correctamente a: {}" 
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
        self.wifi_scan_active = False 
        
        # 1. Obtener todas las interfaces disponibles
        self.all_interfaces = self._get_local_ip_and_subnet()
        self.current_interface = None 
        self.local_ip = None
        self.netmask = None
        
        # Variables de estado de la conexión Wi-Fi 
        self.conn_type = "Unknown"
        self.current_ssid = "N/A"
        self.current_bssid = "N/A"
        self.current_signal = "N/A"
        
        # 2. Seleccionar la primera interfaz y establecer self.local_ip/self.netmask
        if self.all_interfaces:
            # Selecciona la primera interfaz por defecto
            self.current_interface = list(self.all_interfaces.keys())[0]
            self._set_initial_network_vars(initial_load=True) 
            
        self.wifi_networks = {}  
        self.monitor_interface = None 
        
        # 3. UI Setup
        self._setup_style()
        
        # CREACIÓN DE WIDGETS
        self._create_widgets()
        
        # 4. AHORA podemos actualizar el Label
        if self.all_interfaces:
             self._update_network_info()
        
        # Apply initial settings
        self.toggle_theme(initial=True) 
        self.toggle_theme() 
        self.set_language() 

    # ----------------------- Setup & Helpers -----------------------

    def _run_system_command(self, command, check_error=True):
        """
        Ejecuta un comando del sistema.
        """
        try:
            # Comprobación de existencia del comando (solo para nmcli y iw)
            if platform.system() == "Linux":
                if command.startswith("nmcli") and not subprocess.run("which nmcli", shell=True, capture_output=True).returncode == 0:
                    return "nmcli no se encontró. Asegúrate de que NetworkManager esté instalado.", 127
                if command.startswith("iw") and not subprocess.run("which iw", shell=True, capture_output=True).returncode == 0:
                    return "iw no se encontró. Asegúrate de que el paquete 'iw' esté instalado.", 127
                    
            # Ejecución del comando
            # Usar 'creationflags' para ocultar la ventana de la consola en Windows
            creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            
            result = subprocess.run(command, capture_output=True, text=True, check=check_error, shell=True, encoding="utf-8", 
                                    creationflags=creation_flags)
            
            # Limpiamos retornos de carro ('\r') y nulos ('\x00')
            output = result.stdout.strip().replace('\r', '').replace('\x00', '')
            
            return output, result.returncode
        except subprocess.CalledProcessError as e:
            output = e.stderr.strip().replace('\r', '').replace('\x00', '')
            return output, e.returncode
        except FileNotFoundError:
            return "Comando no encontrado.", 127


    def _get_local_ip_and_subnet(self):
        """
        Recupera IP local, máscara de subred y MAC para TODAS las interfaces activas.
        Devuelve: { 'iface_name': {'ip': 'x.x.x.x', 'netmask': 'y.y.y.y', 'mac': 'aa:bb:cc...'} }
        """
        interfaces_details = {}
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                
                # Buscamos la dirección IPv4
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip = ip_info.get('addr')
                    netmask = ip_info.get('netmask')
                    
                    # Ignoramos la interfaz loopback y las que no tienen IP válida
                    if ip and ip != "127.0.0.1" and netmask:
                        mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'N/A')
                        
                        # Corrección de formato de MAC en Windows
                        if platform.system() == "Windows" and mac != 'N/A':
                            mac = mac.replace('-', ':').lower()
                            
                        interfaces_details[iface] = {
                            'ip': ip,
                            'netmask': netmask,
                            'mac': mac
                        }
            return interfaces_details
        except Exception as e:
            print(f"Error al obtener interfaces: {e}")
            return {}
            
    def _get_wifi_details(self, interface_name):
        """
        Obtiene el Tipo de Conexión, SSID, BSSID y Signal (Wi-Fi o Wired).
        Devuelve: (SSID, BSSID, Signal, Type) o (None, None, None, Type)
        """
        system = platform.system()
        ssid, bssid, signal, dev_type = "N/A", "N/A", "N/A", "Unknown"
        
        # --- Lógica Específica para Windows ---
        if system == "Windows":
            # 1. Intentar determinar si es Wi-Fi o Wired basándose en el nombre
            if re.search(r'wireless|wi-fi', interface_name, re.IGNORECASE):
                dev_type = "Wi-Fi"
            elif re.search(r'ethernet|lan', interface_name, re.IGNORECASE):
                dev_type = "Wired"
            else:
                 dev_type = "Unknown"
                 
            # 2. Intentar obtener detalles de Wi-Fi usando 'netsh wlan show interfaces'
            if dev_type == "Wi-Fi":
                try:
                    output, code = self._run_system_command("netsh wlan show interfaces", check_error=False)
                    if code == 0:
                        # Buscar los detalles de la interfaz actual
                        if re.search(rf'Nombre de interfaz\s*:\s*{interface_name}', output, re.IGNORECASE):
                            
                            match_ssid = re.search(r'SSID\s*:\s*([^\n]+)', output, re.IGNORECASE)
                            if match_ssid: ssid = match_ssid.group(1).strip()
                            
                            match_bssid = re.search(r'BSSID\s*:\s*([0-9A-Fa-f:-]+)', output, re.IGNORECASE)
                            if match_bssid: bssid = match_bssid.group(1).strip().replace('-', ':').lower()
                            
                            match_signal = re.search(r'Señal\s*:\s*(\d+)%', output, re.IGNORECASE)
                            if match_signal: signal = match_signal.group(1).strip() # Porcentaje
                            
                            return ssid, bssid, signal, dev_type
                            
                except Exception:
                    # Si netsh falla o no encuentra detalles, seguimos con los valores por defecto
                    pass
            
            return ssid, bssid, signal, dev_type

        # --- Lógica Específica para Linux (EXISTENTE) ---
        elif system == "Linux":
            # (El código existente de Linux con nmcli se mantiene igual)
            try:
                # --- Intento 1: nmcli (Obtener estado general y detectar WIRED primero) ---
                cmd_main = "nmcli"
                output_main, code_main = self._run_system_command(cmd_main, check_error=False)

                if code_main == 0 and interface_name in output_main:
                    
                    # A. Detectar conexión Cableada (Wired/Ethernet)
                    if re.search(rf'{interface_name}:\s+.*ethernet', output_main, re.IGNORECASE | re.DOTALL):
                        dev_type = "Wired" if re.search(rf'{interface_name}:\s+connected', output_main, re.IGNORECASE | re.DOTALL) else "Wired (Disconnected)"
                        return "N/A", "N/A", "N/A", dev_type

                    # B. Si no es cableado, buscamos conexión Wi-Fi
                    if re.search(rf'{interface_name}:\s+.*wifi', output_main, re.IGNORECASE | re.DOTALL):
                        dev_type = "Wi-Fi"
                        
                        match_conn = re.search(rf'{interface_name}:\s+conectado to\s+([^\n]+)', output_main, re.IGNORECASE)
                        if match_conn: ssid = match_conn.group(1).strip()
                        
                        cmd_details_full = f"nmcli -t -f active,bssid,signal,ssid,type device wifi list ifname {interface_name} | grep -E '^yes' | head -n 1"
                        output_details, code_details = self._run_system_command(cmd_details_full, check_error=False)

                        if code_details == 0 and output_details:
                            parts_details = output_details.strip().split(':')

                            if len(parts_details) >= 5:
                                bssid = parts_details[1].strip()
                                signal = parts_details[2].strip() 
                                ssid = parts_details[3].strip() if parts_details[3].strip() else ssid 
                                dev_type = parts_details[4].strip().capitalize()
                            else: 
                                cmd_fallback = f"nmcli -g BSSID,SIGNAL device show {interface_name}"
                                output_fallback, code_fallback = self._run_system_command(cmd_fallback, check_error=False)
                                
                                if code_fallback == 0 and output_fallback:
                                    parts_fallback = output_fallback.strip().split('\n')
                                    if len(parts_fallback) >= 2:
                                        bssid = parts_fallback[0].strip()
                                        signal = parts_fallback[1].strip()
                        
                        if (signal == "N/A" or bssid == "N/A") and self._run_system_command("which iw", check_error=False)[1] == 0:
                            cmd_iw = f"iw dev {interface_name} link"
                            output_iw, code_iw = self._run_system_command(cmd_iw, check_error=False)
                            
                            if code_iw == 0 and output_iw.strip().startswith("Connected to"):
                                match_bssid = re.search(r'BSSID:\s+([0-9A-Fa-f:]{17})', output_iw, re.IGNORECASE)
                                if match_bssid: bssid = match_bssid.group(1).strip()

                                match_signal_dbm = re.search(r'signal:\s*(-?\d+(\.\d+)?)\s*dBm', output_iw, re.IGNORECASE)
                                if match_signal_dbm:
                                    dbm = float(match_signal_dbm.group(1))
                                    signal_perc = min(100, max(0, round((dbm + 100) * 2)))
                                    signal = str(signal_perc)
                                
                                match_ssid_iw = re.search(r'SSID:\s+([^\n]+)', output_iw)
                                if match_ssid_iw and ssid == "N/A": ssid = match_ssid_iw.group(1).strip()

                ssid = ssid if ssid else "N/A"
                bssid = bssid if bssid else "N/A"
                signal = signal if signal else "N/A"
                
                return ssid, bssid, signal, dev_type

            except Exception:
                return "N/A", "N/A", "N/A", "Unknown"
        
        # --- Lógica por defecto (para otros sistemas o errores) ---
        return "N/A", "N/A", "N/A", "Unknown"

            
    def _set_initial_network_vars(self, initial_load=False):
        """
        Recarga self.all_interfaces y establece self.local_ip y self.netmask
        y los detalles Wi-Fi para la interfaz seleccionada.
        """
        self.all_interfaces = self._get_local_ip_and_subnet() 

        if initial_load and not self.current_interface and self.all_interfaces:
             self.current_interface = list(self.all_interfaces.keys())[0]

        if self.current_interface and self.current_interface in self.all_interfaces:
            info = self.all_interfaces[self.current_interface]
            self.local_ip = info['ip']
            self.netmask = info['netmask']
            
            # Detección de detalles Wi-Fi al inicio/recarga
            ssid, bssid, signal, self.conn_type = self._get_wifi_details(self.current_interface)
            self.current_ssid = ssid if ssid else "N/A"
            self.current_bssid = bssid if bssid else "N/A"
            self.current_signal = signal if signal else "N/A"
            
        else:
            self.local_ip = None
            self.netmask = None
            self.conn_type = "Unknown"
            self.current_ssid = "N/A"
            self.current_bssid = "N/A"
            self.current_signal = "N/A"
            
    def _update_network_info(self, event=None):
        """Actualiza la IP, Máscara, y los detalles Wi-Fi de la clase según la interfaz seleccionada y actualiza el Label."""
        tr = LANG_DICT[self.current_lang]
        
        # Recarga la IP y la Máscara del sistema
        self._set_initial_network_vars() 
        
        if self.current_interface and self.current_interface in self.all_interfaces:
            
            ip_info_text = f"Interfaz: {self.current_interface}\nTipo de Conexión: {self.conn_type}\n\n"
            
            if self.conn_type == "Wi-Fi":
                ip_info_text += f"SSID: {self.current_ssid}\n"
                ip_info_text += f"BSSID: {self.current_bssid}\n"
                signal_display = f"{self.current_signal} %" if self.current_signal != "N/A" and self.current_signal.isdigit() else self.current_signal
                ip_info_text += f"Señal: {signal_display}\n"
            
            ip_info_text += f"IP Local: {self.local_ip}\nMáscara de Subred: {self.netmask}"

            self.local_ip_label.config(text=ip_info_text) 
            self.tree.delete(*self.tree.get_children())
        else:
            self.local_ip = None
            self.netmask = None
            self.local_ip_label.config(text=tr["error_ip"])


    def _on_interface_selected(self, event):
        """Maneja el evento de cambio en el selector de interfaz."""
        self.current_interface = self.interface_combo.get()
        self._update_network_info()
        
    def _setup_style(self):
        """Inicializa el estilo ttk."""
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
    def _create_widgets(self):
        """Crea y empaqueta todos los elementos de la GUI."""
        self.master.geometry("1300x980")
        
        # --- Selector de Interfaz ---
        interfaces = list(self.all_interfaces.keys())
        tr = LANG_DICT[self.current_lang]
        
        tk.Label(self.master, text=tr["select_interface"], font=("Arial", 10)).pack(pady=5)
        
        if interfaces:
            self.interface_combo = ttk.Combobox(self.master, values=interfaces, state="readonly")
            self.interface_combo.set(self.current_interface if self.current_interface else interfaces[0])
            self.interface_combo.pack()
            
            self.interface_combo.bind("<<ComboboxSelected>>", self._on_interface_selected)
            self.current_interface = self.interface_combo.get()
        else:
            tk.Label(self.master, text=tr["error_interface"], font=("Arial", 12, "bold"), fg="red").pack(pady=10)

        # --- Información de IP Local (CREACIÓN DEL LABEL) ---
        initial_ip_text = f"Interfaz: {self.current_interface}\nTipo de Conexión: {self.conn_type}\n\nIP Local: {self.local_ip}\nMáscara de Subred: {self.netmask}"
        
        self.local_ip_label = tk.Label(self.master, text=initial_ip_text, font=("Arial", 12))
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
        
        # --- NUEVOS BOTONES DE CONTROL (SALIR y TEMA) ---
        control_frame = tk.Frame(self.master)
        control_frame.pack(pady=10)

        self.theme_button = tk.Button(control_frame, text="", command=self.toggle_theme)
        self.theme_button.pack(side=tk.LEFT, padx=10)
        
        self.exit_button = tk.Button(control_frame, text="", command=self.master.quit, bg="red", fg="white")
        self.exit_button.pack(side=tk.LEFT, padx=10)
        # --------------------------------------------------

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


    # ----------------------- Theme/Language Methods -----------------------
    # (Se mantienen sin cambios)

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
            
        self._update_network_info() 
            
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
        for widget in self.master.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.config(bg=bg_color)
                if widget.winfo_name() == "!frame":
                    widget.config(bg=bg_color)
            if isinstance(widget, (tk.Label, ttk.Label)):
                widget.config(bg=bg_color, fg=fg_color)
            if isinstance(widget, (tk.Button)):
                widget.config(bg=button_bg, fg=button_fg, activebackground=accent, activeforeground="#FFFFFF",
                              relief="flat", bd=2, highlightbackground=accent)
                
        self.ports_text.config(bg=entry_bg, fg=fg_color, insertbackground=fg_color,
                                 relief="flat", bd=2, highlightbackground=accent)
                                 
        self.exit_button.config(bg="red", fg="white")

    # ----------------------- Network Helper Methods -----------------------
    # (Se mantienen sin cambios, son compatibles con ambos sistemas)

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
        mac_clean = re.sub(r'[^0-9A-Fa-f]', '', mac)
        
        oui = mac_clean.upper()[0:6] 
        if len(oui) < 6:
            return "Broadcast/Unknown"
            
        if oui in self.mac_cache:
            return self.mac_cache[oui]
        try:
            mac_for_api = ':'.join(oui[i:i+2] for i in range(0, len(oui), 2)) + ':00:00:00' 

            response = requests.get(f"https://api.macvendors.com/{mac_for_api}", timeout=2)
            manufacturer = response.text.strip() if response.status_code == 200 and response.text.strip() not in ('Not Found', 'null', 'mac address not found') else "Unknown"
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
        if self.current_interface in self.all_interfaces:
            return self.all_interfaces[self.current_interface].get('mac', 'Unknown')
        
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs and netifaces.AF_LINK in addrs:
                if addrs[netifaces.AF_INET][0]['addr'] == ip:
                    mac = addrs[netifaces.AF_LINK][0]['addr']
                    if platform.system() == "Windows":
                        return mac.replace('-', ':').lower()
                    return mac
        return "Unknown"

    def _get_os(self, ip):
        """Detección aproximada del SO basada en el TTL de ping."""
        try:
            # Comando de ping compatible con Windows (-n) y Linux/Unix (-c)
            param = "-n" if platform.system().lower() == "windows" else "-c"
            result = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True, timeout=1)
            output = result.stdout
            
            # Patrón para buscar TTL en la respuesta (compatible con ambos sistemas)
            match = re.search(r'ttl[=\s]\s*(\d+)', output, re.IGNORECASE)
            
            if match:
                ttl = int(match.group(1))
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
        tr = LANG_DICT[self.current_lang]
        
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "La librería Scapy no está instalada o no funciona. Instálala con 'pip install scapy' y, en Windows, instala Npcap, y en Linux, ejecuta con sudo.")
            return

        if not self.local_ip or not self.netmask:
            messagebox.showerror("Error", tr["error_ip"])
            return

        messagebox.showinfo(tr["notice_scan"], tr["notice_scan"])
        self.scan_button.config(state=tk.DISABLED)
        self.tree.delete(*self.tree.get_children())
        self._update_progress_bar(0)
        
        threading.Thread(target=self._run_network_scan, daemon=True).start()

    def _run_network_scan(self):
        """Realiza el escaneo ARP y recopila los detalles del host. (Requiere Sudo/Admin)"""
        if not SCAPY_AVAILABLE: return

        try:
            # USANDO LA INTERFAZ SELECCIONADA
            network = ipaddress.IPv4Network(f"{self.local_ip}/{self.netmask}", strict=False)
            arp_req = ARP(pdst=str(network))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_req
            
            # srp requiere root/administrador y la interfaz
            # Nota: En Windows, Scapy a veces necesita especificar la interfaz
            # Usamos la interfaz actual si está definida
            interface_param = self.current_interface if platform.system() == "Windows" else None
            
            result = srp(arp_request_broadcast, timeout=2, verbose=False, retry=2, iface=interface_param)[0] 
            
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
            msg = f"Error de escaneo de red: Asegúrate de tener Scapy instalado y estar ejecutando como Administrador (Windows) o Sudo (Linux). (Detalle: {e})"
            self.master.after(0, lambda: messagebox.showerror("Error", msg))
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
    # (Se mantienen sin cambios, son compatibles con ambos sistemas)
    
    def scan_ports(self):
        """Inicia el escaneo de puertos multi-hilo."""
        tr = LANG_DICT[self.current_lang]
        selected_item = self.tree.focus()
        if not selected_item:
            messagebox.showwarning(tr["select_host_warning"], tr["select_host_warning"])
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


    # ----------------------- Advanced Mode (WIFI SCAN LOGIC) -----------------------

    def _get_all_interfaces(self):
        """Obtiene todas las interfaces de red del sistema."""
        system = platform.system()
        
        if system == "Linux":
            # Lógica de Linux (nmcli o iw dev)
            output, code = self._run_system_command("nmcli device status | grep wifi", check_error=False)
            if code == 0 and output.strip():
                return [line.split()[0] for line in output.splitlines() if 'wifi' in line.split()]
            
            # Fallback a iw dev si nmcli no encuentra nada o falla
            if not output.strip() or code != 0:
                 iw_output, iw_code = self._run_system_command("iw dev", check_error=False)
                 if iw_code == 0 and "Interface" in iw_output:
                     return [line.split()[1] for line in iw_output.splitlines() if line.strip().startswith("Interface")]

        # Lógica por defecto (incluye Windows)
        # Netifaces devuelve los nombres internos de las interfaces en Windows, lo cual es correcto.
        interfaces = [i for i in netifaces.interfaces() if not i.startswith(("lo", "docker", "veth"))]
        return interfaces


    def _categorize_signal(self, signal_dbm_str):
        """Convierte la intensidad de la señal (porcentaje) a una categoría cualitativa."""
        try:
            signal_perc = int(signal_dbm_str) 
            
            if signal_perc >= 80:
                return ("Excelente", "Excellent") 
            elif signal_perc >= 60:
                return ("Buena", "Good")          
            elif signal_perc >= 40:
                return ("Baja", "Low")
            else:
                return ("Muy Baja", "Very Low")   
            
        except ValueError:
            return (signal_dbm_str, "Error") 
        except Exception:
             return ("Error", "Error")

    def _open_advanced_mode(self):
        """Crea la ventana del Modo Avanzado."""
        tr = LANG_DICT[self.current_lang]
        
        advanced_window = tk.Toplevel(self.master)
        advanced_window.title(tr["advanced_mode"])
        advanced_window.geometry("850x600")
        
        bg_color = "#121212" if self.dark_mode else "#F5F5F5"
        fg_color = "#E0E0E0" if self.dark_mode else "#000000"
        advanced_window.configure(bg=bg_color)
        
        if platform.system() != "Linux":
            # Mensaje de advertencia para sistemas que no son Linux
            tk.Label(advanced_window, text=tr["linux_only"], bg="yellow", fg="black", font=("Arial", 10, "bold")).pack(pady=10)


        # --- Selector de Interfaz y Botón de Escaneo ---
        interface_frame = tk.Frame(advanced_window, bg=bg_color)
        interface_frame.pack(pady=10)
        
        tk.Label(interface_frame, text=tr["select_interface"], bg=bg_color, fg=fg_color).pack(side=tk.LEFT, padx=5)
        
        interfaces = self._get_all_interfaces()
        
        self.interface_combo_adv = ttk.Combobox(interface_frame, values=interfaces, state="readonly", width=12)
        if self.current_interface in interfaces:
            self.interface_combo_adv.set(self.current_interface)
        elif interfaces:
            self.interface_combo_adv.set(interfaces[0])
        else:
            self.interface_combo_adv.set("")
            
        self.interface_combo_adv.pack(side=tk.LEFT, padx=5)
        
        # Botón Iniciar Escaneo
        self.adv_scan_button = tk.Button(interface_frame, text=tr["start_wifi_scan"], 
                                 command=lambda: self._start_wifi_scan_thread(self.interface_combo_adv.get(), advanced_window))
        self.adv_scan_button.pack(side=tk.LEFT, padx=15)
        
        # Botón Detener Escaneo (ROJO)
        self.adv_stop_button = tk.Button(interface_frame, text=tr["stop_scan"], 
                                 command=self._stop_wifi_scan, 
                                 state=tk.DISABLED, bg="red", fg="white")
        self.adv_stop_button.pack(side=tk.LEFT, padx=15)
        
        # Botón de Exportar a CSV
        export_button = tk.Button(interface_frame, text=tr["export_csv"], 
                                 command=self._export_wifi_to_csv)
        export_button.pack(side=tk.LEFT, padx=15)
        
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

        # Configuración de etiquetas de color para la señal
        self.wifi_tree.tag_configure("Excellent", background="#1e3d1e", foreground="#00ff00") 
        self.wifi_tree.tag_configure("Good", background="#3d3d1e", foreground="#ffff00")      
        self.wifi_tree.tag_configure("Low", background="#4a321e", foreground="#ffaa00")       
        self.wifi_tree.tag_configure("Very Low", background="#3d1e1e", foreground="#ff4444")  
        self.wifi_tree.tag_configure("Error", background="#4a4a4a", foreground="#cccccc")     
        
    def _stop_wifi_scan(self):
        """Detiene el ciclo de escaneo Wi-Fi."""
        self.wifi_scan_active = False
        self.adv_scan_button.config(state=tk.NORMAL)
        self.adv_stop_button.config(state=tk.DISABLED)
        messagebox.showinfo(LANG_DICT[self.current_lang]["advanced_mode"], LANG_DICT[self.current_lang]["wifi_scan_stopped"])


    def _start_wifi_scan_thread(self, interface, window):
        """Inicia el escaneo Wi-Fi en un hilo separado."""
        tr = LANG_DICT[self.current_lang]
        
        # En Windows, no podemos escanear, mostramos un mensaje y salimos.
        if platform.system() != "Linux":
            messagebox.showerror("Error", tr["linux_only"])
            return

        self.wifi_networks = {}
        self.wifi_tree.delete(*self.wifi_tree.get_children())
        self.wifi_scan_active = True
        self.adv_scan_button.config(state=tk.DISABLED)
        self.adv_stop_button.config(state=tk.NORMAL)
        
        threading.Thread(target=self._run_wifi_scan, args=(interface, window), daemon=True).start()

    def _run_wifi_scan(self, interface, window):
        """Escanea la red Wi-Fi usando nmcli (SOLO Linux)."""
        tr = LANG_DICT[self.current_lang]
        
        # 1. Iniciar escaneo con nmcli
        self._run_system_command(f"nmcli device wifi rescan ifname {interface}", check_error=False)

        # 2. Obtener la lista de redes
        command = f"nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY device wifi list --rescan yes ifname {interface}"
        output, code = self._run_system_command(command, check_error=False)
        
        # ... [El resto de la lógica de nmcli se mantiene igual para Linux] ...
        
        if code != 0 or not output:
             error_msg = f"{tr['error_wifi_scan']} (nmcli Error: {output if output else 'Desconocido, código:' + str(code)})"
             window.after(0, lambda: messagebox.showerror(tr["advanced_mode"], error_msg))
             self.wifi_scan_active = False
             self.adv_scan_button.config(state=tk.NORMAL)
             self.adv_stop_button.config(state=tk.DISABLED)
             return
        
        lines = output.splitlines()
        
        if not lines:
            window.after(0, lambda: messagebox.showinfo(tr["advanced_mode"], "No se encontraron redes."))
            self.wifi_scan_active = False
            self.adv_scan_button.config(state=tk.NORMAL)
            self.adv_stop_button.config(state=tk.DISABLED)
            return
            
        for line in lines:
            if not self.wifi_scan_active: 
                break
                
            line = line.strip()
            if not line:
                continue
            
            clean_line = line.replace('\\', '')
            parts = clean_line.split(':')
            
            if len(parts) < 9: 
                continue

            try:
                ssid = parts[0].strip() if parts[0].strip() else "<Hidden/Unknown>"
                bssid_raw = parts[1:7]
                bssid = ':'.join([p.strip() for p in bssid_raw])

                channel = parts[7].strip()
                signal_raw = parts[8].strip() 
                encryption = " ".join(parts[9:]).strip() 
                
            except IndexError:
                continue
                
            mac_clean = re.sub(r'[^0-9A-Fa-f]', '', bssid) 
            if len(mac_clean) != 12: 
                 continue

            if mac_clean in self.wifi_networks:
                continue
                
            manufacturer = self._get_device_manufacturer(mac_clean)
            
            signal_category, signal_color_tag = self._categorize_signal(signal_raw)
            
            details = {
                "SSID": ssid,
                "BSSID": ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2)), 
                "Channel": channel,
                "Signal": f"{signal_raw}% ({signal_category})", 
                "Encryption": encryption if encryption else "Open",
                "Manufacturer": manufacturer,
                "ColorTag": signal_color_tag 
            }
            self.wifi_networks[mac_clean] = details
            
            self.master.after(0, lambda d=details: self._update_wifi_treeview(d))

        if self.wifi_scan_active:
             window.after(0, lambda: messagebox.showinfo(tr["advanced_mode"], tr["wifi_scan_complete"]))

        self.wifi_scan_active = False
        self.master.after(0, lambda: self.adv_scan_button.config(state=tk.NORMAL))
        self.master.after(0, lambda: self.adv_stop_button.config(state=tk.DISABLED))


    def _update_wifi_treeview(self, details):
        """Inserta o actualiza un host Wi-Fi en el Treeview con etiquetas de color."""
        tag = details["ColorTag"]
        
        values = (
            details["SSID"], 
            details["BSSID"], 
            details["Channel"], 
            details["Signal"], 
            details["Encryption"], 
            details["Manufacturer"]
        )
        
        for item in self.wifi_tree.get_children():
            if self.wifi_tree.item(item, "values")[1] == details["BSSID"]:
                self.wifi_tree.delete(item)
                break
                
        self.wifi_tree.insert("", "end", values=values, tags=(tag,))


    def _export_wifi_to_csv(self):
        """Exporta los datos de Wi-Fi escaneados a un archivo CSV."""
        
        tr = LANG_DICT[self.current_lang]
        
        if not self.wifi_networks:
            messagebox.showwarning(tr["advanced_mode"], "No hay datos de Wi-Fi para exportar. Por favor, realiza un escaneo primero.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Guardar datos de Wi-Fi como CSV"
        )
        
        if not filename:
            return

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ["SSID", "BSSID", "Channel", "Signal", "Encryption", "Manufacturer"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
                
                writer.writeheader() 
                
                for net in self.wifi_networks.values():
                    net_export = {k: v for k, v in net.items() if k in fieldnames}
                    writer.writerow(net_export)

            messagebox.showinfo(tr["advanced_mode"], tr["csv_success"].format(filename))
            
        except Exception as e:
            messagebox.showerror(tr["advanced_mode"], f"Error al exportar a CSV: {e}")

# ----------------------- Main Tkinter Loop -----------------------

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    app = NetworkMonitorApp(root)
    root.mainloop()
