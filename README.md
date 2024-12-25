# GNU-NetworkMonitor2025

GNU-NetworkMonitor is a Python-based graphical tool designed to monitor networks and scan for connected hosts. It allows users to view detailed information about each host, including its IP address, MAC address, hostname, and manufacturer. Additionally, the tool can scan open ports for any host and retrieve the public IP address and ISP.

## Features

- **Live Network Scanning**: Detects hosts on your local network in real-time.
- **Device Information**: Displays IP, MAC, hostname, and manufacturer of connected devices.
- **Port Scanning**: Scans for open ports on a selected host.
- **Progress Indication**: Includes a progress bar for network and port scanning.
- **Public IP and ISP Detection**: Retrieves your public IP address and ISP details.

## Requirements

- Python 3.6 or later
- Libraries: `tkinter`, `scapy`, `requests`, `netifaces`

## Install the required libraries using pip:

```bash
pip install scapy requests netifaces
```
## Alternative to install in linux:

```
pip install scapy --break-system-packages
pip install requests --break-system-packages
pip install netifaces --break-system-packages
```

## Clone this repository:
```
git clone https://github.com/TheHellishPandaa/GNU-NetworkMonitor.git
cd GNU-NetworkMonitor
 ``` 
## Run the program:

    python GNU-NetworkMonitor.py
´´´
## On Linux:
```
sudo python GNU-NetworkMonitor.py
```
  Follow the graphical interface to scan your network, analyze hosts, and perform port scans.

## Screenshots

## Usage

  - Scan Network: Click on the "Scan Network" button to discover devices in your network. Be patient, as scanning might take a few minutes.
  - View Public IP and ISP: Click on "View Public IP and ISP" to see your public-facing network details.
  - Scan Ports: Select a host from the list and click "Scan Ports" to analyze open ports.

## Note

  - Ensure you run the script with administrative privileges for network scanning.
  - Use the tool responsibly and only on networks you have permission to analyze.

## License

This project is licensed under the GNU License. See the LICENSE file for details.
Contributions

Contributions, issues, and feature requests are welcome! Feel free to submit a pull request or create an issue to improve the tool.


Let me know if you'd like to add or modify anything further!
