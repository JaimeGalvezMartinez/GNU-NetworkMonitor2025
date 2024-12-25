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
sudo python3 GNU-NetworkMonitor.py
```
  Follow the graphical interface to scan your network, analyze hosts, and perform port scans.

## Screenshots

![imagen](https://github.com/user-attachments/assets/826e5f0d-8fe9-48b2-907c-1869dd12b50d)
<br>
![imagen](https://github.com/user-attachments/assets/60980445-1c6e-460f-aac1-5bbd610ec447)
<br>
![imagen](https://github.com/user-attachments/assets/00ac1b81-d850-4c5d-8326-beb7f9bf320c)
<br>
![imagen](https://github.com/user-attachments/assets/b4cf805e-bef1-41e8-96b4-6d53d30cc7e5)
<br>
![imagen](https://github.com/user-attachments/assets/e18eefce-4926-4e0d-8842-a158fec9aaf3)


## Usage

  - Scan Network: Click on the "Scan Network" button to discover devices in your network. Be patient, as scanning might take a few minutes.
  - View Public IP and ISP: Click on "View Public IP and ISP" to see your public-facing network details.
  - Scan Ports: Select a host from the list and click "Scan Ports" to analyze open ports.

## Note

  - Ensure you run the script with administrative privileges for network scanning.
  - Use the tool responsibly and only on networks you have permission to analyze.

## License

This project is licensed under the GNU License. See the ```LICENSE``` file for details.

COPYRIGHT &COPY; 2025 Jaime Galvez Martinez; This project is released under the GNU General Public License

## Contributions

Contributions, issues, and feature requests are welcome! Feel free to submit a pull request or create an issue to improve the tool.

Let me know if you'd like to add or modify anything further!

