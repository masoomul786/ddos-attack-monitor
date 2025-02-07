# DDoS Attack Monitor Tools

## Overview
DDoS Attack Monitor Tools is a cybersecurity monitoring tool that helps detect and prevent DoS, DDoS, and brute force attacks in real-time. It utilizes **psutil** to monitor system resources and **Tkinter** for a graphical user interface.

## Requirements
Ensure you have the following dependencies installed before running the tool:

```sh
pip install psutil matplotlib
```

## Installation
1. Clone the repository and navigate into the project folder:
   ```sh
   git clone https://github.com/masoomul786/ddos-attack-monitor.git
   cd ddos-attack-monitor
   ```

2. Install dependencies (if not already installed):
   ```sh
   pip install -r requirements.txt
   ```

## Running the Project

### Start the Monitoring Tool
Run the script using Python:

```sh
python ddos_monitor.py
```

## Features
- **Real-time monitoring:** Tracks CPU, memory, network, and connection activity.
- **Attack detection:** Identifies DoS, DDoS, and brute force attacks.
- **IP blocking system:** Blocks suspicious IPs based on request thresholds.
- **Graphical visualization:** Displays live graphs of system activity.
- **Logging system:** Saves attack logs for future analysis.

## How It Works
- The tool continuously monitors CPU usage, network activity, and connections.
- If system metrics exceed predefined thresholds, an attack alert is triggered.
- Users can toggle IP blocking and reset the system when needed.
- Attack logs are stored in `attack_log.txt`.

## GUI Overview
The tool provides a Tkinter-based user interface with:
- Live graphs for CPU, memory, network, and connection statistics.
- Warning labels to indicate detected attacks.
- Control panel for enabling/disabling attack detection and IP blocking.

## Contributing
Pull requests are welcome. If you have suggestions or want to improve this tool, feel free to fork the repository and submit a PR.

## License
This project is licensed under the MIT License.

