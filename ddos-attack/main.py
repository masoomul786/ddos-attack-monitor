import psutil
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import time
import threading
import logging

# Logging setup
logging.basicConfig(filename="attack_log.txt", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# Variables for attack categories
attack_types = {"DoS": False, "DDoS": False, "Brute Force": False}
ip_blocking_enabled = False
blocked_ips = set()
ip_request_count = {}
ip_threshold = 100  # Example threshold for requests per IP

# Function to categorize attacks based on conditions
def detect_attacks():
    cpu_usage = psutil.cpu_percent(interval=1)
    connections = len(psutil.net_connections())
    net_info = psutil.net_io_counters()
    
    if cpu_usage > 80 and connections > 100:
        attack_types["DoS"] = True
        update_warning_label("WARNING: DoS Attack Detected", "red")
        log_attack("DoS Attack Detected: High CPU and connections")
    
    if net_info.bytes_recv > network_threshold:
        attack_types["DDoS"] = True
        update_warning_label("WARNING: DDoS Attack Detected", "red")
        log_attack("DDoS Attack Detected: High Network Activity")

    for ip, count in ip_request_count.items():
        if count > 200:  # Assume brute force if too many requests
            attack_types["Brute Force"] = True
            update_warning_label("WARNING: Brute Force Attack Detected", "red")
            log_attack(f"Brute Force Attack Detected from IP: {ip}")

def stop_attacks():
    global attack_types, ip_request_count, blocked_ips
    attack_types = {"DoS": False, "DDoS": False, "Brute Force": False}
    ip_request_count.clear()
    blocked_ips.clear()
    update_warning_label("System Stable", "green")
    log_attack("Attacks Stopped. System reset.")

def monitor_ip_requests():
    connections = psutil.net_connections()
    for conn in connections:
        if conn.raddr:
            ip = conn.raddr.ip
            if ip_blocking_enabled and ip in blocked_ips:
                continue
            ip_request_count[ip] = ip_request_count.get(ip, 0) + 1
            if ip_request_count[ip] > ip_threshold:
                blocked_ips.add(ip)
                log_attack(f"IP Blocked: {ip}")

def toggle_ip_blocking():
    global ip_blocking_enabled
    ip_blocking_enabled = not ip_blocking_enabled
    status = "enabled" if ip_blocking_enabled else "disabled"
    toggle_button_label.config(text=f"IP Blocking: {status}")
    log_attack(f"IP blocking {status}")

def update_warning_label(message, color):
    warning_label.config(text=message, foreground=color)

def update_cpu_graph():
    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_data.append(cpu_usage)
    if len(cpu_data) > max_data_points:
        cpu_data.pop(0)

    ax_cpu.clear()
    ax_cpu.plot(cpu_data, label="CPU Usage (%)", color='blue')
    ax_cpu.set_ylim(0, 100)
    ax_cpu.legend(loc="upper right")
    ax_cpu.set_title("CPU Usage")
    canvas_cpu.draw()

def update_memory_graph():
    memory_info = psutil.virtual_memory()
    memory_data.append(memory_info.percent)
    if len(memory_data) > max_data_points:
        memory_data.pop(0)

    ax_memory.clear()
    ax_memory.plot(memory_data, label="Memory Usage (%)", color='green')
    ax_memory.set_ylim(0, 100)
    ax_memory.legend(loc="upper right")
    ax_memory.set_title("Memory Usage")
    canvas_memory.draw()

def update_network_graph():
    net_info = psutil.net_io_counters()
    net_data.append(net_info.bytes_sent + net_info.bytes_recv)
    if len(net_data) > max_data_points:
        net_data.pop(0)

    ax_network.clear()
    ax_network.plot(net_data, label="Network (Bytes Sent + Received)", color='red')
    ax_network.legend(loc="upper right")
    ax_network.set_title("Network Activity")
    canvas_network.draw()

def update_connection_graph():
    active_connections = len(psutil.net_connections())
    connection_data.append(active_connections)
    if len(connection_data) > max_data_points:
        connection_data.pop(0)

    ax_connections.clear()
    ax_connections.plot(connection_data, label="Active Connections", color='purple')
    ax_connections.legend(loc="upper right")
    ax_connections.set_title("Connections")
    canvas_connections.draw()

def log_attack(message):
    logging.info(message)
    attack_log.insert(tk.END, f"{message}\n")

def update_graphs():
    while True:
        update_cpu_graph()
        update_memory_graph()
        update_network_graph()
        update_connection_graph()
        monitor_ip_requests()
        detect_attacks()
        time.sleep(1)

# Create main Tkinter window
root = tk.Tk()
root.title("Cybersecurity Monitoring Tool")
root.geometry("900x700")

# Create a frame for monitoring graphs
graph_frame = ttk.Frame(root)
graph_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Create a frame for the control panel
control_frame = ttk.Frame(root, padding=(10, 10))
control_frame.pack(side=tk.RIGHT, fill=tk.Y)

# Variables for graph data
cpu_data = []
memory_data = []
net_data = []
connection_data = []
max_data_points = 50
network_threshold = 50000000  # 50MB

# Create figures for graphs
fig_cpu = plt.Figure(figsize=(5, 2), dpi=100)
ax_cpu = fig_cpu.add_subplot(111)
canvas_cpu = FigureCanvasTkAgg(fig_cpu, master=graph_frame)
canvas_cpu.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH)

fig_memory = plt.Figure(figsize=(5, 2), dpi=100)
ax_memory = fig_memory.add_subplot(111)
canvas_memory = FigureCanvasTkAgg(fig_memory, master=graph_frame)
canvas_memory.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH)

fig_network = plt.Figure(figsize=(5, 2), dpi=100)
ax_network = fig_network.add_subplot(111)
canvas_network = FigureCanvasTkAgg(fig_network, master=graph_frame)
canvas_network.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH)

fig_connections = plt.Figure(figsize=(5, 2), dpi=100)
ax_connections = fig_connections.add_subplot(111)
canvas_connections = FigureCanvasTkAgg(fig_connections, master=graph_frame)
canvas_connections.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH)

# Add a Text widget for logging attacks
attack_log = tk.Text(root, height=10, state='normal')
attack_log.pack(side=tk.BOTTOM, fill=tk.X)

# Add a larger warning label with specific width
warning_label = ttk.Label(root, text="System Stable", foreground="green", font=("Arial", 16, "bold"), anchor="center")
warning_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(5, 20))

# Control panel UI elements
control_frame.columnconfigure(0, weight=1)

toggle_button_label = ttk.Label(control_frame, text="IP Blocking: disabled")
toggle_button_label.pack(side=tk.TOP, fill=tk.X, pady=(10, 5))

toggle_button = ttk.Button(control_frame, text="Toggle IP Blocking", command=toggle_ip_blocking)
toggle_button.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

stop_button = ttk.Button(control_frame, text="Stop All Attack Detection", command=stop_attacks)
stop_button.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

# Buttons for enabling attack detection
ttk.Button(control_frame, text="Enable DoS Detection", command=lambda: enable_attack("DoS")).pack(fill=tk.X, padx=5, pady=5)
ttk.Button(control_frame, text="Enable DDoS Detection", command=lambda: enable_attack("DDoS")).pack(fill=tk.X, padx=5, pady=5)
ttk.Button(control_frame, text="Enable Brute Force Detection", command=lambda: enable_attack("Brute Force")).pack(fill=tk.X, padx=5, pady=5)

def enable_attack(attack_type):
    attack_types[attack_type] = True
    log_attack(f"{attack_type} detection enabled.")
    update_warning_label(f"{attack_type} detection enabled.", "blue")

# Start the thread to update graphs
thread = threading.Thread(target=update_graphs)
thread.daemon = True
thread.start()

# Start the Tkinter main loop
root.mainloop()
