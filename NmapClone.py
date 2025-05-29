import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from scapy.all import IP, TCP, sr1
import csv
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from concurrent.futures import ThreadPoolExecutor

MAX_THREADS = 10  # Optimize the scanning speed your system compacity 

def scan_tcp_port(src_ip, dst_ip, port):       # Sending TCP SYN packet
    try:
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=False)
        if response and response.haslayer(TCP):             #We  Checking to see if TCP response exists
            if response[TCP].flags == 0x12:
                return f"Port {port} (TCP) is OPEN", "green"    # green ifport open, red if close and blue if FILTERED or blocked 
            elif response[TCP].flags == 0x14:
                return f"Port {port} (TCP) is CLOSED", "red"
        else:
            return f"Port {port} (TCP) is FILTERED or no response", "blue"
    except Exception as e:
        return f"Error scanning TCP port {port}: {e}", "gray"

def scan_udp_port(dst_ip, port):                              # here we create UDP socket and wait for response 2 sec 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'', (dst_ip, port))
        sock.settimeout(2)
        try:
            _, _ = sock.recvfrom(1024)
            return f"Port {port} (UDP) is OPEN", "green"
        except socket.timeout:
            return f"Port {port} (UDP) is FILTERED or no response", "blue"
        finally:
            sock.close()
    except Exception as e:
        return f"Error scanning UDP port {port}: {e}", "gray"

def start_scan():                                               #start scan function button 
    src_ip = src_entry.get()
    dst_ip = dst_entry.get()
    port_range = port_entry.get()

    try:
        start_port, end_port = map(int, port_range.split('-'))      # we convert the range to int (numbers)
    except ValueError:
        messagebox.showerror("Error", "Invalid port range format. Use: start-end")
        return

    results_widget.delete(1.0, tk.END)      # removing previous results
    progress_bar["value"] = 0
    progress_bar["maximum"] = (end_port - start_port + 1)

    scan_thread = threading.Thread(target=run_scan, args=(src_ip, dst_ip, start_port, end_port))    # we start scanning in a separate thread
    scan_thread.start()

def run_scan(src_ip, dst_ip, start_port, end_port):
    results = []
    graph = nx.Graph()     # create the network graph

    def scan_port(port):
        tcp_result, tcp_color = scan_tcp_port(src_ip, dst_ip, port)
        udp_result, udp_color = scan_udp_port(dst_ip, port)

        results.append([port, tcp_result, udp_result])
        results_widget.after(0, lambda: update_results_widget(tcp_result, tcp_color))
        results_widget.after(0, lambda: update_results_widget(udp_result, udp_color))
        graph.add_edge(dst_ip, f"Port {port}", color=get_port_color(tcp_result, udp_result))
        progress_bar.after(0, lambda: progress_bar.step(1))

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(scan_port, range(start_port, end_port + 1))

    save_results_to_csv(results)
    window.after(0, lambda: embed_matplotlib_graph(graph))          # adding the  visualization to run inside Tkinter's main thread instead of opening two seperate windows 

def update_results_widget(result_text, color):              
    results_widget.insert(tk.END, result_text + "\n")
    results_widget.tag_add(color, "end-2l", "end-1c")
    results_widget.tag_config(color, foreground=color)

def save_results_to_csv(results):
    filename = "port_scan_results.csv"
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Port", "TCP Status", "UDP Status"])
        writer.writerows(results)
    messagebox.showinfo("Export Complete", f"Results saved to {filename}")

def get_port_color(tcp_result, udp_result):
    if "OPEN" in tcp_result or "OPEN" in udp_result:
        return "green"
    elif "CLOSED" in tcp_result:
        return "red"
    else:
        return "blue"

def embed_matplotlib_graph(graph):                         # Embed Matplotlib graph inside Tkinter window (executed in main thread)
   
    for widget in graph_frame.winfo_children():
        widget.destroy()

    edges = graph.edges()
    colors = [graph[u][v]["color"] for u, v in edges]

    fig, ax = plt.subplots(figsize=(10, 4))                 # Runs in main thread
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, edge_color=colors, with_labels=True, node_size=500, font_size=10, ax=ax)
    ax.set_title("Port Scan Visualization")

    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    plt.close(fig)


window = tk.Tk()                         # Setting up the GUI Layout 
window.title("Network Scanner with Embedded Graph")
window.geometry("1000x800")
window.resizable(False, False)


input_frame = tk.LabelFrame(window, text="Scan Settings", padx=10, pady=10)
input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

tk.Label(input_frame, text="Source IP:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
src_entry = tk.Entry(input_frame)
src_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(input_frame, text="Destination IP:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
dst_entry = tk.Entry(input_frame)
dst_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(input_frame, text="Port Range (e.g., 20-80):").grid(row=2, column=0, sticky="e", padx=5, pady=5)
port_entry = tk.Entry(input_frame)
port_entry.grid(row=2, column=1, padx=5, pady=5)

scan_button = tk.Button(input_frame, text="Start Scan", command=start_scan)
scan_button.grid(row=3, column=0, columnspan=2, pady=10)

progress_bar = ttk.Progressbar(window, orient="horizontal", length=550, mode="determinate")
progress_bar.grid(row=1, column=0, padx=10, pady=5, sticky="ew")


results_frame = tk.LabelFrame(window, text="Scan Results", padx=10, pady=10) # The esults Frame
results_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

results_widget = tk.Text(results_frame, height=10, width=70)
results_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar = tk.Scrollbar(results_frame, command=results_widget.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
results_widget.config(yscrollcommand=scrollbar.set)

results_widget.tag_config("green", foreground="green")
results_widget.tag_config("red", foreground="red")
results_widget.tag_config("blue", foreground="blue")
results_widget.tag_config("gray", foreground="gray")


graph_frame = tk.LabelFrame(window, text="Port Scan Visualization", padx=10, pady=10)
graph_frame.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

window.grid_rowconfigure(3, weight=1)
window.grid_columnconfigure(0, weight=1)

window.mainloop()

