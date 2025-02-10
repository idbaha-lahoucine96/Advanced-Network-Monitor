import tkinter as tk
from ttkbootstrap import Style, ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tableview import Tableview
from scapy.all import *
from datetime import datetime, timedelta
import threading
import json
import socket
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx
import pandas as pd
from geopy.geocoders import Nominatim
from ipwhois import IPWhois
import numpy as np
from typing import Dict, List, Any
import logging
import queue

class AdvancedNetworkMonitor:
    def __init__(self, root: tk.Tk):
        """Initialize the Advanced Network Monitor application."""
        self.root = root
        self.style = Style(theme='darkly')
        self.root.title("Advanced Network Monitor")
        self.root.geometry("1400x900")
        
        # Initialize data structures
        self.attacks_data: List[List[str]] = []
        self.is_capturing = False
        self.packet_counter = 0
        self.packet_queue = queue.Queue()
        self.ip_cache: Dict[str, Dict[str, str]] = {}
        
        # Initialize figures for graphs
        self.attack_type_fig = None
        self.attack_type_canvas = None
        self.attack_time_fig = None
        self.attack_time_canvas = None
        self.network_fig = None
        self.network_canvas = None
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='network_monitor.log'
        )
        
        self.threat_levels = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        
        self.attack_patterns = self._initialize_attack_patterns()
        self.setup_gui()
        self._start_packet_processor()

    def _initialize_attack_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize attack pattern definitions."""
        return {
            'syn_flood': {
                'pattern': lambda pkt: TCP in pkt and pkt[TCP].flags == 2,
                'severity': 'High',
                'description': 'SYN Flood Attack',
                'risk_level': 3,
                'details': 'TCP SYN flood attempt detected'
            },
            'ping_flood': {
                'pattern': lambda pkt: ICMP in pkt and pkt[ICMP].type == 8,
                'severity': 'Medium',
                'description': 'Ping Flood Attack',
                'risk_level': 2,
                'details': 'ICMP flood attempt detected'
            },
            'port_scan': {
                'pattern': lambda pkt: TCP in pkt and pkt[TCP].flags == 2,
                'severity': 'High',
                'description': 'Port Scan',
                'risk_level': 3,
                'details': 'Port scanning activity detected'
            },
            'dns_amplification': {
                'pattern': lambda pkt: UDP in pkt and pkt[UDP].dport == 53,
                'severity': 'Critical',
                'description': 'DNS Amplification',
                'risk_level': 4,
                'details': 'DNS amplification attack detected'
            },
            'arp_spoofing': {
                'pattern': lambda pkt: ARP in pkt,
                'severity': 'Critical',
                'description': 'ARP Spoofing',
                'risk_level': 4,
                'details': 'ARP spoofing attempt detected'
            }
        }

    def setup_gui(self):
        """Set up the graphical user interface."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create main pages
        main_page = ttk.Frame(self.notebook)
        analysis_page = ttk.Frame(self.notebook)
        map_page = ttk.Frame(self.notebook)
        
        self.notebook.add(main_page, text="Live Monitoring")
        self.notebook.add(analysis_page, text="Advanced Analysis")
        self.notebook.add(map_page, text="Attack Map")
        
        self.setup_main_page(main_page)
        self.setup_analysis_page(analysis_page)
        self.setup_map_page(map_page)

    def setup_main_page(self, parent: ttk.Frame):
        """Set up the main monitoring page."""
        # Control toolbar
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill='x', pady=5, padx=5)
        
        control_frame = ttk.Frame(toolbar)
        control_frame.pack(side='left')
        
        self.start_button = ttk.Button(
            control_frame,
            text="▶ Start Monitoring",
            style='success.TButton',
            command=self.start_capture
        )
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(
            control_frame,
            text="⏹ Stop Monitoring",
            style='danger.TButton',
            command=self.stop_capture,
            state='disabled'
        )
        self.stop_button.pack(side='left', padx=5)
        
        ttk.Button(
            control_frame,
            text="💾 Export Report",
            style='info.TButton',
            command=self.export_report
        ).pack(side='left', padx=5)
        
        # Advanced search frame
        self.setup_search_frame(parent)
        
        # Statistics panel
        self.setup_stats_panel(parent)
        
        # Main table
        self.setup_main_table(parent)

    def setup_search_frame(self, parent: ttk.Frame):
        """Set up the advanced search frame."""
        search_frame = ttk.LabelFrame(parent, text="Advanced Search", padding=10)
        search_frame.pack(fill='x', pady=5, padx=5)
        
        # Search row 1
        search_row1 = ttk.Frame(search_frame)
        search_row1.pack(fill='x', pady=2)
        
        ttk.Label(search_row1, text="Search:").pack(side='left', padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_table)
        ttk.Entry(search_row1, textvariable=self.search_var).pack(side='left', padx=5)
        
        ttk.Label(search_row1, text="Severity:").pack(side='left', padx=5)
        self.severity_var = tk.StringVar(value="All")
        ttk.Combobox(
            search_row1,
            textvariable=self.severity_var,
            values=["All", "Critical", "High", "Medium", "Low"],
            width=10
        ).pack(side='left', padx=5)
        
        # Search row 2
        search_row2 = ttk.Frame(search_frame)
        search_row2.pack(fill='x', pady=2)
        
        ttk.Label(search_row2, text="Attack Type:").pack(side='left', padx=5)
        self.attack_type_var = tk.StringVar(value="All")
        ttk.Combobox(
            search_row2,
            textvariable=self.attack_type_var,
            values=["All"] + [info['description'] for info in self.attack_patterns.values()],
            width=20
        ).pack(side='left', padx=5)

    def setup_stats_panel(self, parent: ttk.Frame):
        """Set up the statistics panel."""
        stats_frame = ttk.LabelFrame(parent, text="Monitoring Statistics", padding=10)
        stats_frame.pack(fill='x', pady=5, padx=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x')
        
        self.stats_labels = {}
        stats = [
            ("packets", "📊 Packets Monitored: 0"),
            ("attacks", "⚠️ Attacks Detected: 0"),
            ("unique_ips", "🌐 Unique IPs: 0"),
            ("risk_level", "⚡ Current Risk Level: Low")
        ]
        
        for i, (key, text) in enumerate(stats):
            label = ttk.Label(stats_grid, text=text, style='info.TLabel')
            label.grid(row=i//2, column=i%2, padx=10, pady=2, sticky='w')
            self.stats_labels[key] = label

    def setup_main_table(self, parent: ttk.Frame):
        """Set up the main monitoring table."""
        columns = [
            {"text": "⏰ Time", "stretch": True},
            {"text": "🔍 Attack Type", "stretch": True},
            {"text": "⚠️ Severity", "stretch": True},
            {"text": "📍 Source", "stretch": True},
            {"text": "🎯 Target", "stretch": True},
            {"text": "📝 Details", "stretch": True}
        ]
        
        self.table = Tableview(
            parent,
            coldata=columns,
            searchable=True,
            bootstyle=PRIMARY,
            stripecolor=('gray86', None),
            height=15
        )
        self.table.pack(fill='both', expand=True, pady=5, padx=5)

    def setup_analysis_page(self, parent: ttk.Frame):
        """Set up the analysis page with graphs."""
        graphs_frame = ttk.Frame(parent)
        graphs_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.attack_type_fig = plt.Figure(figsize=(6, 4))
        self.attack_type_canvas = FigureCanvasTkAgg(self.attack_type_fig, graphs_frame)
        self.attack_type_canvas.get_tk_widget().pack(side='left', fill='both', expand=True)
        
        self.attack_time_fig = plt.Figure(figsize=(6, 4))
        self.attack_time_canvas = FigureCanvasTkAgg(self.attack_time_fig, graphs_frame)
        self.attack_time_canvas.get_tk_widget().pack(side='right', fill='both', expand=True)

    def setup_map_page(self, parent: ttk.Frame):
        """Set up the network map page."""
        self.network_fig = plt.Figure(figsize=(12, 8))
        self.network_canvas = FigureCanvasTkAgg(self.network_fig, parent)
        self.network_canvas.get_tk_widget().pack(fill='both', expand=True)

    def start_capture(self):
        """Start packet capture."""
        if not self.is_capturing:
            self.is_capturing = True
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            
            # Start packet capture in a separate thread
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            logging.info("Packet capture started")

    def stop_capture(self):
        """Stop packet capture."""
        self.is_capturing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        logging.info("Packet capture stopped")

    def _capture_packets(self):
        """Capture network packets."""
        try:
            sniff(prn=self._packet_callback, store=0, stop_filter=lambda p: not self.is_capturing)
        except Exception as e:
            logging.error(f"Error in packet capture: {str(e)}")
            self.root.after(0, self.stop_capture)

    def _packet_callback(self, packet):
        """Process captured packet."""
        self.packet_counter += 1
        self.packet_queue.put(packet)

    def _start_packet_processor(self):
        """Start the packet processing thread."""
        def process_packets():
            while True:
                try:
                    packet = self.packet_queue.get(timeout=1)
                    self.analyze_packet(packet)
                except queue.Empty:
                    if not self.is_capturing:
                        break
                except Exception as e:
                    logging.error(f"Error processing packet: {str(e)}")
        
        processor_thread = threading.Thread(target=process_packets)
        processor_thread.daemon = True
        processor_thread.start()

    def analyze_packet(self, packet):
        """Analyze packet for potential attacks."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            for attack_name, attack_info in self.attack_patterns.items():
                if attack_info['pattern'](packet):
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    src_info = self.get_ip_info(src_ip)
                    
                    row_data = [
                        timestamp,
                        attack_info['description'],
                        attack_info['severity'],
                        f"{src_ip} ({src_info['country']})",
                        dst_ip,
                        f"{attack_info['details']} | {src_info['org']}"
                    ]
                    
                    self.attacks_data.append(row_data)
                    self.root.after(0, self.update_display, row_data)
                    logging.info(f"Attack detected: {attack_info['description']} from {src_ip}")

    def get_ip_info(self, ip: str) -> Dict[str, str]:
        """Get IP information with caching."""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            
            info = {
                'country': result.get('asn_country_code', 'Unknown'),
                'org': result.get('asn_description', 'Unknown'),
                'asn': result.get('asn', 'Unknown')
            }
            
            self.ip_cache[ip] = info
            return info
        except Exception as e:
            logging.error(f"Error getting IP info for {ip}: {str(e)}")
            return {'country': 'Unknown', 'org': 'Unknown', 'asn': 'Unknown'}

    def update_display(self, row_data: List[str]):
        """Update all display elements."""
        self.table.insert_row('end', row_data)
        self.table.see('end')
        self.update_stats()
        
        if len(self.attacks_data) % 10 == 0:
            self.update_graphs()
            self.update_network_map()

    def update_stats(self):
        """Update statistics display."""
        unique_ips = set()
        current_risk = 0
        
        recent_attacks = self.attacks_data[-100:]
        for attack in recent_attacks:
            unique_ips.add(attack[3])
            unique_ips.add(attack[4])
            current_risk = max(current_risk, self.threat_levels.get(attack[2], 0))
        
        # Update statistics labels
        self.stats_labels['packets'].config(
            text=f"📊 Packets Monitored: {self.packet_counter:,}"
        )
        self.stats_labels['attacks'].config(
            text=f"⚠️ Attacks Detected: {len(self.attacks_data):,}"
        )
        self.stats_labels['unique_ips'].config(
            text=f"🌐 Unique IPs: {len(unique_ips):,}"
        )
        
        # Update risk level with appropriate styling
        risk_text, risk_style = self._get_risk_level_info(current_risk)
        self.stats_labels['risk_level'].config(
            text=f"⚡ Current Risk Level: {risk_text}",
            style=risk_style
        )

    def _get_risk_level_info(self, risk_level: int) -> tuple:
        """Get risk level text and style."""
        if risk_level == 4:
            return "Critical", "danger.inverse.TLabel"
        elif risk_level == 3:
            return "High", "danger.TLabel"
        elif risk_level == 2:
            return "Medium", "warning.TLabel"
        else:
            return "Low", "success.TLabel"

    def update_graphs(self):
        """Update all analysis graphs."""
        self._update_attack_type_graph()
        self._update_attack_time_graph()

    def _update_attack_type_graph(self):
        """Update attack type distribution graph."""
        self.attack_type_fig.clear()
        ax1 = self.attack_type_fig.add_subplot(111)
        
        attack_counts = pd.Series([attack[1] for attack in self.attacks_data]).value_counts()
        attack_counts.plot(kind='bar', ax=ax1)
        
        ax1.set_title('Attack Type Distribution')
        ax1.set_ylabel('Number of Attacks')
        ax1.tick_params(axis='x', rotation=45)
        
        self.attack_type_fig.tight_layout()
        self.attack_type_canvas.draw()

    def _update_attack_time_graph(self):
        """Update attack timeline graph."""
        self.attack_time_fig.clear()
        ax2 = self.attack_time_fig.add_subplot(111)
        
        times = pd.to_datetime([attack[0] for attack in self.attacks_data])
        pd.Series(1, index=times).resample('1Min').sum().plot(ax=ax2)
        
        ax2.set_title('Attack Rate Over Time')
        ax2.set_ylabel('Attacks/Minute')
        
        self.attack_time_fig.tight_layout()
        self.attack_time_canvas.draw()

    def update_network_map(self):
        """Update network attack map."""
        G = nx.Graph()
        
        # Add nodes and edges from recent attacks
        recent_attacks = self.attacks_data[-50:]
        for attack in recent_attacks:
            src = attack[3].split()[0]  # Extract IP from source
            dst = attack[4]
            G.add_edge(src, dst)
            
            # Add node attributes
            G.nodes[src]['type'] = 'source'
            G.nodes[dst]['type'] = 'target'
        
        # Clear and redraw the network map
        self.network_fig.clear()
        ax = self.network_fig.add_subplot(111)
        
        # Calculate layout
        pos = nx.spring_layout(G, k=1, iterations=50)
        
        # Draw nodes with different colors for sources and targets
        node_colors = ['red' if G.nodes[node].get('type') == 'source' else 'blue' 
                      for node in G.nodes()]
        
        nx.draw(G, pos, ax=ax, 
                with_labels=True,
                node_color=node_colors,
                node_size=500,
                font_size=8,
                font_weight='bold',
                edge_color='gray',
                alpha=0.7)
        
        ax.set_title('Recent Attack Network Map')
        self.network_canvas.draw()

    def export_report(self):
        """Export detailed security report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.html"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self._generate_report_html())
            
            logging.info(f"Report exported successfully: {filename}")
            tk.messagebox.showinfo(
                "Export Successful",
                f"Report has been exported to:\n{filename}"
            )
        except Exception as e:
            logging.error(f"Error exporting report: {str(e)}")
            tk.messagebox.showerror(
                "Export Error",
                "Failed to export report. Check logs for details."
            )

    def _generate_report_html(self) -> str:
        """Generate HTML content for the security report."""
        attack_summary = self._generate_attack_summary()
        
        return f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Network Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f5f5f5; }}
                .critical {{ color: darkred; font-weight: bold; }}
                .high {{ color: red; }}
                .medium {{ color: orange; }}
                .low {{ color: green; }}
                .stats {{ margin: 20px 0; padding: 15px; background-color: #f9f9f9; }}
                .summary {{ margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1>Network Security Report</h1>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="stats">
                <h2>Monitoring Statistics</h2>
                <p>Total Packets Monitored: {self.packet_counter:,}</p>
                <p>Total Attacks Detected: {len(self.attacks_data):,}</p>
                <p>Detection Rate: {(len(self.attacks_data) / max(1, self.packet_counter) * 100):.2f}%</p>
            </div>
            
            <div class="summary">
                <h2>Attack Summary</h2>
                {attack_summary}
            </div>
            
            <h2>Recent Attacks</h2>
            {self._generate_attacks_table()}
        </body>
        </html>
        """

    def _generate_attack_summary(self) -> str:
        """Generate summary of attack statistics."""
        attack_types = {}
        severities = {}
        
        for attack in self.attacks_data:
            attack_type = attack[1]
            severity = attack[2]
            
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1
        
        summary = "<h3>Attack Types</h3><ul>"
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            summary += f"<li>{attack_type}: {count:,} attacks</li>"
        
        summary += "</ul><h3>Severity Distribution</h3><ul>"
        for severity, count in sorted(severities.items(), key=lambda x: self.threat_levels.get(x[0], 0), reverse=True):
            summary += f"<li>{severity}: {count:,} attacks</li>"
        
        return summary + "</ul>"

    def _generate_attacks_table(self) -> str:
        """Generate HTML table of recent attacks."""
        table = """
        <table>
            <tr>
                <th>Time</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Target</th>
                <th>Details</th>
            </tr>
        """
        
        for attack in reversed(self.attacks_data[-100:]):  # Show last 100 attacks
            severity_class = {
                'Critical': 'critical',
                'High': 'high',
                'Medium': 'medium',
                'Low': 'low'
            }.get(attack[2], '')
            
            table += f"""
            <tr>
                <td>{attack[0]}</td>
                <td>{attack[1]}</td>
                <td class="{severity_class}">{attack[2]}</td>
                <td>{attack[3]}</td>
                <td>{attack[4]}</td>
                <td>{attack[5]}</td>
            </tr>
            """
        
        return table + "</table>"

    def filter_table(self, *args):
        """Filter table based on search criteria."""
        search_term = self.search_var.get().lower()
        severity_filter = self.severity_var.get()
        attack_type_filter = self.attack_type_var.get()
        
        filtered_data = []
        for row in self.attacks_data:
            if (
                (severity_filter == "All" or severity_filter == row[2]) and
                (attack_type_filter == "All" or attack_type_filter == row[1]) and
                any(search_term in str(cell).lower() for cell in row)
            ):
                filtered_data.append(row)
        
        self.table.delete_rows()
        for row in filtered_data:
            self.table.insert_row('end', row)
def main():
    """Main application entry point."""
    try:
        root = tk.Tk()
        app = AdvancedNetworkMonitor(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Application failed to start: {str(e)}")
        raise

if __name__ == "__main__":
    main()