from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
import socket

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return str(port)

def create_layout():
    """
    Defines screen structure: Header, Main area (Table + Stats), and Footer.
    """
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=3)
    )
    
    # Internal division of main area
    layout["main"].split_row(
        Layout(name="packets", ratio=2),
        Layout(name="stats", ratio=1)
    )
    
    layout["header"].update(Panel(Text("📡 WiFi & Network Sniffer Dashboard", justify="center", style="bold white"), style="bold blue"))
    layout["footer"].update(Panel(Text("Running on Localhost:5005 | Press Ctrl+C to Exit", justify="center", style="dim")))
    
    return layout

def render_packet_table(packet_history):
    """Generates the real-time updating table"""
    table = Table(box=box.SIMPLE_HEAD, expand=True, title="Live Traffic Stream")
    
    # Define columns
    table.add_column("Time", style="dim", width=8)
    table.add_column("Type", justify="center", width=8)
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="magenta")
    table.add_column("Info / SSID", style="green")
    table.add_column("Signal", justify="right", width=8)

    for pkt in packet_history:
        # Extract basic data
        pkt_type = pkt.get('type', 'UNKNOWN')
        subtype = pkt.get('subtype', '')
        
        # Default
        style = "white"
        type_display = pkt_type
        
        source = "N/A"
        dest = "N/A"
        info = ""
        signal = ""

        # --- WiFi Logic ---
        if pkt_type == "802.11":
            source = pkt.get('src_mac', '')
            dest = pkt.get('dest_mac', '')
            
            # Color and text by WiFi type
            if subtype == "BEACON": 
                type_display = "BEACON"
                style = "bold green"
            elif subtype == "PROBE_REQ": 
                type_display = "PROBE"
                style = "bold yellow"
            elif subtype == "DATA": 
                type_display = "DATA"
                style = "dim white"
            elif ssid == "[HANDSHAKE]":
                type_display = "EAPOL"     # השם המקצועי
                style = "bold red blink"   # אדום מהבהב!
                info = "🔑 KEY EXCHANGE!"
            
            # WiFi parameters (SSID, Channel, Signal)
            ssid = pkt.get('ssid', '')
            chan = pkt.get('channel', 0)
            
            if ssid == "<HIDDEN>":
                info = f"🔒 [Hidden] (Ch:{chan})"
            elif ssid == "[BROADCAST]":
                info = f"📡 [Searching...] (Ch:{chan})"
            else:
                info = f"📶 {ssid} (Ch:{chan})"
            
            # Display signal strength (dBm) with colors
            dbm = pkt.get('signal_dbm', 0)
            if dbm < 0:
                # Green = Good signal, Red = Bad
                sig_color = "green" if dbm > -65 else "yellow" if dbm > -80 else "red"
                signal = Text(f"{dbm} dBm", style=sig_color)
            else:
                signal = "-"

        # --- Standard Ethernet Logic (TCP/UDP) ---
        else:
            if pkt_type == "TCP": style = "bold blue"
            elif pkt_type == "UDP": style = "bold orange3"
            
            source = f"{pkt.get('src_ip')}:{pkt.get('src_port')}"
            dest = f"{pkt.get('dest_ip')}:{pkt.get('dest_port')}"
            info = f"Size: {pkt.get('size')} bytes"
            signal = "Wired"

        # Add row to table
        table.add_row(
            pkt.get('timestamp', ''),
            Text(type_display, style=style),
            source,
            dest,
            info,
            signal
        )
            
    return table

def render_stats_panel(top_talkers, protocols, total_bytes):
    """Generates the statistics panel on the right"""
    text = Text()
    
    # Part 1: Active Sources
    text.append("🏆 Top Sources\n", style="bold underline gold1")
    for src, count in top_talkers:
        # Truncate address if too long
        display_src = src
        if len(src) > 18: display_src = src[:17] + ".."
        text.append(f"{display_src:<18} : {count}\n", style="cyan")

    # Part 2: Protocol Types
    text.append("\n📊 Breakdown\n", style="bold underline green")
    for proto, count in protocols:
        text.append(f"{proto:<10} : {count}\n")
        
    # Part 3: Total Traffic
    text.append(f"\n📦 Total: {total_bytes / 1024:.2f} KB", style="bold white on blue")
    
    return Panel(text, title="Network Stats", border_style="red")