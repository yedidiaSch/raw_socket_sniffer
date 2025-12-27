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

def decode_tcp_flags(flags_int):
    if not flags_int: return ""
    flags = []
    if flags_int & 0x02: flags.append("SYN")
    if flags_int & 0x10: flags.append("ACK")
    if flags_int & 0x01: flags.append("FIN")
    if flags_int & 0x04: flags.append("RST")
    if flags_int & 0x08: flags.append("PSH")
    if flags_int & 0x20: flags.append("URG")
    return ",".join(flags)

def create_layout():
    """
    Defines the TUI (Text User Interface) layout.
    Split: Header (Top), Main (Center), Footer (Bottom).
    Main is split into: Packets (Left), Stats (Right).
    """
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=3)
    )
    
    # Split the main section
    layout["main"].split_row(
        Layout(name="packets", ratio=2),
        Layout(name="stats", ratio=1)
    )
    
    # Static content for Header and Footer
    layout["header"].update(Panel(Text("🚀 Advanced C-Sniffer Analytics", justify="center", style="bold white"), style="bold blue"))
    layout["footer"].update(Panel(Text("Running on Localhost:5005 | Press Ctrl+C to Exit", justify="center", style="dim")))
    
    return layout

def render_packet_table(packet_history):
    """Generates the Rich Table object for the live packet stream."""
    table = Table(box=box.SIMPLE_HEAD, expand=True, title="📡 Live Traffic")
    
    # Define Columns
    table.add_column("Time", style="dim", width=8)
    table.add_column("Proto", justify="center", width=6)
    table.add_column("Source IP", style="cyan")
    table.add_column("Dest IP", style="magenta")
    table.add_column("Preview", style="green")
    table.add_column("Size", justify="right")

    for pkt in packet_history:
        # Determine protocol color style
        proto_style = "white"
        if pkt['type'] == "TCP": proto_style = "bold blue"
        elif pkt['type'] == "UDP": proto_style = "bold orange3"
        elif pkt['type'] == "ARP": proto_style = "bold yellow"
        elif pkt['type'] == "IPv6": proto_style = "bold purple"

        # Format info column (Payload snippet or Ports)
        info = ""
        if pkt['type'] == "TCP":
            s_port = get_service_name(pkt.get('src_port', 0))
            d_port = get_service_name(pkt.get('dest_port', 0))
            flags = decode_tcp_flags(pkt.get('tcp_flags', 0))
            info = f"{s_port} → {d_port} [{flags}]"
        elif pkt['type'] == "UDP":
            s_port = get_service_name(pkt.get('src_port', 0))
            d_port = get_service_name(pkt.get('dest_port', 0))
            info = f"{s_port} → {d_port}"
        else:
             info = pkt.get('payload_hex', '')[:16]

        table.add_row(
            pkt['timestamp'],
            Text(pkt['type'], style=proto_style),
            pkt['src_ip'],
            pkt['dest_ip'],
            info,
            str(pkt['size'])
        )
    return table

def render_stats_panel(top_talkers, protocols, total_bytes):
    """Generates the Side Panel with statistics."""
    text = Text()
    
    # Section 1: Top Talkers
    text.append("🏆 Top Talkers\n", style="bold underline gold1")
    for ip, count in top_talkers:
        text.append(f"{ip:<15} : {count}\n", style="cyan")

    # Section 2: Protocol Breakdown
    text.append("\n📊 Protocols\n", style="bold underline green")
    for proto, count in protocols:
        text.append(f"{proto:<10} : {count}\n")
        
    # Section 3: Total Bandwidth
    text.append(f"\n📦 Total: {total_bytes / 1024:.2f} KB", style="bold white on blue")
    
    return Panel(text, title="Network Stats", border_style="red")