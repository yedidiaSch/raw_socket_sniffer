from time import sleep
from rich.live import Live

# Import local modules
from data_listener import PacketListener
import ui_renderer

def main():
    # 1. Initialize Business Logic
    listener = PacketListener()
    print("[*] Dashboard initialized. Waiting for packets from C sniffer...")

    # 2. Initialize UI Layout
    layout = ui_renderer.create_layout()
    
    # 3. Main Event Loop
    # refresh_per_second=4 ensures smooth updates without high CPU usage
    with Live(layout, refresh_per_second=4, screen=True):
        while True:
            try:
                # A. Fetch new data from network
                listener.fetch_packets()
                
                # B. Generate updated UI components
                table = ui_renderer.render_packet_table(listener.get_history())
                stats = ui_renderer.render_stats_panel(
                    listener.get_top_talkers(),
                    listener.get_protocol_stats(),
                    listener.get_total_traffic()
                )
                
                # C. Update the Layout
                layout["packets"].update(table)
                layout["stats"].update(stats)
                
                # D. Small sleep to yield CPU
                sleep(0.1)
                
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    main()