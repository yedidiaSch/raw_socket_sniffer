import socket
import json
from collections import Counter, deque
from datetime import datetime

class PacketListener:
    """
    Handles UDP socket listening and statistical aggregation 
    for the network sniffer.
    """
    def __init__(self, ip="127.0.0.1", port=5005, history_size=20):
        # Initialize UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        # Set to non-blocking mode to prevent UI freezes
        self.sock.setblocking(False)
        
        # Data Structures
        self.history = deque(maxlen=history_size) # Rolling buffer for the packet table
        self.ip_counter = Counter()               # Stats for Source IPs
        self.protocol_counter = Counter()         # Stats for Protocols (TCP/UDP/etc.)
        self.total_bytes = 0

    def fetch_packets(self):
        """
        Reads all available packets currently in the socket buffer.
        This enables batch processing for better performance.
        """
        while True:
            try:
                # Receive data (buffer size 4096 to accommodate JSON)
                data, _ = self.sock.recvfrom(4096)
                
                # Parse JSON
                packet = json.loads(data.decode('utf-8'))
                
                # Add local timestamp for display
                packet['timestamp'] = datetime.now().strftime("%H:%M:%S")
                
                self._update_stats(packet)
                
            except BlockingIOError:
                # No more data in the buffer, exit loop
                break 
            except Exception:
                # Ignore malformed packets or JSON errors
                continue

    def _update_stats(self, packet):
        """Internal method to update counters and history."""
        self.history.append(packet)
        self.total_bytes += packet['size']
        self.protocol_counter[packet['type']] += 1
        
        # Count source IPs (ignore N/A or local noise if needed)
        if packet['src_ip'] != "N/A":
            self.ip_counter[packet['src_ip']] += 1

    # --- Getters for the UI ---
    def get_history(self):
        return self.history

    def get_top_talkers(self, n=10):
        return self.ip_counter.most_common(n)

    def get_protocol_stats(self):
        return self.protocol_counter.most_common()

    def get_total_traffic(self):
        return self.total_bytes