import socket
import json
from collections import Counter, deque
from datetime import datetime

class PacketListener:
    """
    Listens for UDP connection from C Sniffer and processes data.
    """
    def __init__(self, ip="127.0.0.1", port=5005, history_size=25):
        # Create socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.sock.setblocking(False) # Prevent interface blocking
        
        # Data structures
        self.history = deque(maxlen=history_size) # Keep only last 25
        self.ip_counter = Counter()               # Count addresses (IP or MAC)
        self.protocol_counter = Counter()         # Count protocols
        self.total_bytes = 0

    def fetch_packets(self):
        """Reads all packets accumulated in buffer"""
        while True:
            try:
                data, _ = self.sock.recvfrom(4096)
                packet = json.loads(data.decode('utf-8'))
                
                # Add local time for display
                packet['timestamp'] = datetime.now().strftime("%H:%M:%S")
                
                self._update_stats(packet)
                
            except BlockingIOError:
                break # No more data at the moment
            except json.JSONDecodeError as e:
                print(f"[ERROR] JSON decode failed: {e}")
                print(f"[ERROR] Raw data: {data[:200]}")
                continue
            except Exception as e:
                print(f"[ERROR] Unexpected error: {e}")
                continue

    def _update_stats(self, packet):
        self.history.append(packet)
        self.total_bytes += packet.get('size', 0)
        
        # Identify protocol type for statistics
        # If WiFi, use subtype (e.g. BEACON), otherwise type (e.g. TCP)
        p_type = packet.get('subtype') if packet.get('type') == '802.11' else packet.get('type')
        if not p_type: p_type = "Unknown"
        self.protocol_counter[p_type] += 1
        
        # Count source (MAC for WiFi, IP for Ethernet)
        src = packet.get('src_mac') if packet.get('type') == '802.11' else packet.get('src_ip')
        
        if src and src != "N/A":
            self.ip_counter[src] += 1

    # --- Getters ---
    def get_history(self):
        return self.history

    def get_top_talkers(self, n=10):
        return self.ip_counter.most_common(n)

    def get_protocol_stats(self):
        return self.protocol_counter.most_common()

    def get_total_traffic(self):
        return self.total_bytes