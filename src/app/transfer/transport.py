import enet
import time


def encode_packet_with_headers(headers: dict, data: bytes) -> bytes:
    """
    Encodes metadata as headers followed by data.
    Format: "key1:value1|key2:value2|key3:value3\n<data>"
    """
    header_parts = [f"{k}:{v}" for k, v in headers.items()]
    header_str = "|".join(header_parts) + "\n"
    return header_str.encode('utf-8') + data


def decode_packet_with_headers(packet_data: bytes) -> tuple[dict, bytes]:
    """
    Decodes packet with headers.
    Returns: (headers_dict, data_bytes)
    """
    # Find the newline separator
    try:
        header_end = packet_data.index(b'\n')
        header_bytes = packet_data[:header_end]
        data_bytes = packet_data[header_end + 1:]
        
        # Parse headers
        header_str = header_bytes.decode('utf-8')
        headers = {}
        for part in header_str.split('|'):
            if ':' in part:
                key, value = part.split(':', 1)
                # Convert string values to appropriate types
                if value.lower() == 'true':
                    headers[key] = True
                elif value.lower() == 'false':
                    headers[key] = False
                elif value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
                    headers[key] = int(value)
                else:
                    headers[key] = value
        
        return headers, data_bytes
    except (ValueError, IndexError) as e:
        raise ValueError(f"Invalid packet format: {e}")


class Transport:
    def __init__(self, is_server=False, ip='0.0.0.0', port=0):
        self.is_server = is_server

        if is_server:
            # FIX: pyenet requires the IP to be bytes, not a string.
            # We encode it to utf-8 if it is a string.
            ip_bytes = ip.encode('utf-8') if isinstance(ip, str) else ip
            addr = enet.Address(ip_bytes, port)
        else:
            addr = None

        # Host: 10 peers, 2 channels (0: Reliable, 1: Unreliable)
        # bind to the address if server, otherwise None allows outgoing connections
        self.host = enet.Host(addr, 10, 2, 0)
        self.peer = None
        print(f"[{'SERVER' if is_server else 'CLIENT'}] Transport initialized.")

    def connect(self, dest_ip, dest_port):
        print(f"Connecting to {dest_ip}:{dest_port}...")

        # FIX: Encode the destination IP to bytes as well
        dest_ip_bytes = dest_ip.encode('utf-8') if isinstance(dest_ip, str) else dest_ip

        self.peer = self.host.connect(enet.Address(dest_ip_bytes, dest_port), 2)

        # Block until connection succeeds or times out (5s)
        start = time.time()
        while time.time() - start < 5.0:
            event = self.host.service(100)
            if event.type == enet.EVENT_TYPE_CONNECT:
                print("Connected!")
                return True
        return False

    def send_reliable(self, data: bytes):
        if not self.peer:
            raise ConnectionError("No peer connected")
        packet = enet.Packet(data, enet.PACKET_FLAG_RELIABLE)
        self.peer.send(0, packet)

    def service(self, timeout=0):
        return self.host.service(timeout)

    def flush(self):
        self.host.flush()