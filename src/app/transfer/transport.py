import enet
import time


class Transport:
    def __init__(self, is_server=False, ip='0.0.0.0', port=0):
        self.is_server = is_server
        addr = enet.Address(ip, port) if is_server else None

        # Host: 10 peers, 2 channels (0: Reliable, 1: Unreliable)
        self.host = enet.Host(addr, 10, 2, 0)
        self.peer = None
        print(f"[{'SERVER' if is_server else 'CLIENT'}] Transport initialized.")

    def connect(self, dest_ip, dest_port):
        print(f"Connecting to {dest_ip}:{dest_port}...")
        self.peer = self.host.connect(enet.Address(dest_ip, dest_port), 2)

        # Block until connection succeeds or times out (5s)
        start = time.time()
        while time.time() - start < 5.0:
            event = self.host.service(100)
            if event.type == enet.EVENT_TYPE_CONNECT:
                print("Connected!")
                return True
        return False

    def send_reliable(self, data: bytes):
        if not self.peer: raise ConnectionError("No peer connected")
        packet = enet.Packet(data, enet.PACKET_FLAG_RELIABLE)
        self.peer.send(0, packet)

    def service(self, timeout=0):
        return self.host.service(timeout)

    def flush(self):
        self.host.flush()