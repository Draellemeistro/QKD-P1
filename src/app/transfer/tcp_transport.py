import socket
import struct



class TcpTransport:
    def __init__(self, is_server=False, ip='0.0.0.0', port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.conn = None
        self.addr = None
        self.is_server = is_server

        if is_server:
            self.sock.bind((ip, port))
            self.sock.listen(1)
            print(f"[SERVER] Listening on {ip}:{port} (TCP)")
        else:
            print("[CLIENT] TCP Transport initialized.")

    def connect(self, dest_ip, dest_port):
        """Client-side connection logic"""
        try:
            print(f"Connecting to {dest_ip}:{dest_port}...")
            self.sock.connect((dest_ip, dest_port))
            print("Connected!")
            self.conn = self.sock  # Client uses the main socket as connection
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def accept(self):
        """Server-side: blocks until a client connects"""
        if not self.is_server: return None
        conn, addr = self.sock.accept()
        self.conn = conn
        self.addr = addr
        print(f"Client connected from {addr}")
        return conn

    def send_reliable(self, data: bytes):
        """Sends data with a 4-byte length header (Framing)"""
        if not self.conn:
            raise ConnectionError("No connection established")

        # 1. Pack length (4 bytes big-endian)
        length_header = struct.pack('>I', len(data))

        # 2. Send Length + Data
        self.conn.sendall(length_header + data)

    def receive_packet(self):
        """
        Blocks until a full packet is received.
        Returns: bytes of data, or None if connection closed.
        """
        if not self.conn: return None

        try:
            # 1. Read Length Header (4 bytes)
            header = self._recv_exact(4)
            if not header: return None  # Connection closed

            msg_length = struct.unpack('>I', header)[0]

            # 2. Read Payload
            return self._recv_exact(msg_length)
        except ConnectionResetError:
            return None

    def _recv_exact(self, n):
        """Helper to read exactly n bytes from the stream"""
        data = b''
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet: return None
            data += packet
        return data

    def close(self):
        if self.conn: self.conn.close()
        if self.sock: self.sock.close()