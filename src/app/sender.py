import time
import sys
import xxhash
import datetime
import threading
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, Future
from collections import deque
from typing import Tuple, Deque, Optional
from src.app.transfer.tcp_transport import TcpTransport
from src.app.key_fetcher import KeyFetcher
from src.app.file_utils import split_file_and_hash_xxh
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers


# --- Configuration ---
@dataclass
class TransferConfig:
    chunk_size: int = 1024 * 1024 * 4
    key_rotation_limit: int = 1024 * 1024 * 2
    pipeline_depth: int = 64
    max_workers: int = 12
    receiver_buffer: int = 100


# --- Metrics ---
class PipelineMetrics:
    """Thread-safe metrics tracker for the pipeline stages."""

    def __init__(self):
        self._lock = threading.Lock()
        self.read_times = []
        self.enc_times = []
        self.net_times = []

    def record(self, r_time: float, e_time: float, n_time: float):
        with self._lock:
            self.read_times.append(r_time)
            self.enc_times.append(e_time)
            self.net_times.append(n_time)

    def get_and_reset_averages(self) -> Tuple[float, float, float]:
        with self._lock:
            if not self.read_times:
                return 0.0, 0.0, 0.0

            avg = lambda x: sum(x) / len(x)
            avgs = (avg(self.read_times), avg(self.enc_times), avg(self.net_times))

            self.read_times.clear()
            self.enc_times.clear()
            self.net_times.clear()
            return avgs


# --- Task Helper ---
def encrypt_chunk_task(chunk: dict, key_data: dict) -> Tuple[bytes, int, float]:
    """Pure function for ThreadPool to execute encryption."""
    start = time.time()
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
    duration = time.time() - start

    packet = create_data_packet(
        chunk["id"],
        key_data["blockId"],
        key_data["index"],
        encrypted_payload
    )
    return packet, chunk["size"], duration


# --- Main Controller ---
class FileTransferClient:
    def __init__(self, receiver_id: str, dest_ip: str, dest_port: int, config: TransferConfig):
        self.config = config
        self.receiver_id = receiver_id
        self.dest_ip = dest_ip
        self.dest_port = dest_port

        # State
        self.transport = TcpTransport(is_server=False)
        self.metrics = PipelineMetrics()
        self.hasher = xxhash.xxh3_64()

        # Sliding Window: Stores tuples of (Future, read_duration)
        self.pending_futures: Deque[Tuple[Future, float]] = deque()
        self.total_bytes = 0

    def _log(self, msg: str):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {msg}")

    def connect(self) -> bool:
        if not self.transport.connect(self.dest_ip, self.dest_port):
            self._log(f"Error: Could not connect to {self.dest_ip}:{self.dest_port}")
            return False
        return True

    def _process_completed_task(self):
        """
        Pops the oldest task from the window, waits for it to finish,
        sends the data, and records metrics.
        """
        oldest_future, read_duration = self.pending_futures.popleft()

        # Block until encryption is ready (Flow Control)
        packet, _, enc_duration = oldest_future.result()

        # Send Packet
        net_start = time.time()
        self.transport.send_reliable(packet)
        net_duration = time.time() - net_start

        self.metrics.record(read_duration, enc_duration, net_duration)

    def _wait_for_ack(self):
        """Waits for final verification from receiver."""
        self._log("Waiting for Receiver Verification (ACK)...")
        try:
            ack_data = self.transport.receive_packet()
            if ack_data:
                headers, _ = decode_packet_with_headers(ack_data)
                if headers.get("type") == "ACK":
                    self._log(f"[Receiver Reply] {headers.get('status')} | {headers.get('message')}")
        except Exception as e:
            self._log(f"Error reading ACK: {e}")

    def send_file(self, file_path: str):
        self._log(f"Starting Transfer: {file_path}")
        start_time = time.time()

        fetcher = KeyFetcher(self.receiver_id, buffer_size=self.config.receiver_buffer)

        try:
            current_key = fetcher.get_next_key()
            bytes_on_key = 0
            last_chunk_ts = time.time()

            #
            # We use a ThreadPool to handle encryption in parallel while
            # maintaining a sliding window of futures to preserve packet order.

            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:

                # --- Producer Phase ---
                chunks = split_file_and_hash_xxh(file_path, self.config.chunk_size, self.hasher)

                for chunk in chunks:
                    # 1. Calculate Read Overhead
                    read_dur = time.time() - last_chunk_ts

                    # 2. Key Rotation
                    if bytes_on_key >= self.config.key_rotation_limit:
                        current_key = fetcher.get_next_key()
                        bytes_on_key = 0

                    # 3. Submit Task
                    future = executor.submit(encrypt_chunk_task, chunk, current_key)
                    self.pending_futures.append((future, read_dur))

                    # 4. Maintain Window (Flow Control)
                    if len(self.pending_futures) >= self.config.pipeline_depth:
                        self._process_completed_task()

                    # 5. Update State
                    bytes_on_key += chunk["size"]
                    self.total_bytes += chunk["size"]
                    last_chunk_ts = time.time()

                    # 6. Logging
                    if chunk["id"] % 50 == 0:
                        r, e, n = self.metrics.get_and_reset_averages()
                        mb = self.total_bytes / 1024 / 1024
                        self._log(f"Progress: {mb:.1f}MB | Avg Read:{r:.4f}s Enc:{e:.4f}s Net:{n:.4f}s")

                # --- Flush Phase ---
                self._log("Flushing remaining tasks...")
                while self.pending_futures:
                    self._process_completed_task()

            # --- Finalization ---
            final_hash = self.hasher.hexdigest()
            self._log(f"Final xxHash: {final_hash}")
            self.transport.send_reliable(create_termination_packet(final_hash))

            duration = time.time() - start_time
            speed = (self.total_bytes / 1024 / 1024) / max(duration, 0.001)
            self._log(f"Transfer complete: {speed:.2f} MB/s")

            self._wait_for_ack()

        except Exception as e:
            self._log(f"Critical Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            fetcher.stop()
            self.transport.close()


# --- Entry Point ---
if __name__ == "__main__":
    host_arg = sys.argv[1] if len(sys.argv) > 1 else "bob"
    target_ip, target_port, peer_id = resolve_host(host_arg)

    config = TransferConfig()
    client = FileTransferClient(peer_id, target_ip, target_port, config)

    if client.connect():
        client.send_file("data/patient_records.txt")