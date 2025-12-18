import time
import sys
import xxhash
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import deque  # IMPORTED: For the sliding window

from src.app.transfer.tcp_transport import TcpTransport
from src.app.key_fetcher import KeyFetcher
from src.app.file_utils import split_file_and_hash_xxh
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers

# CONFIGURATION FOR 2GBPS+ PIPELINE
CHUNK_SIZE = 1024 * 1024 * 4
KEY_ROTATION_LIMIT = 1024 * 1024 * 2
MAX_PIPELINE_DEPTH = 64  # Controls memory usage


class PipelineMetrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.read_times = []
        self.enc_times = []
        self.net_times = []

    def report(self, r, e, n):
        with self.lock:
            self.read_times.append(r)
            self.enc_times.append(e)
            self.net_times.append(n)

    def get_averages(self):
        with self.lock:
            if not self.read_times: return 0, 0, 0
            avg_r = sum(self.read_times) / len(self.read_times)
            avg_e = sum(self.enc_times) / len(self.enc_times)
            avg_n = sum(self.net_times) / len(self.net_times)
            self.read_times, self.enc_times, self.net_times = [], [], []
            return avg_r, avg_e, avg_n


def encrypt_chunk_task(chunk, key_data):
    """
    Helper function run by ThreadPoolExecutor.
    Perform encryption and packet creation off the main thread.
    """
    short_key = key_data["hexKey"][:8]
    print(f"[Sender] Chunk {chunk['id']} | Block: {key_data['blockId']} | Index: {key_data['index']} | KeyHex: {short_key}...")
    e_start = time.time()
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
    e_duration = time.time() - e_start

    packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload)
    return packet, chunk["size"], e_duration


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    transport = TcpTransport(is_server=False)
    if not transport.connect(destination_ip, destination_port):
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    fetcher = KeyFetcher(receiver_id, buffer_size=500)
    xxh_hasher = xxhash.xxh3_64()
    metrics = PipelineMetrics()

    def log_event(msg):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {msg}")

    log_event(f"Starting Ordered 2Gbps Transfer for {file_path}...")

    # SLIDING WINDOW STATE
    pending_futures = deque()
    start_time = time.time()
    total_bytes = 0

    try:
        log_event("Fetching initial key...")
        current_key_data = fetcher.get_next_key()
        bytes_sent_with_current_key = 0
        last_chunk_time = time.time()

        # We use a context manager for the pool to ensure clean shutdown
        with ThreadPoolExecutor(max_workers=12) as executor:

            # STAGE 1: PRODUCER LOOP
            for chunk in split_file_and_hash_xxh(file_path, CHUNK_SIZE, xxh_hasher):
                r_duration = time.time() - last_chunk_time

                # Key Rotation Logic
                if bytes_sent_with_current_key >= KEY_ROTATION_LIMIT:
                    current_key_data = fetcher.get_next_key()
                    bytes_sent_with_current_key = 0

                # 1. Submit Encryption Task (Non-blocking)
                future = executor.submit(encrypt_chunk_task, chunk, current_key_data)

                # 2. Add to Sliding Window (Preserves Order)
                # We store the future AND the read_duration for metrics reporting later
                pending_futures.append((future, r_duration))

                # 3. Maintain Window Size (Flow Control)
                if len(pending_futures) >= MAX_PIPELINE_DEPTH:
                    # Retrieve the OLDEST task. This forces us to wait for Chunk N
                    # before sending Chunk N+1, even if N+1 finished encrypting first.
                    oldest_future, r_dur_old = pending_futures.popleft()

                    # BLOCK until this specific chunk is ready
                    packet, size, e_dur = oldest_future.result()

                    # Send Packet (Main thread guarantees sequential network writes)
                    n_start = time.time()
                    transport.send_reliable(packet)
                    n_duration = time.time() - n_start

                    metrics.report(r_dur_old, e_dur, n_duration)

                # Update counters
                bytes_sent_with_current_key += chunk["size"]
                total_bytes += chunk["size"]

                if chunk["id"] % 50 == 0:
                    avg_r, avg_e, avg_n = metrics.get_averages()
                    log_event(
                        f"Progress: {total_bytes / 1024 / 1024:.1f}MB | Avg Read: {avg_r:.4f}s | Avg Enc: {avg_e:.4f}s | Avg Net: {avg_n:.4f}s")

                last_chunk_time = time.time()

            # STAGE 2: FLUSH WINDOW
            log_event("Flushing remaining encryption tasks...")
            while pending_futures:
                oldest_future, r_dur_old = pending_futures.popleft()
                packet, size, e_dur = oldest_future.result()

                n_start = time.time()
                transport.send_reliable(packet)
                n_duration = time.time() - n_start

                metrics.report(r_dur_old, e_dur, n_duration)

    except Exception as e:
        log_event(f"Critical Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        fetcher.stop()

    final_hash = xxh_hasher.hexdigest()
    log_event(f"Final File xxHash: {final_hash}")
    transport.send_reliable(create_termination_packet(final_hash))

    duration = time.time() - start_time
    mb_sec = (total_bytes / 1024 / 1024) / (duration if duration > 0 else 0.001)
    log_event(f"Transfer complete: {mb_sec:.2f} MB/s")

    log_event("Waiting for Receiver Verification (ACK)...")
    try:
        ack_data = transport.receive_packet()
        if ack_data:
            headers, _ = decode_packet_with_headers(ack_data)
            if headers.get("type") == "ACK":
                log_event(f"[Receiver Reply] Status: {headers.get('status')} | Message: {headers.get('message')}")
    except Exception as e:
        log_event(f"Error reading ACK: {e}")

    transport.close()


if __name__ == "__main__":
    target_ip, target_port, peer_site_id = resolve_host(sys.argv[1] if len(sys.argv) > 1 else "bob")
    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")