import time
import sys
import xxhash
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

from src.app.transfer.tcp_transport import TcpTransport
from src.app.key_fetcher import KeyFetcher
from src.app.file_utils import split_file_and_hash_xxh
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers

# CONFIGURATION FOR 1Gbps PIPELINE
CHUNK_SIZE = 1024 * 1024 * 1
KEY_ROTATION_LIMIT = 1024 * 1024 * 500
MAX_PIPELINE_DEPTH = 32


class PipelineMetrics:
    """Synchronized metrics collector for multithreaded pipelines."""

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
            # Clear for next window
            self.read_times, self.enc_times, self.net_times = [], [], []
            return avg_r, avg_e, avg_n


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    transport = TcpTransport(is_server=False)
    if not transport.connect(destination_ip, destination_port):
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    fetcher = KeyFetcher(receiver_id, buffer_size=200)
    xxh_hasher = xxhash.xxh3_64()
    metrics = PipelineMetrics()

    def log_event(msg):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {msg}")

    log_event(f"Starting 1Gbps Pipelined Transfer for {file_path}...")

    encryption_queue = Queue(maxsize=MAX_PIPELINE_DEPTH)
    network_queue = Queue(maxsize=MAX_PIPELINE_DEPTH)
    start_time = time.time()
    total_bytes = 0

    def encryption_worker():
        while True:
            item = encryption_queue.get()
            if item is None:
                network_queue.put(None)
                break

            chunk, key_data, r_dur = item
            e_start = time.time()
            encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
            e_duration = time.time() - e_start

            packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload)
            network_queue.put((packet, r_dur, e_duration))
            encryption_queue.task_done()

    def network_worker():
        while True:
            item = network_queue.get()
            if item is None: break
            packet, r_dur, e_dur = item

            n_start = time.time()
            transport.send_reliable(packet)
            n_duration = time.time() - n_start

            metrics.report(r_dur, e_dur, n_duration)
            network_queue.task_done()

    executor = ThreadPoolExecutor(max_workers=5)
    for _ in range(4): executor.submit(encryption_worker)
    executor.submit(network_worker)

    try:
        log_event("Fetching initial key...")
        current_key_data = fetcher.get_next_key()
        log_event(f"Initial key acquired (Index: {current_key_data['index']})")

        bytes_sent_with_current_key = 0
        last_chunk_time = time.time()

        for chunk in split_file_and_hash_xxh(file_path, CHUNK_SIZE, xxh_hasher):
            r_duration = time.time() - last_chunk_time

            if bytes_sent_with_current_key >= KEY_ROTATION_LIMIT:
                current_key_data = fetcher.get_next_key()
                bytes_sent_with_current_key = 0

            encryption_queue.put((chunk, current_key_data, r_duration))
            bytes_sent_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            if chunk["id"] % 100 == 0:
                avg_r, avg_e, avg_n = metrics.get_averages()
                log_event(
                    f"Progress: {total_bytes / 1024 / 1024:.1f}MB | Avg Read/Hash: {avg_r:.4f}s | Avg Enc: {avg_e:.4f}s | Avg Net: {avg_n:.4f}s")

            last_chunk_time = time.time()

        for _ in range(4): encryption_queue.put(None)

    except Exception as e:
        log_event(f"Critical Error: {e}")
    finally:
        executor.shutdown(wait=True)
        fetcher.stop()

    final_hash = xxh_hasher.hexdigest()
    log_event(f"Final File xxHash: {final_hash}")
    transport.send_reliable(create_termination_packet(final_hash))

    duration = time.time() - start_time
    mb_sec = (total_bytes / 1024 / 1024) / (duration if duration > 0 else 0.001)
    log_event(f"Transfer complete: {mb_sec:.2f} MB/s")
    transport.close()


if __name__ == "__main__":
    target_ip, target_port, peer_site_id = resolve_host(sys.argv[1] if len(sys.argv) > 1 else "bob")
    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")