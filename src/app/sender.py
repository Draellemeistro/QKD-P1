import time
import sys
import xxhash
import datetime
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

from src.app.transfer.tcp_transport import TcpTransport
from src.app.key_fetcher import KeyFetcher
from src.app.file_utils import split_file_and_hash_xxh
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet

# CONFIGURATION FOR 1Gbps
CHUNK_SIZE = 1024 * 1024 * 1  # 1MB chunks keep the pipeline smoother at high speeds
KEY_ROTATION_LIMIT = 1024 * 1024 * 500  # Rotate every 500MB to reduce overhead
MAX_PIPELINE_DEPTH = 16  # Number of chunks allowed in flight


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    transport = TcpTransport(is_server=False)
    if not transport.connect(destination_ip, destination_port):
        return

    # Increase buffer to 200 to survive KMS jitter at 125MB/s
    fetcher = KeyFetcher(receiver_id, buffer_size=200)
    xxh_hasher = xxhash.xxh3_64()

    def log_event(msg):
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}")

    log_event(f"Starting 1Gbps Pipeline for {file_path}...")

    encryption_queue = Queue(maxsize=MAX_PIPELINE_DEPTH)
    network_queue = Queue(maxsize=MAX_PIPELINE_DEPTH)

    current_key_data = fetcher.get_next_key()
    bytes_with_key = 0
    total_bytes = 0
    start_time = time.time()

    # Worker: Encryption
    def encryption_worker():
        while True:
            item = encryption_queue.get()
            if item is None: break
            chunk, key = item
            enc_data = encryption.encrypt_AES256(chunk["data"], key["hexKey"])
            packet = create_data_packet(chunk["id"], key["blockId"], key["index"], enc_data)
            network_queue.put(packet)
            encryption_queue.task_done()

    # Worker: Network Sender
    def network_worker():
        while True:
            packet = network_queue.get()
            if packet is None: break
            transport.send_reliable(packet)
            network_queue.task_done()

    # Start Threads
    enc_thread = ThreadPoolExecutor(max_workers=4)  # Multiple threads for AES math
    net_thread = ThreadPoolExecutor(max_workers=1)
    enc_thread.submit(encryption_worker)
    net_thread.submit(network_worker)

    try:
        # Producer: Disk Read & Hash
        for chunk in split_file_and_hash_xxh(file_path, CHUNK_SIZE, xxh_hasher):
            if bytes_with_key >= KEY_ROTATION_LIMIT:
                current_key_data = fetcher.get_next_key()
                bytes_with_key = 0

            encryption_queue.put((chunk, current_key_data))
            bytes_with_key += chunk["size"]
            total_bytes += chunk["size"]

            if chunk["id"] % 100 == 0:
                log_event(f"Pipelined {total_bytes / 1024 / 1024:.2f} MB...")

    finally:
        # Drain Pipeline
        encryption_queue.put(None)
        enc_thread.shutdown(wait=True)
        network_queue.put(None)
        net_thread.shutdown(wait=True)
        fetcher.stop()

    # Finalize
    final_hash = xxh_hasher.hexdigest()
    transport.send_reliable(create_termination_packet(final_hash))

    duration = time.time() - start_time
    mb_sec = (total_bytes / 1024 / 1024) / duration
    log_event(f"Transfer complete: {mb_sec:.2f} MB/s")
    transport.close()