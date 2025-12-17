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
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers

# CONFIGURATION FOR 1Gbps PIPELINE
CHUNK_SIZE = 1024 * 1024 * 1  # 1MB chunks provide smoother pipeline flow at high speeds
KEY_ROTATION_LIMIT = 1024 * 1024 * 500  # Rotate every 500MB to minimize management overhead
MAX_PIPELINE_DEPTH = 32  # Number of chunks allowed to be in-flight in memory


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    transport = TcpTransport(is_server=False)
    if not transport.connect(destination_ip, destination_port):
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    # Increased buffer size to 200 to protect against KMS network jitter at 125MB/s
    fetcher = KeyFetcher(receiver_id, buffer_size=200)
    xxh_hasher = xxhash.xxh3_64()

    def log_event(msg):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {msg}")

    log_event(f"Starting 1Gbps Pipelined Transfer for {file_path}...")

    # Queues to pass data between pipeline stages
    encryption_queue = Queue(maxsize=MAX_PIPELINE_DEPTH)
    network_queue = Queue(maxsize=MAX_PIPELINE_DEPTH)

    start_time = time.time()
    total_bytes = 0

    # PIPELINE STAGE 2: Encryption Workers (CPU Bound)
    def encryption_worker():
        while True:
            item = encryption_queue.get()
            if item is None:  # Termination signal
                network_queue.put(None)
                break

            chunk, key_data = item
            # AES-GCM Encryption
            encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
            # Create Protocol Packet
            packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload)

            network_queue.put(packet)
            encryption_queue.task_done()

    # PIPELINE STAGE 3: Network Sender (I/O Bound)
    def network_worker():
        while True:
            packet = network_queue.get()
            if packet is None:  # Termination signal
                break
            transport.send_reliable(packet)
            network_queue.task_done()

    # Launch Pipeline Background Threads
    # We use 4 threads for encryption to utilize multiple CPU cores
    executor = ThreadPoolExecutor(max_workers=5)
    for _ in range(4):
        executor.submit(encryption_worker)
    executor.submit(network_worker)

    try:
        log_event("Fetching initial key...")
        current_key_data = fetcher.get_next_key()
        log_event(f"Initial key acquired (Index: {current_key_data['index']})")

        bytes_sent_with_current_key = 0

        # PIPELINE STAGE 1: Disk Producer (Disk I/O + Fast Hashing)
        for chunk in split_file_and_hash_xxh(file_path, CHUNK_SIZE, xxh_hasher):

            # Key Rotation Logic
            if bytes_sent_with_current_key >= KEY_ROTATION_LIMIT:
                current_key_data = fetcher.get_next_key()
                bytes_sent_with_current_key = 0

            # Push to pipeline
            encryption_queue.put((chunk, current_key_data))

            bytes_sent_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            if chunk["id"] % 100 == 0:
                log_event(f"In-Flight: {total_bytes / 1024 / 1024:.2f} MB processed...")

        # Signal completion to workers
        for _ in range(4):
            encryption_queue.put(None)

    except Exception as e:
        log_event(f"Critical Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        executor.shutdown(wait=True)
        fetcher.stop()

    # Send termination with final fast hash
    final_hash = xxh_hasher.hexdigest()
    log_event(f"Final File xxHash: {final_hash}")
    transport.send_reliable(create_termination_packet(final_hash))

    duration = time.time() - start_time
    mb_sec = (total_bytes / 1024 / 1024) / (duration if duration > 0 else 0.001)
    log_event(f"Transfer complete. {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s ({mb_sec:.2f} MB/s)")

    # Wait for Receiver Verification
    try:
        ack_data = transport.receive_packet()
        if ack_data:
            headers, _ = decode_packet_with_headers(ack_data)
            if headers.get("type") == "ACK":
                log_event(f"[Server Reply] Status: {headers.get('status')}")
    except Exception as e:
        log_event(f"Error reading ACK: {e}")

    transport.close()


if __name__ == "__main__":
    target_ip, target_port, peer_site_id = resolve_host(sys.argv[1] if len(sys.argv) > 1 else "bob")
    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")