import time
import sys
import xxhash
import datetime

from src.app.transfer.tcp_transport import TcpTransport
from src.app.key_fetcher import KeyFetcher
from src.app.file_utils import split_file_and_hash_xxh
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers

# CONFIGURATION
CHUNK_SIZE = 1024 * 1024 * 4
KEY_ROTATION_LIMIT = 1024 * 1024 * 100


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    transport = TcpTransport(is_server=False)
    if not transport.connect(destination_ip, destination_port):
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    fetcher = KeyFetcher(receiver_id)

    # REPLACED: Use xxHash (64-bit) instead of SHA-256 for high performance
    xxh_hasher = xxhash.xxh3_64()

    def log_event(msg):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {msg}")

    log_event(f"Starting transfer (TCP) with xxHash for {file_path}...")

    current_key_data = None
    bytes_encrypted_with_current_key = 0
    total_bytes = 0
    start_time = time.time()

    try:
        log_event("Fetching initial key...")
        current_key_data = fetcher.get_next_key()
        log_event(f"Initial key acquired (Index: {current_key_data['index']})")

        # Track when the loop starts to measure the very first acquisition
        last_loop_time = time.time()

        # UPDATED: Use the xxhash-specific split utility
        for chunk in split_file_and_hash_xxh(file_path, CHUNK_SIZE, xxh_hasher):
            # 1. Profile Data Acquisition (Disk I/O + Fast Hashing)
            acquisition_time = time.time() - last_loop_time

            if bytes_encrypted_with_current_key >= KEY_ROTATION_LIMIT:
                log_event("Rotating key...")
                current_key_data = fetcher.get_next_key()
                log_event(f"New key acquired (Index: {current_key_data['index']})")
                bytes_encrypted_with_current_key = 0

            # 2. Profile Encryption (AES-GCM)
            enc_start = time.time()
            encrypted_payload = encryption.encrypt_AES256(chunk["data"], current_key_data["hexKey"])
            enc_duration = time.time() - enc_start

            # 3. Profile Network Transmission
            net_start = time.time()
            packet = create_data_packet(chunk["id"], current_key_data["blockId"], current_key_data["index"],
                                        encrypted_payload)
            transport.send_reliable(packet)
            net_duration = time.time() - net_start

            bytes_encrypted_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            # Provide detailed metrics every 50 chunks
            if chunk["id"] % 50 == 0:
                log_event(
                    f"Chunk {chunk['id']} Metrics -> "
                    f"Read/Hash: {acquisition_time:.4f}s | "
                    f"Encrypt: {enc_duration:.4f}s | "
                    f"Network: {net_duration:.4f}s | "
                    f"Total: {total_bytes / 1024 / 1024:.2f} MB"
                )

            # Reset the timer for the next iteration's acquisition
            last_loop_time = time.time()

    except Exception as e:
        log_event(f"Critical Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        fetcher.stop()

    # Get the final 64-bit digest
    final_hash = xxh_hasher.hexdigest()
    log_event(f"Final File xxHash: {final_hash}")

    log_event("Sending termination signal...")
    end_packet = create_termination_packet(final_hash)
    transport.send_reliable(end_packet)

    duration = time.time() - start_time
    mb_sec = (total_bytes / 1024 / 1024) / (duration if duration > 0 else 0.001)
    log_event(f"Transfer complete. {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s ({mb_sec:.2f} MB/s)")

    log_event("Waiting for Receiver Confirmation (ACK)...")
    try:
        ack_data = transport.receive_packet()
        if ack_data:
            headers, _ = decode_packet_with_headers(ack_data)
            if headers.get("type") == "ACK":
                status = headers.get("status", "UNKNOWN")
                log_event(f"[Server Reply] Status: {status}")
                if status == "OK":
                    log_event("Success: Integrity Verified.")
                else:
                    log_event("Failure: Receiver reported error.")
            else:
                log_event(f"Warning: Unexpected packet type {headers.get('type')}")
        else:
            log_event("Error: Connection closed by server before ACK.")
    except Exception as e:
        log_event(f"Error reading ACK: {e}")

    log_event("Sender exiting.")
    transport.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_name = sys.argv[1]
    else:
        target_name = "bob"

    target_ip, target_port, peer_site_id = resolve_host(target_name)
    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")