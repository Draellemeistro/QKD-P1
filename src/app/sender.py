import time
import sys
import hashlib
import datetime  # Added for timestamps

from src.app.transfer.tcp_transport import TcpTransport
from src.app.key_fetcher import KeyFetcher
from src.app.file_utils import split_file_and_hash
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers

# CONFIGURATION
CHUNK_SIZE = 1024 * 1024 * 4  # Optimized to 4MB based on previous tests
KEY_ROTATION_LIMIT = 1024 * 1024 * 100

def send_chunk_packet(transport, chunk, key_data):
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
    packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload)
    transport.send_reliable(packet)

def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    transport = TcpTransport(is_server=False)
    if not transport.connect(destination_ip, destination_port):
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    fetcher = KeyFetcher(receiver_id)
    sha256_hash = hashlib.sha256()

    # Helper function for timestamped logs
    def log_event(msg):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {msg}")

    log_event(f"Starting transfer (TCP) for {file_path}...")

    current_key_data = None
    bytes_encrypted_with_current_key = 0
    total_bytes = 0
    start_time = time.time()

    try:
        log_event("Fetching initial key...")
        current_key_data = fetcher.get_next_key()
        log_event(f"Initial key acquired (Index: {current_key_data['index']})")

        for chunk in split_file_and_hash(file_path, CHUNK_SIZE, sha256_hash):

            if bytes_encrypted_with_current_key >= KEY_ROTATION_LIMIT:
                log_event("Rotating key...")
                current_key_data = fetcher.get_next_key()
                log_event(f"New key acquired (Index: {current_key_data['index']})")
                bytes_encrypted_with_current_key = 0

            send_chunk_packet(transport, chunk, current_key_data)

            bytes_encrypted_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            # Changed: No longer using '\r', using log_event for separate lines
            if chunk["id"] % 50 == 0:
                log_event(f"Sent chunk {chunk['id']} (Total: {total_bytes / 1024 / 1024:.2f} MB)")

    except Exception as e:
        log_event(f"Critical Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        fetcher.stop()

    final_hash = sha256_hash.hexdigest()
    log_event(f"Final File Hash: {final_hash}")

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