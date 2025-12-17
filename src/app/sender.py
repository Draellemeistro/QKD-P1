import time
import sys
import requests
import enet  # REQUIRED: To use EVENT_TYPE_RECEIVE
from src.app.kms_api import new_key
from src.app.transfer.transport import Transport
from src.app.file_utils import split_file_into_chunks, hash_file
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
# UPDATE 1: Import decode helper to read the ACK
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers
# NEW IMPORT: The background key manager
from src.app.key_fetcher import KeyFetcher

# --- CONFIGURATION (OPTIMIZED FOR 1 GBPS) ---
# Increased chunk size reduces Python CPU overhead per packet
CHUNK_SIZE = 1024 * 1024 * 1  # 1 MB

# Rotate every 10 MB.
# This is small enough to be secure, but large enough to hide the 15ms latency
# when using the KeyFetcher (Prefetcher).
KEY_ROTATION_LIMIT = 1024 * 1024 * 10


def establish_connection(ip, port):
    transport = Transport(is_server=False)
    if transport.connect(ip, port):
        return transport
    return None


def send_chunk_packet(transport, chunk, key_data):
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
    packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload)
    transport.send_reliable(packet)


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    # 1. Setup Network
    transport = establish_connection(destination_ip, destination_port)
    if not transport:
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    print(f"Calculating hash for {file_path}...")
    file_hash = hash_file(file_path)
    print(f"File Hash (SHA-256): {file_hash}")

    # 2. Setup Key Fetcher (The "KME" Client Buffer)
    # Starts a background thread immediately to fill the buffer.
    fetcher = KeyFetcher(receiver_id)

    print(f"Starting transfer of {file_path}...")
    print(f"Policy: Rotation at {KEY_ROTATION_LIMIT / 1024 / 1024:.1f} MB intervals")

    current_key_data = None
    bytes_encrypted_with_current_key = 0
    total_bytes = 0
    start_time = time.time()

    try:
        # Get the first key immediately.
        # If the buffer is empty (start of run), this might block for ~15ms once.
        current_key_data = fetcher.get_next_key()

        # 3. Streaming Loop
        for chunk in split_file_into_chunks(file_path, CHUNK_SIZE):

            # --- KEY ROTATION LOGIC ---
            # We simply check if we exceeded our data limit for this key.
            if bytes_encrypted_with_current_key >= KEY_ROTATION_LIMIT:
                # Fetch new key.
                # Thanks to KeyFetcher, this is INSTANT (0ms) 99% of the time.
                # It only blocks if the Proxy (Physics) is actually throttling us.
                current_key_data = fetcher.get_next_key()
                bytes_encrypted_with_current_key = 0

            # --- SENDING LOGIC ---
            send_chunk_packet(transport, chunk, current_key_data)
            transport.service(0)

            # State Update
            bytes_encrypted_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            if chunk["id"] % 5 == 0:
                print(f"Sent chunk {chunk['id']}...", end='\r')

    except Exception as e:
        print(f"\nCritical Error during transmission: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # ALWAYS clean up the background thread
        fetcher.stop()

    # 4. Termination & ACK
    print("\nSending termination signal...")
    end_packet = create_termination_packet(file_hash)
    transport.send_reliable(end_packet)
    transport.flush()

    duration = time.time() - start_time
    # Avoid div by zero if too fast
    if duration == 0: duration = 0.001

    mb_sec = (total_bytes / 1024 / 1024) / duration
    print(f"Transfer complete. {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s ({mb_sec:.2f} MB/s)")

    # --- ACK WAITING ---
    print("\n[Protocol] Waiting for Receiver Confirmation (ACK)...")
    ack_received = False
    start_wait = time.time()

    while time.time() - start_wait < 60:
        event = transport.service(100)
        if event.type == enet.EVENT_TYPE_RECEIVE:
            try:
                headers, _ = decode_packet_with_headers(event.packet.data)
                if headers.get("type") == "ACK":
                    status = headers.get("status", "UNKNOWN")
                    message = headers.get("message", "")
                    print(f"\n[Server Reply] Status: {status} - {message}")
                    if status == "OK":
                        ack_received = True
                        break
            except Exception as e:
                print(f"Ignored unexpected packet: {e}")

    if not ack_received:
        print("\n[Warning] Timed out waiting for ACK.")
    else:
        print("Transfer successfully confirmed by Receiver.")

    print("Sender exiting.")
    transport.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_name = sys.argv[1]
    else:
        target_name = "bob"

    target_ip, target_port, peer_site_id = resolve_host(target_name)

    print(f"Resolved '{target_name}':")
    print(f"IP: {target_ip}")
    print(f"Site ID: {peer_site_id}")

    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")