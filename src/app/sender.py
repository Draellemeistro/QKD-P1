import time
import sys
import requests

# USE TCP (Standard, Reliable)
from src.app.transfer.tcp_transport import TcpTransport
from src.app.key_fetcher import KeyFetcher
from src.app.file_utils import split_file_into_chunks, hash_file
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers

# --- CONFIGURATION ---
CHUNK_SIZE = 1024 * 1024 * 1  # 1 MB Chunks
KEY_ROTATION_LIMIT = 1024 * 1024 * 10  # 10 MB Rotation


def send_chunk_packet(transport, chunk, key_data):
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
    packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload)
    transport.send_reliable(packet)


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    # 1. Setup TCP Transport
    transport = TcpTransport(is_server=False)
    if not transport.connect(destination_ip, destination_port):
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    # 2. Setup Key Fetcher
    fetcher = KeyFetcher(receiver_id)

    print(f"Calculating hash for {file_path}...")
    file_hash = hash_file(file_path)
    print(f"File Hash (SHA-256): {file_hash}")
    print(f"Starting transfer (TCP)...")

    current_key_data = None
    bytes_encrypted_with_current_key = 0
    total_bytes = 0
    start_time = time.time()

    try:
        # Get first key (Immediate)
        current_key_data = fetcher.get_next_key()

        # 3. Streaming Loop
        for chunk in split_file_into_chunks(file_path, CHUNK_SIZE):

            # Rotation Logic
            if bytes_encrypted_with_current_key >= KEY_ROTATION_LIMIT:
                current_key_data = fetcher.get_next_key()
                bytes_encrypted_with_current_key = 0

            # Encrypt & Send
            send_chunk_packet(transport, chunk, current_key_data)

            # Note: No transport.service() needed for TCP

            bytes_encrypted_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            if chunk["id"] % 5 == 0:
                print(f"Sent chunk {chunk['id']}...", end='\r')

    except Exception as e:
        print(f"\nCritical Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        fetcher.stop()

    # 4. Termination & ACK
    print("\nSending termination signal...")
    end_packet = create_termination_packet(file_hash)
    transport.send_reliable(end_packet)

    duration = time.time() - start_time
    if duration == 0: duration = 0.001
    mb_sec = (total_bytes / 1024 / 1024) / duration
    print(f"Transfer complete. {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s ({mb_sec:.2f} MB/s)")

    # 5. Wait for ACK (TCP Blocking Read)
    print("\n[Protocol] Waiting for Receiver Confirmation (ACK)...")

    try:
        # Blocks until data arrives
        ack_data = transport.receive_packet()

        if ack_data:
            headers, _ = decode_packet_with_headers(ack_data)
            if headers.get("type") == "ACK":
                status = headers.get("status", "UNKNOWN")
                print(f"[Server Reply] Status: {status}")
                if status == "OK":
                    print("Success: Integrity Verified.")
                else:
                    print("Failure: Receiver reported error.")
            else:
                print(f"Warning: Unexpected packet type {headers.get('type')}")
        else:
            print("Error: Connection closed by server before ACK.")

    except Exception as e:
        print(f"Error reading ACK: {e}")

    print("Sender exiting.")
    transport.close()  # Now this works because TcpTransport has .close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_name = sys.argv[1]
    else:
        target_name = "bob"

    target_ip, target_port, peer_site_id = resolve_host(target_name)
    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")