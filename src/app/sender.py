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

# --- CONFIGURATION ---
CHUNK_SIZE = 64 * 1024

# 1. Soft Limit (Preferred Rotation): Try to rotate here (e.g., 1 MB)
KEY_ROTATION_SOFT_LIMIT = 1024 * 1024 * 1

# 2. Hard Limit (Mandatory Rotation): Stop and wait here (e.g., 50 MB)
KEY_ROTATION_HARD_LIMIT = 1024 * 1024 * 50


def establish_connection(ip, port):
    transport = Transport(is_server=False)
    if transport.connect(ip, port):
        return transport
    return None


def fetch_key_blocking(receiver_id):
    """
    Helper: Enters a retry loop until a key is successfully obtained.
    """
    while True:
        try:
            return new_key(receiver_id)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 503:
                print(" [!] Hard Limit / No Key: KMS busy (503). Waiting 1s...")
                time.sleep(1)
                continue
            else:
                raise e


def ensure_valid_key(current_key, bytes_used, soft_limit, hard_limit, receiver_id):
    """
    Adaptive Key Logic with Soft/Hard limits.
    """
    # Case A: No key
    if current_key is None:
        print("Initial key fetch...")
        return fetch_key_blocking(receiver_id)

    # Case B: Check Limits
    if bytes_used >= soft_limit:
        try:
            # Try to rotate (Optimistic)
            return new_key(receiver_id)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 503:
                # 503 Received: The 'Physics' is limiting us.

                # Case C: Check Hard Limit
                if bytes_used >= hard_limit:
                    print(f" [!] HARD LIMIT HIT ({bytes_used} bytes). Blocking for new key...")
                    return fetch_key_blocking(receiver_id)

                else:
                    # Case D: Adapt (Reuse Key)
                    print(f" [i] Rate Limit (503). Extending key life (Used: {bytes_used / 1024:.0f} KB)")
                    return current_key
            else:
                raise e

    # Case E: Below Soft Limit -> Keep going
    return current_key


def send_chunk_packet(transport, chunk, key_data):
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
    packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload)
    transport.send_reliable(packet)


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    # 1. Setup
    transport = establish_connection(destination_ip, destination_port)
    if not transport:
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    print(f"Calculating hash for {file_path}...")
    file_hash = hash_file(file_path)
    print(f"File Hash (SHA-256): {file_hash}")

    current_key_data = None
    bytes_encrypted_with_current_key = 0
    total_bytes = 0
    start_time = time.time()

    print(f"Starting transfer of {file_path}...")
    print(
        f"Policy: Soft Limit={KEY_ROTATION_SOFT_LIMIT / 1024 / 1024:.1f}MB, Hard Limit={KEY_ROTATION_HARD_LIMIT / 1024 / 1024:.1f}MB")

    # 2. Streaming Loop
    for chunk in split_file_into_chunks(file_path, CHUNK_SIZE):
        try:
            # A. Key Management
            old_key_id = current_key_data["index"] if current_key_data else -1

            current_key_data = ensure_valid_key(
                current_key_data,
                bytes_encrypted_with_current_key,
                KEY_ROTATION_SOFT_LIMIT,
                KEY_ROTATION_HARD_LIMIT,
                receiver_id
            )

            # Check if key actually changed
            if current_key_data["index"] != old_key_id:
                bytes_encrypted_with_current_key = 0

            # B. Processing & Sending
            send_chunk_packet(transport, chunk, current_key_data)
            transport.service(0)

            # D. State Update
            bytes_encrypted_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            if chunk["id"] % 10 == 0:
                print(f"Sent chunk {chunk['id']}...", end='\r')

        except Exception as e:
            print(f"\nCritical Error during transmission: {e}")
            import traceback
            traceback.print_exc()
            break

    # 3. Termination
    print("\nSending termination signal...")
    end_packet = create_termination_packet(file_hash)
    transport.send_reliable(end_packet)
    transport.flush()

    duration = time.time() - start_time
    print(f"Transfer complete. {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s")

    # --- UPDATE 2: ROBUSTNESS / ACK WAITING ---
    print("\n[Protocol] Waiting for Receiver Confirmation (ACK)...")

    ack_received = False
    start_wait = time.time()

    # Wait up to 60s for the ACK (keeps ENet alive to resend dropped packets)
    while time.time() - start_wait < 60:
        event = transport.service(100)  # Pump network

        if event.type == enet.EVENT_TYPE_RECEIVE:
            try:
                # We got a reply!
                headers, _ = decode_packet_with_headers(event.packet.data)

                # Check if it is our ACK
                if headers.get("type") == "ACK":
                    status = headers.get("status", "UNKNOWN")
                    message = headers.get("message", "")
                    print(f"\n[Server Reply] Status: {status} - {message}")

                    if status == "OK":
                        ack_received = True
                        break  # Success! Exit loop.
                    else:
                        print("Warning: Receiver reported an error.")
                        break  # Exit, but with failure state.

            except Exception as e:
                print(f"Ignored unexpected packet: {e}")

    if not ack_received:
        print("\n[Warning] Timed out waiting for ACK (Receiver might be slow or dead).")
    else:
        print("Transfer successfully confirmed by Receiver.")

    print("Sender exiting.")


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