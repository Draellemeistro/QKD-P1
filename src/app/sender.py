import time
import sys
import requests  # REQUIRED: To catch the 503 error
from src.app.kms_api import new_key
from src.app.transfer.transport import Transport
from src.app.file_utils import split_file_into_chunks, hash_file
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet

# --- CONFIGURATION ---
CHUNK_SIZE = 64 * 1024

# 1. Soft Limit (Preferred Rotation): Try to rotate here (e.g., 1 MB)
KEY_ROTATION_SOFT_LIMIT = 1024 * 1024 * 1

# 2. Hard Limit (Mandatory Rotation): Stop and wait here (e.g., 50 MB)
# This prevents a single key from being used indefinitely if the link is down.
KEY_ROTATION_HARD_LIMIT = 1024 * 1024 * 50


def establish_connection(ip, port):
    transport = Transport(is_server=False)
    if transport.connect(ip, port):
        return transport
    return None


def fetch_key_blocking(receiver_id):
    """
    Helper: Enters a retry loop until a key is successfully obtained.
    Used when we hit the Hard Limit or have no key at all.
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
                raise e  # Critical error (e.g., 404, 500) -> Crash


def ensure_valid_key(current_key, bytes_used, soft_limit, hard_limit, receiver_id):
    """
    Adaptive Key Logic:
    1. No Key? -> Block until we get one.
    2. > Hard Limit? -> Block until we get a NEW one.
    3. > Soft Limit? -> Try to get a new one. If 503, reuse current (Adapt).
    """

    # Case A: We have no key at all (Start of transfer)
    if current_key is None:
        print("Initial key fetch...")
        return fetch_key_blocking(receiver_id)

    # Case B: Check Limits
    if bytes_used >= soft_limit:
        try:
            # Try to rotate (Optimistic)
            # print(f"Soft limit hit ({bytes_used} bytes). Requesting new key...")
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
                    # We are in the 'Safety Zone' between Soft and Hard limits.
                    # We print a warning but continue.
                    print(f" [i] Rate Limit (503). Extending key life (Used: {bytes_used / 1024:.0f} KB)")
                    return current_key
            else:
                # Some other error (network down?)
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
        f"Policy: Soft Limit={KEY_ROTATION_SOFT_LIMIT / 1024 / 1024}MB, Hard Limit={KEY_ROTATION_HARD_LIMIT / 1024 / 1024}MB")

    # 2. Streaming Loop
    for chunk in split_file_into_chunks(file_path, CHUNK_SIZE):
        try:
            # A. Key Management (Updated with 2 limits)
            # Store old ID to detect if rotation happened
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
                # Key rotated (either purely soft, or after hard blocking)
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