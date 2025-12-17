import time
import sys
import requests
# REMOVED: from src.app.transfer.transport import Transport (Old ENet)
from src.app.transfer.tcp_transport import TcpTransport
from src.app.kms_api import new_key
from src.app.file_utils import split_file_into_chunks, hash_file
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers

# --- CONFIGURATION ---
CHUNK_SIZE = 64 * 1024
KEY_ROTATION_SOFT_LIMIT = 1024 * 1024 * 1
KEY_ROTATION_HARD_LIMIT = 1024 * 1024 * 50


def establish_connection(ip, port):
    transport = TcpTransport(is_server=False)
    if transport.connect(ip, port):
        return transport
    return None


def fetch_key_blocking(receiver_id):
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
    if current_key is None:
        print("Initial key fetch...")
        return fetch_key_blocking(receiver_id)

    if bytes_used >= soft_limit:
        try:
            return new_key(receiver_id)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 503:
                if bytes_used >= hard_limit:
                    print(f" [!] HARD LIMIT HIT ({bytes_used} bytes). Blocking for new key...")
                    return fetch_key_blocking(receiver_id)
                else:
                    print(f" [i] Rate Limit (503). Extending key life (Used: {bytes_used / 1024:.0f} KB)")
                    return current_key
            else:
                raise e
    return current_key


def send_chunk_packet(transport, chunk, key_data):
    encrypted_payload = encryption.encrypt_AES256(chunk["data"], key_data["hexKey"])
    packet = create_data_packet(chunk["id"], key_data["blockId"], key_data["index"], encrypted_payload)
    # TCP Update: send_reliable now just writes to the socket stream
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

            if current_key_data["index"] != old_key_id:
                bytes_encrypted_with_current_key = 0

            # B. Processing & Sending
            send_chunk_packet(transport, chunk, current_key_data)

            # REMOVED: transport.service(0) -> Not needed for TCP
            # REMOVED: time.sleep() -> Not needed, TCP handles flow control automatically

            # D. State Update
            bytes_encrypted_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            if chunk["id"] % 10 == 0:
                print(f"Sent chunk {chunk['id']}...", end='\r')

        except BrokenPipeError:
            print("\nError: Connection lost.")
            break
        except Exception as e:
            print(f"\nCritical Error: {e}")
            break

    # 3. Termination
    print("\nSending termination signal...")
    end_packet = create_termination_packet(file_hash)
    transport.send_reliable(end_packet)

    duration = time.time() - start_time
    print(f"Transfer complete. {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s")

    # --- UPDATE: TCP ACK WAITING ---
    print("\n[Protocol] Waiting for Receiver Confirmation (ACK)...")

    # In TCP, we don't loop for events. We just block-read the next packet.
    try:
        ack_data = transport.receive_packet()  # This blocks until data arrives

        if ack_data:
            headers, _ = decode_packet_with_headers(ack_data)
            if headers.get("type") == "ACK":
                status = headers.get("status", "UNKNOWN")
                print(f"[Server Reply] Status: {status} - {headers.get('message', '')}")
            else:
                print("[Warning] Received unexpected packet type.")
        else:
            print("[Error] Connection closed before ACK received.")

    except Exception as e:
        print(f"Error reading ACK: {e}")

    print("Sender exiting.")
    transport.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_name = sys.argv[1]
    else:
        target_name = "bob"

    target_ip, target_port, peer_site_id = resolve_host(target_name)
    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")