import time
import sys
import requests
from src.app.transfer.tcp_transport import TcpTransport
from src.app.kms_api import new_key
from src.app.file_utils import split_file_into_chunks, hash_file
from src.app.crypto import encryption
from src.app.transfer.network_utils import resolve_host
from src.app.transfer.protocol import create_data_packet, create_termination_packet, decode_packet_with_headers

# --- CONFIGURATION ---
CHUNK_SIZE = 64 * 1024

# Rotation policy (bytes)
KEY_ROTATION_SOFT_LIMIT = 1024 * 1024 * 1   # 10 MB
KEY_ROTATION_HARD_LIMIT = 1024 * 1024 * 1.5   # 15 MB


def establish_connection(ip, port):
    transport = TcpTransport(is_server=False)
    if transport.connect(ip, port):
        return transport
    return None


def fetch_key_blocking(receiver_id, metrics):
    """
    Hard-limit behavior: block until a key is available.
    Logs 503 counts + wait time.
    """
    while True:
        try:
            return new_key(receiver_id)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 503:
                metrics["kms_503_total"] += 1
                metrics["kms_503_hard_block"] += 1

                if metrics["kms_503_first_at_mb"] is None:
                    metrics["kms_503_first_at_mb"] = metrics["mb_sent_so_far"]

                print(" [!] Hard Limit / No Key: KMS busy (503). Waiting 1s...")
                t0 = time.time()
                time.sleep(1)
                metrics["kms_503_wait_time_s"] += (time.time() - t0)
                continue
            raise


def ensure_valid_key(current_key, bytes_used, soft_limit, hard_limit, receiver_id, metrics):
    """
    Soft-limit behavior: attempt rotation. If 503:
      - below hard limit: extend current key life (availability)
      - at/above hard limit: block until new key (security policy)
    """
    if current_key is None:
        print("Initial key fetch...")
        return fetch_key_blocking(receiver_id, metrics)

    if bytes_used >= soft_limit:
        try:
            return new_key(receiver_id)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 503:
                metrics["kms_503_total"] += 1

                if metrics["kms_503_first_at_mb"] is None:
                    metrics["kms_503_first_at_mb"] = metrics["mb_sent_so_far"]

                if bytes_used >= hard_limit:
                    print(f" [!] HARD LIMIT HIT ({bytes_used / (1024*1024):.2f} MB). Blocking for new key...")
                    return fetch_key_blocking(receiver_id, metrics)
                else:
                    metrics["kms_503_soft_extend"] += 1
                    print(f" [i] Rate Limit (503). Extending key life (Used: {bytes_used / 1024:.0f} KB)")
                    return current_key
            raise
    return current_key


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    transport = establish_connection(destination_ip, destination_port)
    if not transport:
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    print(f"Calculating hash for {file_path}...")
    file_hash = hash_file(file_path)
    print(f"File Hash (SHA-256): {file_hash}")

    # --- PERFORMANCE TIMERS ---
    t_key_fetch = 0.0
    t_encryption = 0.0
    t_network_send = 0.0

    # --- KEY FETCH COUNTERS ---
    kms_calls_total = 0
    kms_rotations_total = 0
    kms_blocks_total = 0
    last_block_id = None

    # --- SCARCITY / 503 METRICS ---
    metrics = {
        "kms_503_total": 0,
        "kms_503_soft_extend": 0,
        "kms_503_hard_block": 0,
        "kms_503_wait_time_s": 0.0,
        "kms_503_first_at_mb": None,
        "mb_sent_so_far": 0.0,  # updated during loop
    }

    current_key_data = None
    bytes_encrypted_with_current_key = 0
    total_bytes = 0

    print("Rotation policy:")
    print(f"  Soft limit: {KEY_ROTATION_SOFT_LIMIT / (1024*1024):.2f} MB")
    print(f"  Hard limit: {KEY_ROTATION_HARD_LIMIT / (1024*1024):.2f} MB")
    print(f"Chunk size: {CHUNK_SIZE / 1024:.0f} KB")
    print(f"Starting transfer of {file_path}...")
    start_time = time.time()

    for chunk in split_file_into_chunks(file_path, CHUNK_SIZE):
        try:
            # Update "so far" for 503-first-at logging
            metrics["mb_sent_so_far"] = total_bytes / 1024 / 1024

            # A. Key Management
            t0 = time.time()
            old_key_index = current_key_data["index"] if current_key_data else -1
            old_block_id = current_key_data["blockId"] if current_key_data else None

            current_key_data = ensure_valid_key(
                current_key_data,
                bytes_encrypted_with_current_key,
                KEY_ROTATION_SOFT_LIMIT,
                KEY_ROTATION_HARD_LIMIT,
                receiver_id,
                metrics
            )
            t_key_fetch += (time.time() - t0)

            # Detect actual key change (init or rotation)
            key_changed = (
                old_block_id is None or
                current_key_data["blockId"] != old_block_id or
                current_key_data["index"] != old_key_index
            )

            if key_changed:
                kms_calls_total += 1
                if old_block_id is not None:
                    kms_rotations_total += 1

                if current_key_data["blockId"] != last_block_id:
                    kms_blocks_total += 1
                    last_block_id = current_key_data["blockId"]

                bytes_encrypted_with_current_key = 0

            # B. Encryption
            t0 = time.time()
            encrypted_payload = encryption.encrypt_AES256(chunk["data"], current_key_data["hexKey"])
            packet = create_data_packet(
                chunk["id"],
                current_key_data["blockId"],
                current_key_data["index"],
                encrypted_payload
            )
            t_encryption += (time.time() - t0)

            # C. Network Send
            t0 = time.time()
            transport.send_reliable(packet)
            t_network_send += (time.time() - t0)

            # D. State Update
            bytes_encrypted_with_current_key += chunk["size"]
            total_bytes += chunk["size"]

            if chunk["id"] % 10 == 0:
                print(f"Sent chunk {chunk['id']}...", end="\r")

        except BrokenPipeError:
            print("\nError: Connection lost.")
            break
        except Exception as e:
            print(f"\nCritical Error: {e}")
            break

    # Termination
    print("\nSending termination signal...")
    end_packet = create_termination_packet(file_hash)
    transport.send_reliable(end_packet)

    total_duration = time.time() - start_time
    mb_sent = total_bytes / 1024 / 1024

    # Security metric: effective data per key
    keys_used = max(kms_rotations_total, 1)  # avoid divide-by-zero
    effective_mb_per_key = mb_sent / keys_used

    print("\n" + "=" * 40)
    print(f"TRANSFER COMPLETE: {mb_sent:.2f} MB in {total_duration:.2f}s")
    print(f"Throughput:      {(mb_sent * 8) / total_duration:.2f} Mbps")
    print("-" * 40)
    print("TIME BREAKDOWN:")
    print(f"  KMS Fetching:  {t_key_fetch:.4f} s ({(t_key_fetch / total_duration) * 100:.1f}%)")
    print(f"  Encryption:    {t_encryption:.4f} s ({(t_encryption / total_duration) * 100:.1f}%)")
    print(f"  Network Send:  {t_network_send:.4f} s ({(t_network_send / total_duration) * 100:.1f}%)")
    t_other = total_duration - (t_key_fetch + t_encryption + t_network_send)
    print(f"  Disk/Overhead: {t_other:.4f} s ({(t_other / total_duration) * 100:.1f}%)")
    print("-" * 40)

    print("KMS COUNTS:")
    print(f"  KMS key fetches (total):   {kms_calls_total}")
    print(f"  KMS rotations (excl init): {kms_rotations_total}")
    print(f"  Key blocks observed:       {kms_blocks_total}")
    if kms_calls_total > 0:
        print(f"  Avg ms per key fetch:      {(t_key_fetch / kms_calls_total) * 1000:.2f} ms")

    print("-" * 40)
    print("SCARCITY (503) METRICS:")
    print(f"  503 responses total:        {metrics['kms_503_total']}")
    print(f"  503 during soft-limit:      {metrics['kms_503_soft_extend']}")
    print(f"  503 causing hard blocking:  {metrics['kms_503_hard_block']}")
    print(f"  Time spent waiting (sleep): {metrics['kms_503_wait_time_s']:.2f} s")
    if metrics["kms_503_first_at_mb"] is not None:
        print(f"  First 503 at:               {metrics['kms_503_first_at_mb']:.2f} MB sent")
    else:
        print("  First 503 at:               (none)")

    print("-" * 40)
    print("SECURITY METRIC:")
    print(f"  Effective data per key:     {effective_mb_per_key:.3f} MB/key")
    print("=" * 40 + "\n")

    print("[Protocol] Waiting for Receiver Confirmation (ACK)...")
    try:
        ack_data = transport.receive_packet()
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
    target_name = sys.argv[1] if len(sys.argv) > 1 else "bob"
    target_ip, target_port, peer_site_id = resolve_host(target_name)
    run_file_transfer(peer_site_id, target_ip, target_port, "data/patient_records.txt")
