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
CHUNK_SIZE = 64 * 1024  # 64KB

# Rotation policy (bytes)
KEY_ROTATION_SOFT_LIMIT = 10 * 1024 * 1024   # 10 MB
KEY_ROTATION_HARD_LIMIT = 15 * 1024 * 1024   # 15 MB


def establish_connection(ip, port):
    transport = TcpTransport(is_server=False)
    if transport.connect(ip, port):
        return transport
    return None


def _timed_new_key(receiver_id, metrics):
    """
    Wrap new_key() so we count attempts/success and accumulate timing.
    """
    metrics["kms_http_attempts"] += 1
    t0 = time.time()
    try:
        key = new_key(receiver_id)
        metrics["kms_http_success"] += 1
        return key, (time.time() - t0)
    except requests.exceptions.HTTPError as e:
        dt = (time.time() - t0)
        if e.response is not None and e.response.status_code == 503:
            metrics["kms_http_503"] += 1
        raise
    finally:
        metrics["kms_http_time_s"] += (time.time() - t0)


def fetch_key_blocking(receiver_id, metrics):
    """
    Hard-limit behavior: block until a key is available.
    Tracks 503 counts + wait time.
    """
    while True:
        try:
            key, _ = _timed_new_key(receiver_id, metrics)
            return key
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 503:
                metrics["kms_503_total"] += 1
                metrics["kms_503_hard_block"] += 1

                if metrics["kms_503_first_at_mb"] is None:
                    metrics["kms_503_first_at_mb"] = metrics["mb_sent_so_far"]

                # Backoff for hard-blocking (this is fine to keep at 1s)
                t0 = time.time()
                time.sleep(1)
                metrics["kms_503_wait_time_s"] += (time.time() - t0)
                continue
            raise


def ensure_valid_key(current_key, bytes_used, soft_limit, hard_limit, receiver_id, metrics):
    if current_key is None:
        print("Initial key fetch...")
        return fetch_key_blocking(receiver_id, metrics)

    # Only consider rotating once we've exceeded the soft limit
    if bytes_used < soft_limit:
        return current_key

    # Enforce hard limit regardless of cooldown
    if bytes_used >= hard_limit:
        print(f" [!] HARD LIMIT HIT ({bytes_used / (1024*1024):.2f} MB). Blocking for new key...")
        return fetch_key_blocking(receiver_id, metrics)

    # Cooldown gate only for soft-limit retries
    now = time.time()
    if now < metrics.get("rotate_cooldown_until_ts", 0.0):
        return current_key

    # Try to rotate
    try:
        key, _ = _timed_new_key(receiver_id, metrics)
        return key
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 503:
            metrics["kms_503_total"] += 1
            if metrics["kms_503_first_at_mb"] is None:
                metrics["kms_503_first_at_mb"] = metrics["mb_sent_so_far"]

            metrics["kms_503_soft_extend"] += 1

            # Schedule the next rotation attempt (retry spacing)
            metrics["rotate_cooldown_until_ts"] = time.time() + 0.2
            t0 = time.time()
            # Small delay to avoid hot-looping (your request)
            time.sleep(0.02)
            metrics["kms_503_wait_time_s"] += (time.time() - t0)

            return current_key
        raise


def run_file_transfer(receiver_id, destination_ip, destination_port, file_path):
    transport = establish_connection(destination_ip, destination_port)
    if not transport:
        print(f"Error: Could not connect to {destination_ip}:{destination_port}")
        return

    print(f"Calculating hash for {file_path}...")
    file_hash = hash_file(file_path)
    print(f"File Hash (SHA-256): {file_hash}")

    # --- PERFORMANCE TIMERS  ---
    t_key_fetch = 0.0       # time inside ensure_valid_key (includes local logic + sleep)
    t_encryption = 0.0
    t_network_send = 0.0

    # --- KMS SUCCESS COUNTS (actual key changes) ---
    kms_successful_key_changes = 0
    kms_rotations_success = 0
    kms_blocks_observed = 0
    last_block_id = None

    # --- SCARCITY / 503 METRICS + HTTP accounting ---
    metrics = {
        "kms_503_total": 0,
        "kms_503_soft_extend": 0,
        "kms_503_hard_block": 0,
        "kms_503_wait_time_s": 0.0,
        "kms_503_first_at_mb": None,
        "mb_sent_so_far": 0.0,
        "rotate_cooldown_until_ts": 0.0,
        "kms_http_attempts": 0,
        "kms_http_success": 0,
        "kms_http_503": 0,
        "kms_http_time_s": 0.0,
    }

    keys_used_set = set()            # unique (blockId, index) used in encryption
    key_bytes_usage = {}             # (blockId, index) -> bytes encrypted under that key

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

            key_changed = (
                old_block_id is None or
                current_key_data["blockId"] != old_block_id or
                current_key_data["index"] != old_key_index
            )

            if key_changed:
                kms_successful_key_changes += 1
                if old_block_id is not None:
                    kms_rotations_success += 1

                if current_key_data["blockId"] != last_block_id:
                    kms_blocks_observed += 1
                    last_block_id = current_key_data["blockId"]

                bytes_encrypted_with_current_key = 0

            # B. Encryption
            key_id = (current_key_data["blockId"], current_key_data["index"])
            keys_used_set.add(key_id)

            t0 = time.time()
            encrypted_payload = encryption.encrypt_AES256(chunk["data"], current_key_data["hexKey"])
            packet = create_data_packet(
                chunk["id"],
                current_key_data["blockId"],
                current_key_data["index"],
                encrypted_payload
            )
            t_encryption += (time.time() - t0)

            # Track bytes encrypted under the key actually used
            key_bytes_usage[key_id] = key_bytes_usage.get(key_id, 0) + chunk["size"]

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


    unique_keys_used = max(len(keys_used_set), 1)
    effective_mb_per_key = mb_sent / unique_keys_used

    #max bytes under any single key
    max_mb_under_one_key = 0.0
    if key_bytes_usage:
        max_mb_under_one_key = max(key_bytes_usage.values()) / 1024 / 1024

    # Avg ms per HTTP attempt (success+fail), and per success
    avg_ms_per_attempt = (metrics["kms_http_time_s"] / max(metrics["kms_http_attempts"], 1)) * 1000
    avg_ms_per_success = (metrics["kms_http_time_s"] / max(metrics["kms_http_success"], 1)) * 1000

    print("\n" + "=" * 40)
    print(f"TRANSFER COMPLETE: {mb_sent:.2f} MB in {total_duration:.2f}s")
    print(f"Throughput:      {(mb_sent * 8) / total_duration:.2f} Mbps")
    print("-" * 40)
    print("TIME BREAKDOWN:")
    print(f"  KMS Handling:  {t_key_fetch:.4f} s ({(t_key_fetch / total_duration) * 100:.1f}%)")
    print(f"  Encryption:    {t_encryption:.4f} s ({(t_encryption / total_duration) * 100:.1f}%)")
    print(f"  Network Send:  {t_network_send:.4f} s ({(t_network_send / total_duration) * 100:.1f}%)")
    t_other = total_duration - (t_key_fetch + t_encryption + t_network_send)
    print(f"  Disk/Overhead: {t_other:.4f} s ({(t_other / total_duration) * 100:.1f}%)")
    print("-" * 40)

    print("KMS SUCCESS COUNTS (actual key changes):")
    print(f"  Successful key changes (incl init): {kms_successful_key_changes}")
    print(f"  Successful rotations (excl init):   {kms_rotations_success}")
    print(f"  Key blocks observed:                {kms_blocks_observed}")
    print("-" * 40)

    print("KMS HTTP COUNTS (attempt-level):")
    print(f"  HTTP attempts total:        {metrics['kms_http_attempts']}")
    print(f"  HTTP successes total:       {metrics['kms_http_success']}")
    print(f"  HTTP 503 total:             {metrics['kms_http_503']}")
    print(f"  Avg ms per HTTP attempt:    {avg_ms_per_attempt:.2f} ms")
    print(f"  Avg ms per HTTP success:    {avg_ms_per_success:.2f} ms")
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

    print("SECURITY METRICS (based on keys actually used in encryption):")
    print(f"  Unique keys used:           {unique_keys_used}")
    print(f"  Effective data per key:     {effective_mb_per_key:.3f} MB/key")
    print(f"  Max data under one key:     {max_mb_under_one_key:.3f} MB")
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
