import os
from src.app.kms_api import get_key
from src.app.transfer.tcp_transport import TcpTransport
from src.app.crypto import encryption
from src.app.file_utils import FileStreamWriter, validate_file_hash_xxh
from src.app.transfer.protocol import decode_packet_with_headers, create_ack_packet

# Configuration
SENDER_ID = os.getenv("SENDER_ID", "A")  # Ensure this matches the ID expected by KMS
LISTEN_IP = os.getenv("LISTEN_IP", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", 12345))
OUTPUT_FILE = "received_data/reconstructed_patient_data.txt"


def start_server(ip, port):
    """
    Initializes the TCP listener.
    """
    transport = TcpTransport(is_server=True, ip=ip, port=port)
    return transport


def get_decryption_key(sender_id, block_id, index):
    """Wrapper for KMS interaction"""
    #
    return get_key(sender_id, block_id, index)


def process_single_packet(packet_dict, writer, sender_id, key_cache):
    """
    1. Fetches key (if needed).
    2. Decrypts.
    3. Writes to disk.
    """
    chunk_id = packet_dict.get("chunk_id", -1)

    try:
        needed_key_id = (packet_dict["key_block_id"], packet_dict["key_index"])

        # Check if we need to rotate/fetch the key
        if key_cache.get("id") != needed_key_id:
            print(
                f"[Receiver] Chunk {chunk_id} | Fetching Decrypt Key (Block: {needed_key_id[0]}, Index: {needed_key_id[1]})...")
            key_metadata = get_decryption_key(
                sender_id,
                packet_dict["key_block_id"],
                packet_dict["key_index"]
            )
            if not key_metadata:
                raise ValueError(f"KMS returned no key for {needed_key_id}")

            key_cache["id"] = needed_key_id
            key_cache["data"] = key_metadata

        current_key = key_cache["data"]

        # FIX: Ensure we access the key consistently.
        # Assuming current_key is a dict containing "hexKey" based on usage below.
        decrypted_str = encryption.decrypt_AES256(packet_dict["data"], current_key["hexKey"])
        writer.append(decrypted_str)

        # FIX: Use the dictionary value directly for logging.
        # The previous 'current_key.hex()' caused an AttributeError on the dictionary object.
        key_hex_log = current_key.get("hexKey", "UNKNOWN")

        # Optional: Print detailed debug only for specific chunks to reduce noise
        # print(f"[Receiver] Chunk {chunk_id} | Block: {needed_key_id[0]} | Key: {key_hex_log[:10]}...")

        if chunk_id % 50 == 0:
            print(f"Processed chunk {chunk_id}...", end='\r')

    except Exception as e:
        print(f"\nError processing chunk {chunk_id}: {e}")
        # Depending on requirements, you might want to `raise` here to stop the transfer
        # or log it to a separate error file so you know which chunks are missing.


def run_reception_loop(transport, output_file, receiver_id):
    """
    Main TCP Event Loop.
    """
    print(f"Receiver listening on {LISTEN_IP}:{LISTEN_PORT}...")
    client_conn = transport.accept()
    if not client_conn:
        print("Error: Accept failed.")
        return

    key_cache = {"id": None, "data": None}
    received_hash = ""

    # Ensure directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with FileStreamWriter(output_file) as writer:
        print(f"Connection established! Writing to {output_file}")

        while True:
            data = transport.receive_packet()

            if not data:
                print("\nSender disconnected.")
                break

            try:
                headers, encrypted_data = decode_packet_with_headers(data)

                packet_dict = {
                    "chunk_id": headers.get("chunk_id", -1),
                    "key_block_id": headers.get("key_block_id"),
                    "key_index": headers.get("key_index"),
                    "is_last": headers.get("is_last", False),
                    "data": encrypted_data
                }

                if packet_dict["is_last"]:
                    received_hash = headers.get("file_hash", "")
                    print(f"\nTermination packet received. (Remote xxHash: {received_hash})")
                    break
                else:
                    process_single_packet(packet_dict, writer, receiver_id, key_cache)

            except (ValueError, UnicodeDecodeError) as e:
                print(f"Error: Malformed packet: {e}")

    print("Verifying integrity with xxHash...")
    is_valid = validate_file_hash_xxh(output_file, received_hash)

    status_code = "OK" if is_valid else "ERROR"
    status_msg = "Integrity Verified (xxHash)" if is_valid else "Hash Mismatch"

    if is_valid:
        print(f"SUCCESS: {status_msg}")
    else:
        print(f"WARNING: {status_msg}")

    print(f"Sending ACK ({status_code})...")
    ack_data = create_ack_packet(status=status_code, message=status_msg)
    transport.send_reliable(ack_data)


def main():
    transport = start_server(LISTEN_IP, LISTEN_PORT)
    try:
        run_reception_loop(transport, OUTPUT_FILE, SENDER_ID)
        print("Receiver finished.")
    except KeyboardInterrupt:
        print("\nReceiver stopped by user.")
    finally:
        transport.close()


if __name__ == "__main__":
    main()