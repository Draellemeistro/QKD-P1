import os
from src.app.kms_api import get_key
from src.app.transfer.tcp_transport import TcpTransport
from src.app.crypto import encryption
from src.app.file_utils import FileStreamWriter, validate_file_hash
from src.app.transfer.protocol import decode_packet_with_headers, create_ack_packet

# Configuration
SENDER_ID = os.getenv("SENDER_ID", "A")
LISTEN_IP = os.getenv("LISTEN_IP", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", 12345))
OUTPUT_FILE = "received_data/reconstructed_patient_data.txt"


def start_server(ip, port):
    """
    Initializes the TCP transport layer and waits (blocks) for a connection.
    """
    transport = TcpTransport(is_server=True, ip=ip, port=port)
    # This blocks until the Sender connects
    transport.accept()
    return transport


def get_decryption_key(sender_id, block_id, index):
    """
    Wrapper for KMS interaction
    """
    return get_key(sender_id, block_id, index)


def process_single_packet(packet_dict, writer, sender_id, key_cache):
    """
    1. Fetches key (if needed).
    2. Decrypts.
    3. Writes to disk.
    """
    chunk_id = packet_dict.get("chunk_id", -1)

    try:
        # Fetch Key
        needed_key_id = (packet_dict["key_block_id"], packet_dict["key_index"])

        # Check if we need to fetch a new key
        if key_cache.get("id") != needed_key_id:
            # print(f"Fetching new key (Block: {needed_key_id[0]}, Index: {needed_key_id[1]})...")

            key_metadata = get_decryption_key(
                sender_id,
                packet_dict["key_block_id"],
                packet_dict["key_index"]
            )
            # Update the cache
            key_cache["id"] = needed_key_id
            key_cache["data"] = key_metadata

        current_key = key_cache["data"]

        # Decrypt
        decrypted_str = encryption.decrypt_AES256(packet_dict["data"], current_key["hexKey"])

        # Write to Stream
        writer.append(decrypted_str)

        # Log progress (only every 10th chunk to reduce console spam)
        if chunk_id % 10 == 0:
            print(f"Processed chunk {chunk_id}...", end='\r')

    except Exception as e:
        print(f"\nError processing chunk {chunk_id}: {e}")

    return False


def run_reception_loop(transport, output_file, receiver_id):
    """
    Main TCP Blocking Loop.
    """
    # Initialize Key Cache
    key_cache = {"id": None, "data": None}
    received_hash = ""

    # Open the file stream
    with FileStreamWriter(output_file) as writer:
        print(f"Ready to write to {output_file}")

        while True:
            packet_data = transport.receive_packet()

            # If receive_packet returns None, the sender closed the connection (or crashed)
            if not packet_data:
                print("\nConnection closed by Sender.")
                break

            try:
                # Parse Protocol
                headers, encrypted_data = decode_packet_with_headers(packet_data)

                # Convert to dict
                packet_dict = {
                    "chunk_id": headers.get("chunk_id", -1),
                    "key_block_id": headers.get("key_block_id"),
                    "key_index": headers.get("key_index"),
                    "is_last": headers.get("is_last", False),
                    "data": encrypted_data
                }

                if packet_dict["is_last"]:
                    received_hash = headers.get("file_hash", "")
                    print("\nTermination packet received.")
                    break  # Exit loop, file is done

                # Process Data Packet (Decrypt & Write)
                process_single_packet(packet_dict, writer, receiver_id, key_cache)

            except Exception as e:
                print(f"Error decoding/processing packet: {e}")

    print("Verifying integrity...")
    is_valid = validate_file_hash(output_file, received_hash)

    status_code = "OK" if is_valid else "ERROR"
    status_msg = "Integrity Verified" if is_valid else "Hash Mismatch"

    if is_valid:
        print(f"SUCCESS: {status_msg}. Hash: {received_hash}")
    else:
        print(f"WARNING: {status_msg}. Sent: {received_hash}")

    # Send ACK back to Sender
    print(f"Sending ACK ({status_code}) to Sender...")
    ack_data = create_ack_packet(status=status_code, message=status_msg)
    transport.send_reliable(ack_data)


def main():
    # Start Server & Wait for Connection
    transport = start_server(LISTEN_IP, LISTEN_PORT)
    try:
        run_reception_loop(transport, OUTPUT_FILE, SENDER_ID)
        print("File transfer session finished.")
    finally:
        transport.close()


if __name__ == "__main__":
    main()