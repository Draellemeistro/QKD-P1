import json
import enet
from src.app.kms_api import get_key
from src.app.transfer.transport import Transport
from src.app.crypto import encryption
from src.app.file_utils import FileStreamWriter
from src.app.transfer.protocol import decode_packet_with_headers

# Configuration
SENDER_ID = "A"
LISTEN_IP = "172.18.0.4"
LISTEN_PORT = 12345
OUTPUT_FILE = "received_data/reconstructed_patient_data.txt"


def start_server(ip, port):
    """
    Initializes the transport layer (Side Effect: Network IO).
    """
    transport = Transport(is_server=True, ip=ip, port=port)
    print(f"Receiver listening on {ip}:{port}...")
    return transport


def get_decryption_key(sender_id, block_id, index):
    """
    Wrapper for KMS interaction
    """
    return get_key(sender_id, block_id, index)


def process_single_packet(packet_dict, writer, sender_id):
    """
    1. Checks termination.
    2. Fetches key.
    3. Decrypts.
    4. Writes to disk.

    Returns: True if transfer is complete, False otherwise.
    """
    # 1. Termination Check
    if packet_dict.get("is_last", False):
        print("\nTermination packet received.")
        return True

    chunk_id = packet_dict.get("chunk_id", -1)

    try:
        # 2. Fetch Key
        key_metadata = get_decryption_key(
            sender_id,
            packet_dict["key_block_id"],
            packet_dict["key_index"]
        )
        # 3. Decrypt

        decrypted_str = encryption.decrypt_AES256(packet_dict["data"], key_metadata["hexKey"])

        # 4. Write to Stream
        writer.append(decrypted_str)

        # Log progress (only every 10th chunk to reduce console spam)
        if chunk_id % 10 == 0:
            print(f"Processed chunk {chunk_id}...", end='\r')

    except Exception as e:
        # Should send a NACK here
        print(f"\nError processing chunk {chunk_id}: {e}")

    return False


def run_reception_loop(transport, output_file, receiver_id):
    """
    Main Event Loop (Orchestration).
    """
    # Open the file stream
    with FileStreamWriter(output_file) as writer:
        print(f"Ready to write to {output_file}")

        while True:
            # 1. Network Poll (Wait up to 100ms)
            event = transport.service(100)

            if event.type == enet.EVENT_TYPE_RECEIVE:
                try:
                    # 2. Parse Protocol
                    headers, encrypted_data = decode_packet_with_headers(event.packet.data)

                    # Convert to the dict format your processor expects
                    packet_dict = {
                        "chunk_id": headers.get("chunk_id", -1),
                        "key_block_id": headers.get("key_block_id"),
                        "key_index": headers.get("key_index"),
                        "is_last": headers.get("is_last", False),
                        "data": encrypted_data
                    }

                    # 3. Execute Logic
                    finished = process_single_packet(packet_dict, writer, receiver_id)

                    if finished:
                        break

                except json.JSONDecodeError:
                    print("Error: Received malformed JSON")

            elif event.type == enet.EVENT_TYPE_CONNECT:
                print(f"Client connected: {event.peer.address}")


def main():
    transport = start_server(LISTEN_IP, LISTEN_PORT)
    try:
        run_reception_loop(transport, OUTPUT_FILE, SENDER_ID)
        print("File transfer complete.")
    finally:
        transport.flush()


if __name__ == "__main__":
    main()