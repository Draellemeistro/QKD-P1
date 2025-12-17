import time
import os
import secrets
from src.app.crypto import encryption

# Setup 100 MB of dummy data
DATA_SIZE = 100 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
dummy_data = secrets.token_bytes(CHUNK_SIZE)
dummy_key = secrets.token_hex(32) # AES-256

print(f"Benchmarking AES-256-GCM (Python Cryptography)...")
print(f"Encrypting {DATA_SIZE / 1024 / 1024:.0f} MB in memory...")

start = time.time()
bytes_processed = 0

for _ in range(DATA_SIZE // CHUNK_SIZE):
    # This matches exactly what sender.py does
    _ = encryption.encrypt_AES256(dummy_data, dummy_key)
    bytes_processed += CHUNK_SIZE

duration = time.time() - start
mb_sec = (bytes_processed / 1024 / 1024) / duration

print(f"--- RESULTS ---")
print(f"Time: {duration:.4f}s")
print(f"Speed: {mb_sec:.2f} MB/s")
print(f"Max Possible Throughput: {mb_sec * 8:.0f} Mbps")