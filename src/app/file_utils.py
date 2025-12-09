import os
import hashlib
import mmap


# --- 1. Reading (Generator Pattern) ---

def split_file_into_chunks(file_path, chunk_size_bytes):
    """
    Reads a file lazily in binary chunks.
    Memory efficient: Only keeps 'chunk_size_bytes' in RAM at a time.
    """
    chunk_id = 0
    try:
        with open(file_path, 'rb') as file:
            while True:
                chunk_data = file.read(chunk_size_bytes)
                if not chunk_data:
                    break

                yield {
                    "id": chunk_id,
                    "data": chunk_data,
                    "size": len(chunk_data)
                }
                chunk_id += 1
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return


# --- 2. Writing (Streaming Pattern) ---

class FileStreamWriter:
    """
    Context manager for safe, sequential file writing.
    Replaces the need to save thousands of temp files.
    """

    def __init__(self, output_path):
        self.output_path = output_path
        self.file = None

    def __enter__(self):
        # Open in binary write mode (overwrites existing)
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        self.file = open(self.output_path, 'wb')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

    def append(self, data_bytes):
        """Write the next chunk of data to the file."""
        if self.file:
            self.file.write(data_bytes)
            # self.file.flush() # Optional: slowing down but safer


# --- 3. Verification ---

def hash_file(file_path, hash_algorithm="sha256"):
    """
    Computes hash using mmap for memory efficiency on large files.
    """
    hash_func = hashlib.new(hash_algorithm)
    try:
        with open(file_path, "rb") as f:
            # Handle empty files which crash mmap
            if os.path.getsize(file_path) == 0:
                return hash_func.hexdigest()

            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                # Read in 64KB chunks from the memory map
                while chunk := mm.read(65536):
                    hash_func.update(chunk)
    except FileNotFoundError:
        return None

    return hash_func.hexdigest()


def validate_file_hash(file_path, expected_hash):
    computed = hash_file(file_path)
    return computed == expected_hash