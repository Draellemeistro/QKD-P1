import os
import re
import hashlib
import mmap

def load_file_contents(file_path):
    """Load and return the contents of a file."""
    with open(file_path, 'r') as file:
        return file.read()

def save_file_contents(file_path, contents):
    """Save the given contents to a file."""
    with open(file_path, 'w') as file:
        file.write(contents)


def split_file_into_chunks(file_path, chunk_size_bytes):
    """
    Reads any file in binary mode and yields chunks of a specific byte size.
    """
    chunk_id = 0
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



def _get_chunk_id(filename):
    """
    Extracts chunk_id from chunk
    Returns -1 if no number is found.
    """
    # Search for one or more digits
    match = re.search(r'(\d+)', filename)

    # Check if a match was found
    if match:
        # Return the first capturing group (the digits) as an integer
        return int(match.group(1))

    # Return a default value if no number is found
    return -1


def get_sorted_chunk_files(chunk_directory, chunk_prefix="chunk_"):
    """
    Reads a directory, filters for chunk files, and returns
    a list of filenames sorted numerically by their embedded ID.

    Returns an empty list if no files are found or the directory
    doesn't exist.
    """
    try:
        all_files = os.listdir(chunk_directory)
    except FileNotFoundError:
        # If the directory doesn't exist, return an empty list
        return []

    # Filter for files that match our prefix
    chunk_files = [f for f in all_files if f.startswith(chunk_prefix)]

    # Sort the list using our helper function as the key
    chunk_files.sort(key=_get_chunk_id)

    # Return the sorted list
    return chunk_files


def reassemble_file(sorted_chunk_files, output_file_path, chunk_directory):
    """ Reassembles sorted binary chunks into a single file. """

    with open(output_file_path, 'wb') as output_file:
        for chunk_file in sorted_chunk_files:
            chunk_path = os.path.join(chunk_directory, chunk_file)
            with open(chunk_path, 'rb') as cf:
                chunk_data = cf.read()
                output_file.write(chunk_data)
    print(f"Reassembled file saved to {output_file_path}")


def hash_file(file_path, hash_algorithm):
    """ Computes the hash of a file using memory-mapped file access. """
    hash_func = hashlib.new(hash_algorithm)

    with open(file_path, "rb") as f:

        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:

            while chunk := mm.read(65536): # Read in 64KB chunks
                hash_func.update(chunk)

    return hash_func.hexdigest()


def validate_file_hash(file_path, expected_hash, hash_algorithm):
    """ Validates the hash of a file against an expected hash value. """
    computed_hash = hash_file(file_path, hash_algorithm)
    return computed_hash == expected_hash



