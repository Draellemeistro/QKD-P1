import os
import re

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



def reassemble_file(output_file_path, chunk_directory, chunk_prefix="chunk_"):
    """
    Reads binary chunks from a directory, sorts them by ID,
    and stitches them back into a single file.
    """

    # Get all files in the directory
    files = os.listdir(chunk_directory)

    # Filter for files that look like our chunks
    chunk_files = [f for f in files if f.startswith(chunk_prefix)]

    if not chunk_files:
        print("No chunks found")
        return

    # Sort files numerically by the ID embedded in the filename
    # Use regex to extract the number from the filename
    chunk_files.sort(key=lambda f: int(re.search(r'(\d+)', f).group()))

    print(f"Found {len(chunk_files)} chunks. Reassembling...")

    # Create the output file
    with open(output_file_path, 'wb') as output_file:
        for chunk_name in chunk_files:
            chunk_path = os.path.join(chunk_directory, chunk_name)

            # Open each chunk in Read Binary mode
            with open(chunk_path, 'rb') as chunk_file:
                chunk_data = chunk_file.read()
                output_file.write(chunk_data)

            print(f"Stitched: {chunk_name}")

    print(f"Reassembled file saved to: {output_file_path}")