import encryption_module

refresh_interval = 100  # Example refresh interval
refresh_interval_from_size = 1024 * 1024  # Example size-based refresh interval (1 MB)


# Refresh key every refresh_interval blocks
def refresh_key_block(block_number, refresh_interval):
    return block_number % refresh_interval == 0


def refresh_key(size_key_has_encrypted, size_interval):
    if size_interval - size_key_has_encrypted <= 0:
        return True
    return size_key_has_encrypted % size_interval == 0


def get_key_index(block_number, refresh_interval):
    return block_number // refresh_interval


def encrypt_chunk(chunk, key):
    if chunk["size"] > refresh_interval_from_size:
        return  # this would be an error i think

    return encryption_module.encrypt_AES256(chunk["data"], key)


def encrypt_all_chunks(chunks, keys):
    encrypted_chunks = []
    encrypted_data_size = 0
    key_index = 0

    for chunk in chunks:
        total_current_size = encrypted_data_size + chunk["size"]
        if refresh_key(total_current_size, refresh_interval_from_size):
            key_index += 1
            encrypted_data_size = 0  # reset size counter after key refresh

        current_key = keys[key_index]
        encrypted_data = encryption_module.encrypt_AES256(chunk["data"], current_key)
        if not encrypted_data:
            encrypted_chunks.append(
                {
                    "id": chunk["id"],
                    "data": None,
                }
            )
        else:
            encrypted_data_size += chunk["size"]
            encrypted_chunks.append(
                {
                    "id": chunk["id"],
                    "data": encrypted_data,
                }
            )

    return encrypted_chunks
