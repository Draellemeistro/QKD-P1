import threading
import queue
import time
from src.app.kms_api import new_key


class KeyFetcher:
    """
    KMS Client-Side Buffer.
    Background thread that pre-fetches keys so the Sender never waits.
    """

    def __init__(self, receiver_id, buffer_size=5):
        self.receiver_id = receiver_id
        self.queue = queue.Queue(maxsize=buffer_size)
        self.running = True

        # Start background worker
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
        print(f" [KeyFetcher] Background thread started for Site: {receiver_id}")

    def _worker(self):
        while self.running:
            try:
                # 1. If queue full, sleep briefly to save CPU
                if self.queue.full():
                    time.sleep(0.005)
                    continue

                # 2. Fetch from KMS (This is where the 15ms wait happens)
                key_data = new_key(self.receiver_id)

                # 3. Add to buffer
                self.queue.put(key_data)

            except Exception as e:
                # Log error but retry
                print(f" [KeyFetcher] Error: {e}")
                time.sleep(1)

    def get_next_key(self):
        """Returns a key instantly from memory."""
        # Blocks ONLY if the KMS is physically too slow (Buffer Empty)
        return self.queue.get()

    def stop(self):
        self.running = False
        self.thread.join(timeout=1.0)