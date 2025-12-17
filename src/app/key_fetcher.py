import threading
import queue
import time
from src.app.kms_api import new_key


class KeyFetcher:
    """
    KMS Client-Side Buffer.

    Role:
      - Runs a background thread to pre-fetch keys using the existing kms_api.
      - Stores them in a thread-safe Queue.
      - Allows the Sender to get keys with 0ms latency.
    """

    def __init__(self, receiver_id, buffer_size=5):
        self.receiver_id = receiver_id
        self.queue = queue.Queue(maxsize=buffer_size)
        self.running = True

        # Start the background worker
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
        print(f" [KeyFetcher] Background thread started for Site: {receiver_id}")

    def _worker(self):
        """Constantly tries to keep the queue full."""
        while self.running:
            try:
                # 1. If queue is full, wait (prevent CPU spinning)
                if self.queue.full():
                    time.sleep(0.005)
                    continue

                # 2. Call your existing API (This is where the 15ms-40ms wait happens)
                #    The background thread waits here, so the Main Thread doesn't have to.
                key_data = new_key(self.receiver_id)

                # 3. Add to buffer
                self.queue.put(key_data)

            except Exception as e:
                # Log error but keep retrying (connection might be temporarily down)
                # We use a short sleep to avoid flooding logs/network on failure
                print(f" [KeyFetcher] Fetch Error: {e}")
                time.sleep(1)

    def get_next_key(self):
        """
        Called by the Sender.
        Returns a key immediately from memory.
        """
        # .get() blocks ONLY if the queue is empty (True Physics Limit)
        return self.queue.get()

    def stop(self):
        """Stops the background thread gracefully."""
        self.running = False
        self.thread.join(timeout=1.0)