import threading
import queue
import time
import datetime
from src.app.kms_api import new_key

class KeyFetcher:
    """
    KMS Client-Side Buffer.
    Background thread that pre-fetches keys so the Sender never waits.
    """
    def __init__(self, receiver_id, buffer_size=100):
        self.receiver_id = receiver_id
        self.queue = queue.Queue(maxsize=buffer_size)
        self.running = True
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
        print(f" [KeyFetcher] Background thread started for Site: {receiver_id}")

    def _worker(self):
        while self.running:
            try:
                if self.queue.full():
                    time.sleep(0.005)
                    continue

                start_time = time.time()
                key_data = new_key(self.receiver_id)
                duration = time.time() - start_time

                # Only log if the KMS is slow enough to threaten the pipeline (>100ms)
                if duration > 0.1:
                    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    print(f"[{timestamp}] [WARNING] Slow KMS Request: {duration:.4f}s")

                self.queue.put(key_data)
            except Exception as e:
                print(f" [KeyFetcher] Error: {e}")
                time.sleep(1)

    def get_next_key(self):
        """Returns a key instantly from memory."""
        return self.queue.get()

    def stop(self):
        self.running = False
        self.thread.join(timeout=1.0)