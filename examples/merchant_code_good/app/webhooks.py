import hashlib
import hmac
import os

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]


def handle_webhook(raw_body: bytes, signature: str, timestamp: str):
    expected = hmac.new(WEBHOOK_SECRET.encode(), f"{timestamp}.".encode() + raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return 401
    return 200
