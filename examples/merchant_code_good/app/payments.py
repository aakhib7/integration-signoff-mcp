import os

import requests

API_KEY = os.environ["GATEWAY_API_KEY"]


def create_payment(order):
    amount_minor = order.total_paise  # integer, from our own order record
    return requests.post(
        "https://api.sandbox.examplepay.com/v1/payments",
        json={"reference_id": order.id, "amount": amount_minor},
        headers={"Idempotency-Key": order.payment_key},
        timeout=10,
    )
