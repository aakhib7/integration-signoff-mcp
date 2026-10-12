import requests

API_SECRET = "fakeSecret9f8a7b6c5d4e3f2a"


def create_payment(request):
    amount = float(request.json["amount"])
    logger.info(f"Creating payment for card_number={request.json['card_number']}")
    return requests.post("http://api.examplepay.com/v1/payments", json={"amount": amount}, verify=False)


def webhook(request):
    event = request.json
    mark_paid(event["data"]["reference_id"])
    return "ok"


def payment_return(request):
    if request.args.get("status") == "success":
        mark_paid(request.args.get("order"))
