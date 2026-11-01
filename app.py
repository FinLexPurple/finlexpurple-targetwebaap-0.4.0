"""
FinLexPurple 0.4.0 — Deliberately Vulnerable Test Target
========================================================

A small, self-contained, fintech-flavored demo web app used ONLY to QA and demo
the FinLexPurple 0.4.0 scanner on localhost. It is INTENTIONALLY INSECURE.

SAFETY:
  * Binds to 127.0.0.1 (localhost) by default. Do NOT bind to 0.0.0.0.
  * Do NOT deploy this to a public server. Run it locally only.

The vulnerabilities below are planted on purpose so the scanner can find and
verify them. See README.md for the scope manifest (scope -> CLI agent/class ->
expected verdict -> endpoint contract).
"""

import os
import sqlite3

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    render_template,
    request,
)

# --- Configuration ---------------------------------------------------------
# Localhost only by default. Overridable via env for advanced local testing,
# but the default MUST remain 127.0.0.1 (see README safety notes).
HOST = os.environ.get("FLP_TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLP_TARGET_PORT", "5000"))
DB_PATH = os.environ.get("FLP_TARGET_DB", os.path.join(os.path.dirname(__file__), "target.db"))

app = Flask(__name__)
# Weak, hardcoded secret (REPORTED-only finding: insecure session config).
app.secret_key = "flp-0.4.0-demo-secret"

# The single demo cart the checkout page operates on. Deterministic id so the
# bare-GET read-back always reads the same durable row.
CART_ORDER_ID = "ord-1001"


# --- Database helpers ------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create schema and seed deterministic demo data (idempotent)."""
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS webhook_events;

        CREATE TABLE products (
            sku TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            list_price TEXT NOT NULL
        );

        CREATE TABLE orders (
            id TEXT PRIMARY KEY,
            sku TEXT NOT NULL,
            amount TEXT NOT NULL,
            status TEXT NOT NULL
        );

        CREATE TABLE webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT NOT NULL,
            event TEXT NOT NULL,
            status TEXT NOT NULL,
            amount TEXT NOT NULL,
            signature TEXT NOT NULL
        );
        """
    )
    # Deterministic seed data so scans are repeatable.
    db.executemany(
        "INSERT INTO products (sku, name, list_price) VALUES (?,?,?)",
        [
            ("FLP-PRO-12M", "FLP Demo Pro plan (12 months)", "49.99"),
        ],
    )
    db.executemany(
        "INSERT INTO orders (id, sku, amount, status) VALUES (?,?,?,?)",
        [
            # The demo cart the checkout page reads and writes.
            (CART_ORDER_ID, "FLP-PRO-12M", "49.99", "pending"),
        ],
    )
    db.commit()
    db.close()


# --- Security misconfig (REPORTED-only) ------------------------------------
@app.after_request
def no_security_headers(resp):
    """
    Intentionally does NOT set common security headers
    (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
    Strict-Transport-Security, Referrer-Policy). Leave them absent so the
    scanner reports the missing-headers misconfiguration.
    """
    resp.headers["Server"] = "FinLexPurple-Target/0.4.0"
    return resp


def get_order(order_id):
    return get_db().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()


# --- Routes ----------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    # SCOPE 1 (price_tampering): the client-supplied 'amount' is TRUSTED and
    # PERSISTED to the cart order as-is — the server never recomputes it from
    # the product's list price. Read from query OR form so a single-parameter
    # probe (e.g. POST /checkout?amount=0.01) reaches the sink.
    db = get_db()
    amount = request.values.get("amount")
    submitted = amount is not None and amount != ""
    if submitted:
        db.execute("UPDATE orders SET amount = ? WHERE id = ?", (amount, CART_ORDER_ID))
        db.commit()
    # A bare GET (no params) reads the durable row back, so a tampered amount
    # is still shown after the fact.
    order = get_order(CART_ORDER_ID)
    product = db.execute("SELECT * FROM products WHERE sku = ?", (order["sku"],)).fetchone()
    return render_template("checkout.html", order=order, product=product, submitted=submitted)


@app.route("/developers")
def developers():
    # Developer / Integrations page: lists the payment callback URL and a
    # "send test event" form so a crawler discovers POST /payment/webhook.
    webhook_url = request.url_root.rstrip("/") + "/payment/webhook"
    return render_template("developers.html", webhook_url=webhook_url)


@app.route("/payment/webhook", methods=["POST"])
def payment_webhook():
    # SCOPE 2 (webhook_bypass): the X-Signature header is recorded but NEVER
    # validated, so any caller can forge a "paid" callback. The event is
    # trusted and the order is UPSERTED with the claimed status — including
    # order ids the shop never created. GET is not routed here (405), so this
    # endpoint never reflects order state; read it back via /orders/<id>.
    payload = request.get_json(silent=True, force=True)
    if not isinstance(payload, dict):
        # Fallback for the form-encoded "send test event" form.
        payload = request.form.to_dict()
    order_id = str(payload.get("order_id", "")).strip()
    if not order_id:
        return jsonify({"received": False, "error": "order_id is required"}), 400
    event = str(payload.get("event", ""))
    status = str(payload.get("status", ""))
    amount = str(payload.get("amount", ""))
    signature = request.headers.get("X-Signature", "")

    db = get_db()
    db.execute(
        "INSERT INTO webhook_events (order_id, event, status, amount, signature) VALUES (?,?,?,?,?)",
        (order_id, event, status, amount, signature),
    )
    if get_order(order_id) is None:
        db.execute(
            "INSERT INTO orders (id, sku, amount, status) VALUES (?,?,?,?)",
            (order_id, "UNKNOWN", amount, status),
        )
    else:
        db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    db.commit()
    return jsonify({"received": True, "order_id": order_id, "signature_checked": False}), 200


@app.route("/orders/<order_id>")
def order_status(order_id):
    # Separate order-status resource (the in-scope read-back oracle). Shows the
    # order id and its durable status. A missing order is a plain 404 that does
    # not echo the requested id, so the read-back cannot match on a miss.
    order = get_order(order_id)
    if order is None:
        abort(404)
    return render_template("order.html", order=order)


if __name__ == "__main__":
    init_db()
    # VULN (REPORTED-only): debug=True exposes the Werkzeug debugger and verbose
    # tracebacks. Host defaults to 127.0.0.1 — localhost only. Never 0.0.0.0.
    print(" * FinLexPurple 0.4.0 TARGET — deliberately vulnerable, localhost only")
    print(" * Serving on http://%s:%s/  (do NOT expose publicly)" % (HOST, PORT))
    app.run(host=HOST, port=PORT, debug=True)
