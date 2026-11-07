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
    session,
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

# The dedicated paid order the refund endpoint (Scope 6) refunds. Deterministic id
# so the refund-status read-back always reads the same durable row.
REFUND_ORDER_ID = "ord-refund-0001"


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
        DROP TABLE IF EXISTS users;

        CREATE TABLE products (
            sku TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            list_price TEXT NOT NULL
        );

        CREATE TABLE orders (
            id TEXT PRIMARY KEY,
            sku TEXT NOT NULL,
            amount TEXT NOT NULL,
            status TEXT NOT NULL,
            -- Nullable: the public demo cart and webhook-created orders have no
            -- owner; the per-user account orders (Scope 3) are owned by a user.
            owner TEXT,
            -- Scope 4 (coupon_abuse): the client-supplied coupon code applied to
            -- the cart, trusted and persisted here; NULL until one is applied.
            coupon TEXT,
            -- Scope 6 (refund_abuse): the order's durable refunded total. The refund
            -- endpoint ADDS the client amount here with no amount/idempotency check,
            -- so it can grow past `amount` (an over-refund). Defaults to 0.00.
            refunded TEXT NOT NULL DEFAULT '0.00'
        );

        CREATE TABLE users (
            username TEXT PRIMARY KEY
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
        "INSERT INTO orders (id, sku, amount, status, owner) VALUES (?,?,?,?,?)",
        [
            # The demo cart the checkout page reads and writes (no owner).
            (CART_ORDER_ID, "FLP-PRO-12M", "49.99", "pending", None),
            # Scope 3 (order_idor): per-user account orders. Alice's order is
            # readable by Bob through the planted missing per-object authz.
            ("ord-alice-0001", "FLP-PRO-12M", "49.99", "paid", "alice"),
            ("ord-bob-0001", "FLP-PRO-12M", "49.99", "paid", "bob"),
            # Scope 5 (payment_status_trust): a dedicated order whose status the
            # client can set directly (no settlement), separate from the cart.
            ("ord-status-0001", "FLP-PRO-12M", "49.99", "pending", None),
            # Scope 6 (refund_abuse): a dedicated PAID order (refunded 0.00 by the
            # column default) the refund endpoint can over-refund past its amount.
            ("ord-refund-0001", "FLP-PRO-12M", "49.99", "paid", None),
        ],
    )
    db.executemany(
        "INSERT INTO users (username) VALUES (?)",
        [("alice",), ("bob",)],
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


@app.route("/cart/coupon", methods=["GET", "POST"])
def cart_coupon():
    # SCOPE 4 (coupon_abuse): a client-supplied coupon code is TRUSTED and applied
    # to the cart order with NO validation that the code was ever issued — any
    # code drops the total to 0.00 and is persisted. GET shows a real <form> so a
    # crawler discovers POST /cart/coupon with input name 'code'. The durable
    # effect is read back via the separate order-status oracle GET /orders/ord-1001.
    db = get_db()
    code = request.values.get("code")
    applied = code is not None and code != ""
    if applied:
        db.execute(
            "UPDATE orders SET coupon = ?, amount = ? WHERE id = ?",
            (code, "0.00", CART_ORDER_ID),
        )
        db.commit()
        if request.method == "POST":
            return jsonify({"applied": True, "coupon": code, "order_id": CART_ORDER_ID}), 200
    order = get_order(CART_ORDER_ID)
    return render_template("cart.html", order=order, applied=applied)


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
    # PUBLIC on purpose (Scopes 1-2 read it back without a session); this is NOT
    # the Scope-3 IDOR surface, which is the authenticated /account/orders/<id>.
    order = get_order(order_id)
    if order is None:
        abort(404)
    return render_template("order.html", order=order)


@app.route("/orders/<order_id>/status", methods=["GET", "POST"])
def order_set_status(order_id):
    # SCOPE 5 (payment_status_trust): the order's OWN status endpoint TRUSTS a
    # client-supplied `status` and persists it to the order with NO settlement and
    # no server-side check — so a client can mark an unpaid order `paid`. This is
    # the app's own status parameter, distinct from the Scope-2 webhook callback.
    # GET shows a real <form> so a crawler discovers POST /orders/<id>/status with
    # input name `status`. The durable effect is read back via GET /orders/<id>.
    db = get_db()
    order = get_order(order_id)
    if order is None:
        abort(404)
    status = request.values.get("status")
    applied = status is not None and status != ""
    if applied:
        db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
        db.commit()
        if request.method == "POST":
            return jsonify({"updated": True, "order_id": order_id, "status": status}), 200
        order = get_order(order_id)
    return render_template("status.html", order=order, applied=applied)


@app.route("/orders/<order_id>/refund", methods=["GET", "POST"])
def order_refund(order_id):
    # SCOPE 6 (refund_abuse): the refund endpoint TRUSTS a client-supplied `amount`
    # and ADDS it to the order's durable `refunded` total with NO amount check (the
    # refund may exceed what was paid) and NO idempotency key (the same refund
    # re-applies and stacks). So a client can refund more than the amount paid, and
    # a replayed refund stacks further. GET shows a real <form> so a crawler
    # discovers POST /orders/<id>/refund with input name `amount`. The durable
    # effect (refunded > amount) is read back via GET /orders/<id>.
    db = get_db()
    order = get_order(order_id)
    if order is None:
        abort(404)
    amount = request.values.get("amount")
    applied = amount is not None and amount != ""
    if applied:
        try:
            new_refunded = float(order["refunded"]) + float(amount)
            db.execute(
                "UPDATE orders SET refunded = ? WHERE id = ?",
                (f"{new_refunded:.2f}", order_id),
            )
            db.commit()
        except (TypeError, ValueError):
            pass  # non-numeric refund amount: ignore, keep the durable value
        order = get_order(order_id)
        if request.method == "POST":
            return jsonify({
                "refunded": True, "order_id": order_id,
                "amount": amount, "refunded_total": order["refunded"],
            }), 200
    return render_template("refund.html", order=order, applied=applied)


# --- Scope 3 (order_idor): authenticated account orders --------------------
# Two seeded users (alice, bob). Logging in sets a signed-cookie session. The
# per-user order resource below is addressable by id and, by design, performs NO
# per-object ownership check — so a logged-in Bob can read Alice's order. The
# order-list endpoint IS owner-scoped (the negative control), and is how a
# legitimate client would discover only its own ids.
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = (request.values.get("user") or "").strip().lower()
        if user not in ("alice", "bob"):
            abort(401)
        session["user"] = user
        return jsonify({"logged_in_as": user})
    # A real <form> so a crawler starting at / discovers the POST surface.
    return (
        "<!doctype html><title>Account login</title><h1>Account login</h1>"
        "<form method='post' action='/login'>"
        "<input name='user' placeholder='alice or bob'>"
        "<button type='submit'>Log in</button></form>",
        200,
        {"Content-Type": "text/html; charset=utf-8"},
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"logged_out": True})


@app.route("/account/orders")
def account_orders():
    # Negative control: owner-scoped. Returns ONLY the logged-in user's order
    # ids — a legitimate client never sees another user's ids here.
    user = session.get("user")
    if not user:
        abort(401)
    rows = get_db().execute("SELECT id FROM orders WHERE owner = ?", (user,)).fetchall()
    return jsonify({"user": user, "orders": [row["id"] for row in rows]})


@app.route("/account/orders/<order_id>")
def account_order(order_id):
    # PLANTED IDOR (Scope 3): requires a session, but performs NO per-object
    # ownership check — any authenticated user may read ANY order by id. The
    # response is deterministic per order (same bytes whoever reads it), so a
    # cross-account read returns the owner's exact object.
    if not session.get("user"):
        abort(401)
    order = get_order(order_id)
    if order is None:
        abort(404)
    return jsonify({
        "id": order["id"], "owner": order["owner"], "sku": order["sku"],
        "amount": order["amount"], "status": order["status"],
    })


if __name__ == "__main__":
    init_db()
    # VULN (REPORTED-only): debug=True exposes the Werkzeug debugger and verbose
    # tracebacks. Host defaults to 127.0.0.1 — localhost only. Never 0.0.0.0.
    print(" * FinLexPurple 0.4.0 TARGET — deliberately vulnerable, localhost only")
    print(" * Serving on http://%s:%s/  (do NOT expose publicly)" % (HOST, PORT))
    app.run(host=HOST, port=PORT, debug=True)
