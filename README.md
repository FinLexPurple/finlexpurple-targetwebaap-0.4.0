# FinLexPurple 0.4.0 — Deliberately Vulnerable Test Target

> **WARNING: DELIBERATELY VULNERABLE. LOCAL USE ONLY.**
> This application contains intentional security flaws (client-trusted price
> tampering, an unsigned payment webhook, and several misconfigurations). It
> exists **only** to QA and demo the **FinLexPurple 0.4.0** scanner on your own
> machine.
>
> - It binds to **`127.0.0.1` (localhost) by default** — never `0.0.0.0`.
> - **Do NOT deploy it to a public or shared server**, a VM with a public IP, a
>   container exposed to a network, or any environment reachable by others.
> - It is a **fictional** "FLP Demo Shop" — not a real shop or payment provider.
>   Do not use it to impersonate any real organization.

> **Status: skeleton + two verified surfaces.** The recorded scan
> (`reports/scan-0.4.0.md`) is produced later, when this target is scanned with
> the CLI during integration. `reports/` is a placeholder until then.

---

## Purpose

`finlexpurple-targetwebaap-0.4.0` is a small, self-contained, fintech-flavored
web app (a fake subscription shop with a payment callback) used as a
**versioned, deliberately vulnerable target** to test the FinLexPurple scanner
**before the 0.4.0 release**. It is a standalone Flask app that the CLI scans
over HTTP; it does not import `finlexpurple`.

### Why a separate versioned target per release?

Each FinLexPurple release gets its own pinned target repo (this one tracks
**0.4.0**). Keeping a frozen target per version lets us build a **repeatable
test-dataset over time**: the planted vulnerabilities, seed data, and endpoints
don't drift, so a scan of this target should produce the **same findings every
run**. That makes it possible to:

- confirm a release still detects (and *verifies*) the vulnerability classes it
  claims to,
- catch regressions between releases by diffing scan output against the
  expected results below, and
- demo the scanner against a known-good, reproducible target.

0.4.0 focuses on the **financial** classes the `cashier` agent verifies:
`price_tampering` and `webhook_bypass`.

---

## Stack

- **Python 3 + Flask** (web app), **SQLite** (seeded, durable order state).
  `requests` is pinned to match the 0.3.0 target's dependency set. Minimal
  dependencies, one command to run.

---

## Install & run (localhost only)

```bash
# From the repository root:
./run.sh
```

That creates a local virtualenv, installs dependencies, seeds the database, and
serves the app at **http://127.0.0.1:5000/**. Every start re-seeds the database,
so each scan begins from the same state.

Or run it manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py        # serves on http://127.0.0.1:5000/
```

Optional environment overrides (defaults keep it on localhost):

| Variable          | Default       | Notes                                   |
|-------------------|---------------|-----------------------------------------|
| `FLP_TARGET_HOST` | `127.0.0.1`   | **Keep as localhost.** Never `0.0.0.0`. |
| `FLP_TARGET_PORT` | `5000`        | Change if the port is busy.             |
| `FLP_TARGET_DB`   | `./target.db` | SQLite file path.                       |

### Seeded demo data (deterministic)

| Table      | Row                                                          |
|------------|--------------------------------------------------------------|
| `products` | `FLP-PRO-12M` — "FLP Demo Pro plan (12 months)", list price `49.99` |
| `orders`   | `ord-1001` — the demo cart (no owner, coupon NULL), sku `FLP-PRO-12M`, amount `49.99`, status `pending` |
| `orders`   | `ord-alice-0001` — owner `alice`, amount `49.99`, status `paid` (Scope 3) |
| `orders`   | `ord-bob-0001` — owner `bob`, amount `49.99`, status `paid` (Scope 3) |
| `orders`   | `ord-status-0001` — no owner, amount `49.99`, status `pending` (Scope 5) |
| `orders`   | `ord-refund-0001` — no owner, amount `49.99`, status `paid`, refunded `0.00` (Scope 6) |
| `orders`   | `ord-voucher-0001` — no owner, single-use voucher, `voucher_value` `20.00`, `applied_count` `0`, `credit` `0.00` (Scope 7) |
| `users`    | `alice`, `bob` — the two seeded account logins (Scope 3) |

`webhook_events` starts empty. No order `flp-webhook-probe-0001` exists until a
callback creates it.

---

## Scope manifest (authoritative)

Each scope is independently reachable and discoverable by a crawler starting at
the site root (`/`). Recon does not submit forms, so every POST surface is
exposed as a real `<form>` whose `action` and input names the crawler can read.

| Scope | CLI agent / class | Expected verdict | Endpoint contract |
|-------|-------------------|------------------|-------------------|
| **1 — Checkout** | `cashier` / `price_tampering` | **`VERIFIED`** | Root links to `/checkout`. The page has `<form method="post" action="/checkout">` with an input named exactly **`amount`** (plus `sku`). The server reads `amount` from the query string **or** the form body, **trusts it, and persists it** to order `ord-1001` without recomputing from the list price. Submitting `amount=0.01` reflects `0.01` in the response; a later **bare `GET /checkout`** (no params) still shows `0.01`. That bare-GET read-back is what the CLI's `charge_confirmer` reads. |
| **2 — Payment webhook + order-status oracle** | `cashier` / `webhook_bypass` | **`VERIFIED`** (with the order-status read-back pointed at `/orders/flp-webhook-probe-0001`) | Root links to `/developers` ("Developer / Integrations"), which lists the callback URL `/payment/webhook` and a "Send a test event" `<form method="post" action="/payment/webhook">`. **`POST /payment/webhook`** does **not** validate `X-Signature`: the forged request below returns **HTTP 200** and the server **upserts** order `flp-webhook-probe-0001` with status `paid`. `GET /payment/webhook` returns **405** — the webhook never reflects order state. The **separate** read-back is **`GET /orders/<order_id>`**, which shows the order id and its status (404 without echoing the id when the order does not exist). |
| **3 — Order IDOR (two sessions)** | `cashier` / `order_idor` | **`VERIFIED`** (with two sessions configured via `FLP_IDOR_IDENTITIES`) | Root links to `/login` (`<form method="post" action="/login">`, input `user` = `alice` or `bob`), which sets a signed-cookie session. **`GET /account/orders/<id>`** requires a session but performs **no per-object ownership check**, so Bob (logged in) reads Alice's `ord-alice-0001` and gets her **exact** object. The CLI verifies by reading the same id under both sessions: identical owner-view bytes ⇒ cross-account read reproduced. The owner-scoped **`GET /account/orders`** (lists only the caller's own ids) is the negative control — a client never sees another user's ids there. Anonymous access to `/account/orders/<id>` is `401`. |
| **4 — Coupon abuse** | `cashier` / `coupon_abuse` | **`VERIFIED`** (with the order-status read-back pointed at `/orders/ord-1001`) | Root links to `/cart/coupon` (`<form method="post" action="/cart/coupon">`, input `code`). **`POST /cart/coupon`** **trusts any client-supplied coupon code** it never issued: it returns **HTTP 200**, drops the cart order `ord-1001` total to `0.00`, and **persists the code** on the order. The **separate** read-back is **`GET /orders/ord-1001`**, which shows the applied `coupon`. The CLI applies a distinctive bogus code behind the gate and verifies via that read-back: the bogus code recorded on the persisted order ⇒ illegitimate discount reproduced. Without the order-status read-back the verdict is `INCONCLUSIVE`, not `VERIFIED`. |
| **5 — Payment-status trust** | `cashier` / `payment_status_trust` | **`VERIFIED`** (with the order-status read-back pointed at `/orders/ord-status-0001`) | Root links to `/orders/ord-status-0001/status` (`<form method="post" action="/orders/ord-status-0001/status">`, input `status`). **`POST /orders/<id>/status`** **trusts a client-supplied `status`** and persists it to the order with **no settlement** and no server check — so a client marks the pending `ord-status-0001` **`paid`**. This is the app's **own** status field, distinct from the Scope-2 webhook callback. The **separate** read-back is **`GET /orders/ord-status-0001`**, which shows the order durably `paid`. The CLI sets `status=paid` behind the gate and verifies via that read-back. Without the order-status read-back the verdict is `INCONCLUSIVE`, not `VERIFIED`. |
| **6 — Refund abuse** | `cashier` / `refund_abuse` | **`VERIFIED`** (with the order-status read-back pointed at `/orders/ord-refund-0001`) | Root links to `/orders/ord-refund-0001/refund` (`<form method="post" action="/orders/ord-refund-0001/refund">`, input `amount`). **`POST /orders/<id>/refund`** **trusts a client-supplied `amount`** and **adds** it to the order's durable `refunded` total with **no amount check** (the refund may exceed what was paid) and **no idempotency key** (the same refund re-applies and stacks) — so a client refunds `999.99` against the `49.99` paid `ord-refund-0001`, and a replayed refund stacks further. The **separate** read-back is **`GET /orders/ord-refund-0001`**, which exposes the durable `amount` and `refunded` as `data-refund-amount` / `data-refund-refunded` tokens. The CLI issues an over-refund behind the gate and verifies via that read-back, **comparing `refunded` against `amount` itself** (the tool, not the app, owns the verdict): `refunded > amount` ⇒ durable over-refund reproduced. Without the order-status read-back the verdict is `INCONCLUSIVE`, not `VERIFIED`. |
| **7 — Race condition** | `cashier` / `race_condition` | **`INCONCLUSIVE`** (expected — a human-review lead; **never a forced `VERIFIED`**) | Root links to `/orders/ord-voucher-0001/redeem` (`<form method="post" action="/orders/ord-voucher-0001/redeem">`). **`POST /orders/<id>/redeem`** redeems a **single-use** store-credit voucher behind a **check-then-act** guard: it reads `applied_count` and, only while it is `0`, grants `voucher_value` and increments the count. **Sequentially this is single-use** — a second redeem returns **409**. But the check and the act are **not atomic** and there is **no lock or idempotency key**, so two **concurrent** redeems can both read `applied_count==0`, both pass the guard, and both grant credit (`applied_count` → `2`). The **separate** read-back is **`GET /orders/ord-voucher-0001`**, which exposes `applied_count` as the `data-race-applied` token. The CLI runs a **bounded, gated, rate-limited** concurrent burst and verifies via that read-back, **owning the verdict itself** (`applied_count >= 2` ⇒ double-processing). A genuine race is **non-deterministic** (and the single-threaded dev server usually serializes the burst), so the honest verdict is **`INCONCLUSIVE`** — a lead a human must pursue, **not** evidence the race is absent and **not** an auto-`VERIFIED`. The code-level check-then-act flaw is real regardless. |

Forged request the CLI sends for scope 2 (match exactly):

```
POST /payment/webhook
Content-Type: application/json
X-Signature: invalid-not-a-real-hmac

{"amount": "0.00", "event": "payment_intent.succeeded", "order_id": "flp-webhook-probe-0001", "status": "paid"}
```

Response: `200 OK`, `{"order_id": "flp-webhook-probe-0001", "received": true, "signature_checked": false}`.
Afterwards `GET /orders/flp-webhook-probe-0001` shows `flp-webhook-probe-0001`
and status `paid`.

> **Read-back note.** The order-status oracle is a different URL from the
> webhook. The CLI must be pointed at it (the planned `--order-status-url`
> option). A read-back of the webhook URL itself gets `405`, so without the
> order-status read-back the CLI cannot confirm paid state and the expected
> verdict is `INCONCLUSIVE`, not `VERIFIED`.

### PLANNED (not built in this version yet)

| Planned surface | CLI agent / class | Expected verdict | Purpose |
|-----------------|-------------------|------------------|---------|
| Reflected XSS web surface | `hunter` / web class | to be set when built | So full delegation selects `[hunter, cashier]`. (Order IDOR is now built as Scope 3 above, as the financial `order_idor` class.) |
| `/graphql` stub | none (no specialist) | `CapabilityGap` surfaced | Demonstrates the selector reporting a capability gap. |
| Secure checkout (server-recomputed price) | `cashier` / `price_tampering` | `NOT_REPRODUCED` / `INCONCLUSIVE` | Negative control: the tampered amount is rejected or not persisted. |
| Secure webhook (signature-verified) | `cashier` / `webhook_bypass` | `NOT_REPRODUCED` | Negative control: the forged callback is rejected. |

### Reported-only (shows as `[REPORTED]`, not verified)

| Class | Where |
|-------|-------|
| **Debug mode enabled** | Flask runs with `debug=True` (Werkzeug debugger / tracebacks). |
| **Missing security headers** | No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, or `Referrer-Policy`. |
| **Weak session secret** | Hardcoded `app.secret_key`. |

---

## Quick manual checks

Start from a fresh seed (`./run.sh`), then in another terminal:

```bash
# Scope 1 — tamper the amount, then read it back with a bare GET:
curl -s -X POST "http://127.0.0.1:5000/checkout?amount=0.01" | grep "amount-due"
curl -s "http://127.0.0.1:5000/checkout" | grep "amount-due"

# Scope 2 — forge an unsigned 'paid' callback, then read the order status:
curl -s -X POST http://127.0.0.1:5000/payment/webhook \
  -H 'Content-Type: application/json' \
  -H 'X-Signature: invalid-not-a-real-hmac' \
  --data '{"amount": "0.00", "event": "payment_intent.succeeded", "order_id": "flp-webhook-probe-0001", "status": "paid"}'
curl -s http://127.0.0.1:5000/orders/flp-webhook-probe-0001 | grep -E "order-id|order-status"

# Scope 3 — order IDOR: Bob logs in and reads Alice's order (cross-account):
curl -s -c alice.cookies -X POST http://127.0.0.1:5000/login -d 'user=alice' >/dev/null
curl -s -c bob.cookies   -X POST http://127.0.0.1:5000/login -d 'user=bob'   >/dev/null
curl -s -b alice.cookies http://127.0.0.1:5000/account/orders/ord-alice-0001   # owner view
curl -s -b bob.cookies   http://127.0.0.1:5000/account/orders/ord-alice-0001   # IDOR: same bytes
curl -s -b bob.cookies   http://127.0.0.1:5000/account/orders                  # owner-scoped: bob only
curl -s http://127.0.0.1:5000/account/orders/ord-alice-0001                    # anon -> 401

# Scope 4 — coupon abuse: a bogus coupon is trusted, then read back on the order:
curl -s -X POST http://127.0.0.1:5000/cart/coupon -d 'code=FLP-BOGUS-COUPON'    # 200, applied
curl -s http://127.0.0.1:5000/orders/ord-1001 | grep -E "order-coupon|Amount"  # shows the bogus coupon + 0.00

# Scope 5 — payment-status trust: client marks an unpaid order 'paid', read back:
curl -s -X POST http://127.0.0.1:5000/orders/ord-status-0001/status -d 'status=paid'  # 200, status set
curl -s http://127.0.0.1:5000/orders/ord-status-0001 | grep -E "order-status"          # shows 'paid'

# Scope 6 — refund abuse: client over-refunds a paid order (999.99 vs 49.99 paid), read back:
curl -s -X POST http://127.0.0.1:5000/orders/ord-refund-0001/refund -d 'amount=999.99'  # 200, refunded
curl -s http://127.0.0.1:5000/orders/ord-refund-0001 | grep -E "data-refund-"            # refunded 999.99 > amount 49.99

# Scope 7 — race condition: single-use voucher is guarded SEQUENTIALLY; a second
# redeem is rejected, so a sequential check reads applied_count 1 (NOT a double-spend).
# Double-processing requires true concurrency (and usually the dev server serializes it),
# which is why the scanner's honest verdict is INCONCLUSIVE, not VERIFIED:
curl -s -X POST http://127.0.0.1:5000/orders/ord-voucher-0001/redeem                      # 200, redeemed (applied_count 1)
curl -s -X POST http://127.0.0.1:5000/orders/ord-voucher-0001/redeem                      # 409, already redeemed
curl -s http://127.0.0.1:5000/orders/ord-voucher-0001 | grep -E "data-race-applied"       # applied_count 1 (single-use held)
```

Expected: both checkout lines show `$0.01`; the webhook returns `"received": true`;
the order page shows `flp-webhook-probe-0001` and `paid`. For Scope 3, Bob's read of
`ord-alice-0001` returns the **same** JSON as Alice's own view (the IDOR), while
`GET /account/orders` lists only the caller's own ids and the anonymous read is `401`.
For Scope 4, `GET /orders/ord-1001` shows the applied `FLP-BOGUS-COUPON` and amount `0.00`.
For Scope 5, `GET /orders/ord-status-0001` shows status `paid` after the client set it.
For Scope 6, `GET /orders/ord-refund-0001` shows `data-refund-refunded="999.99"` against
`data-refund-amount="49.99"` — a durable over-refund — after the client refund.
For Scope 7, a **sequential** redeem then a second redeem returns `409`, so
`GET /orders/ord-voucher-0001` shows `data-race-applied="1"` — the single-use guard held.
Double-processing (`applied_count >= 2`) only occurs under true concurrency and is
non-deterministic, so the scanner honestly reports `INCONCLUSIVE` (a human-review lead),
never a forced `VERIFIED`.

---

## Expected FinLexPurple 0.4.0 scan results

Real recon output (the CLI's own crawler, run against this target from `/`):

```
Recon: discovered 7 endpoints.
  GET http://127.0.0.1:5000/
  GET http://127.0.0.1:5000/checkout
  GET http://127.0.0.1:5000/developers
  GET http://127.0.0.1:5000/orders/ord-1001
  GET http://127.0.0.1:5000/payment/webhook
  POST http://127.0.0.1:5000/checkout params=amount,sku
  POST http://127.0.0.1:5000/payment/webhook params=event,order_id,status
```

The expected `[VERIFIED]` set is **`price_tampering` (`POST /checkout`, `amount`)
+ `webhook_bypass` (`POST /payment/webhook`)**, both from the `cashier` agent.
Both replays are state-changing, so they run only when the approval gate allows
them (`REQUIRE_HUMAN_APPROVAL=false` for the standard-gate `cashier` agent);
with the default gate they pause and stay `[REPORTED]`. The full scan summary
and finding count will be recorded in `reports/scan-0.4.0.md` from a real run.

---

## License / disclaimer

For local security testing and education only. You are responsible for running
it in an isolated, localhost-only environment. The authors accept no liability
for misuse.
