# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Reference license server for online activation. Run by Aevrin, never shipped to customers.

    python src/scripts/licensing/license_server.py --key ~/.aevrin-signing/activation-2026-10.key.pem \\
        --db licenses.sqlite --port 8787
    python src/scripts/licensing/license_server.py --db licenses.sqlite --revoke L-2026-0042
    python src/scripts/licensing/license_server.py --db licenses.sqlite --list

Endpoints (JSON):
    POST   /v1/activations  {license, installation_id, product, version} -> 200 {receipt} | 403 seat limit | 410 revoked
    DELETE /v1/activations  {license, installation_id}                    -> 200 (frees the seat)

It checks the license key's signature itself, counts installations per license, and signs
receipts with the activation key. Seats not seen for SEAT_TIMEOUT_DAYS are freed, so
destroyed containers do not hold seats forever.

This is a small reference implementation with SQLite. In production put it behind a TLS
reverse proxy (the scanner only accepts https activation URLs), add rate limits, and back
up the database. The activation key lives only on this server.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mcp_scanner.licensing.crypto import sign_token
from mcp_scanner.licensing.license import check_token

RECEIPT_DAYS = 30
SEAT_TIMEOUT_DAYS = 45
DAY = 86400
SCHEMA = """
CREATE TABLE IF NOT EXISTS activations (lid TEXT, iid TEXT, first_seen INTEGER, last_seen INTEGER, version TEXT,
                                        PRIMARY KEY (lid, iid));
CREATE TABLE IF NOT EXISTS revoked (lid TEXT PRIMARY KEY, at INTEGER, reason TEXT);
"""


def open_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, check_same_thread=False)
    db.executescript(SCHEMA)
    return db


def activate(
    db: sqlite3.Connection, key: Any, kid: str, body: dict[str, Any], now: float | None = None
) -> tuple[int, dict[str, Any]]:
    """The answer to one activation request: (HTTP status, JSON body)."""
    now = int(time.time() if now is None else now)
    token, iid = body.get("license"), body.get("installation_id")
    try:
        iid = str(uuid.UUID(str(iid)))
    except ValueError:
        return 400, {"error": "installation_id must be a UUID"}
    if not isinstance(token, str):
        return 400, {"error": "license is missing"}
    check = check_token(token, str(body.get("version") or "0"), now)
    if check.state != "valid" or check.license is None:
        return 401, {"error": f"license not valid: {check.reason or check.state}"}
    lic = check.license
    if db.execute("SELECT 1 FROM revoked WHERE lid = ?", (lic.lid,)).fetchone():
        return 410, {"error": "this license was revoked"}
    with db:
        db.execute("DELETE FROM activations WHERE lid = ? AND last_seen < ?", (lic.lid, now - SEAT_TIMEOUT_DAYS * DAY))
        known = db.execute("SELECT 1 FROM activations WHERE lid = ? AND iid = ?", (lic.lid, iid)).fetchone()
        used = db.execute("SELECT COUNT(*) FROM activations WHERE lid = ?", (lic.lid,)).fetchone()[0]
        if not known and lic.seats is not None and used >= lic.seats:
            return 403, {"error": f"seat limit reached ({lic.seats}); deactivate an installation first"}
        db.execute(
            "INSERT INTO activations VALUES (?, ?, ?, ?, ?) ON CONFLICT (lid, iid) DO UPDATE SET last_seen = ?, version = ?",
            (lic.lid, iid, now, now, str(body.get("version")), now, str(body.get("version"))),
        )
        used = db.execute("SELECT COUNT(*) FROM activations WHERE lid = ?", (lic.lid,)).fetchone()[0]
    receipt = sign_token(
        {"typ": "activation", "kid": kid, "lid": lic.lid, "iid": iid, "iat": now, "exp": now + RECEIPT_DAYS * DAY,
         "seats": lic.seats, "seats_used": used},
        key,
    )  # fmt: skip
    return 200, {"receipt": receipt, "seats_used": used}


def deactivate(db: sqlite3.Connection, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    check = check_token(str(body.get("license", "")), "0")
    if check.license is None:
        return 401, {"error": "license not valid"}
    with db:
        db.execute(
            "DELETE FROM activations WHERE lid = ? AND iid = ?", (check.license.lid, str(body.get("installation_id")))
        )
    return 200, {"ok": True}


def serve(db: sqlite3.Connection, key: Any, kid: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def _answer(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict[str, Any] | None:
            size = int(self.headers.get("Content-Length") or 0)
            if self.path != "/v1/activations" or size > 64_000:
                self._answer(404, {"error": "not found"})
                return None
            try:
                data = json.loads(self.rfile.read(size) or b"{}")
            except ValueError:
                data = None
            if not isinstance(data, dict):
                self._answer(400, {"error": "send a JSON object"})
                return None
            return data

        def do_POST(self) -> None:
            body = self._body()
            if body is not None:
                self._answer(*activate(db, key, kid, body))

        def do_DELETE(self) -> None:
            body = self._body()
            if body is not None:
                self._answer(*deactivate(db, body))

    print(f"License server on http://127.0.0.1:{port} (put a TLS proxy in front of it)")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", required=True)
    parser.add_argument("--key", type=Path, help="The activation private key (PEM).")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--revoke", metavar="LID")
    parser.add_argument("--reason", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    db = open_db(args.db)
    if args.revoke:
        with db:
            db.execute("INSERT OR REPLACE INTO revoked VALUES (?, ?, ?)", (args.revoke, int(time.time()), args.reason))
        print(f"Revoked {args.revoke}. Installations stop working when their receipt and grace period end.")
        return 0
    if args.list:
        for row in db.execute("SELECT lid, COUNT(*), MAX(last_seen) FROM activations GROUP BY lid"):
            print(f"{row[0]}: {row[1]} installation(s), last seen {time.strftime('%Y-%m-%d', time.gmtime(row[2]))}")
        return 0
    if not args.key:
        parser.error("--key is required to serve")
    from issue_license import load_private_key  # same folder

    key, kid = load_private_key(args.key.expanduser())
    serve(db, key, kid, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
