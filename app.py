"""
CryptVault - Flask web application.

Run:  python app.py      then open http://127.0.0.1:5000
"""
from __future__ import annotations

import os
import secrets
import time
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request,
                   session, url_for)

from cryptvault.crypto_core import CryptoError
from cryptvault.passwords import analyse_strength, generate_password
from cryptvault.vault import VaultError, VaultService

BASE = os.path.dirname(os.path.abspath(__file__))
INSTANCE = os.environ.get("CRYPTVAULT_INSTANCE", os.path.join(BASE, "instance"))
os.makedirs(INSTANCE, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("CRYPTVAULT_SECRET") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_TIMEOUT_SECONDS=int(os.environ.get("CRYPTVAULT_TIMEOUT", 300)),   # auto-lock after 5 min idle
)

service = VaultService(os.path.join(INSTANCE, "cryptvault.db"),
                       os.path.join(INSTANCE, "client_state.json"))

# Unlocked vaults live ONLY in server memory, keyed by a random session token.
# The browser cookie carries the token, never the key.
UNLOCKED: dict[str, dict] = {}


# ------------------------------------------------------------------ session handling
def _drop(token):
    entry = UNLOCKED.pop(token, None)
    if entry:
        entry["vault"].lock()


@app.before_request
def load_vault():
    g.vault = None
    token = session.get("token")
    if not token or token not in UNLOCKED:
        return
    entry = UNLOCKED[token]
    if time.time() - entry["last_seen"] > app.config["SESSION_TIMEOUT_SECONDS"]:
        _drop(token)
        session.clear()
        flash("Vault auto-locked after inactivity.", "warn")
        return
    entry["last_seen"] = time.time()
    g.vault, g.username = entry["vault"], entry["username"]


@app.before_request
def csrf_protect():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    if request.method == "POST":
        sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
        # compare bytes: compare_digest raises TypeError on non-ASCII str input
        if not sent or not secrets.compare_digest(sent.encode(), session["csrf"].encode()):
            abort(400, "CSRF token missing or invalid")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self'; script-src 'self'; "
                                               "img-src 'self' data:; frame-ancestors 'none'")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def inject():
    return {"csrf_token": session.get("csrf", ""), "unlocked": g.get("vault") is not None,
            "username": g.get("username"), "timeout": app.config["SESSION_TIMEOUT_SECONDS"]}


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.vault is None:
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper


# ------------------------------------------------------------------ auth routes
@app.route("/")
def index():
    return redirect(url_for("vault") if g.vault else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        pw, confirm = request.form.get("password", ""), request.form.get("confirm", "")
        if pw != confirm:
            flash("Passwords do not match.", "error")
        elif not analyse_strength(pw)["policy_passed"]:
            flash("Master password does not meet the policy: " +
                  "; ".join(analyse_strength(pw)["feedback"]), "error")
        else:
            try:
                service.register(request.form.get("username", ""), pw)
                flash("Account created. Your vault key was generated and wrapped. Please log in.", "ok")
                return redirect(url_for("login"))
            except VaultError as exc:
                flash(str(exc), "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            t0 = time.perf_counter()
            vault = service.unlock(request.form.get("username", ""), request.form.get("password", ""))
            elapsed = (time.perf_counter() - t0) * 1000
        except (VaultError, CryptoError):
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401
        old = session.get("token")
        if old:
            _drop(old)
        session.clear()
        token = secrets.token_urlsafe(32)
        session["token"], session["csrf"] = token, secrets.token_urlsafe(32)
        UNLOCKED[token] = {"vault": vault, "username": request.form["username"].strip().lower(),
                           "last_seen": time.time()}
        flash(f"Vault unlocked (PBKDF2 + Argon2id + VMK unwrap in {elapsed:.0f} ms).", "ok")
        return redirect(url_for("vault"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    _drop(session.get("token"))
    session.clear()
    flash("Vault locked. Keys wiped from memory.", "ok")
    return redirect(url_for("login"))


# ------------------------------------------------------------------ vault routes
@app.route("/vault")
@login_required
def vault():
    q, cat = request.args.get("q", ""), request.args.get("category", "")
    entries, alerts = g.vault.list_entries(q, cat)
    return render_template("vault.html", entries=entries, alerts=alerts, q=q, category=cat,
                           categories=g.vault.categories())


@app.route("/entry/new", methods=["GET", "POST"])
@login_required
def new_entry():
    if request.method == "POST":
        try:
            g.vault.add(request.form)
            flash("Credential encrypted and saved.", "ok")
            return redirect(url_for("vault"))
        except VaultError as exc:
            flash(str(exc), "error")
    return render_template("entry.html", entry=request.form, mode="new")


@app.route("/entry/<record_id>/edit", methods=["GET", "POST"])
@login_required
def edit_entry(record_id):
    try:
        if request.method == "POST":
            g.vault.update(record_id, request.form)
            flash("Credential re-encrypted as a new version.", "ok")
            return redirect(url_for("vault"))
        entry = g.vault.get(record_id)
    except VaultError as exc:
        flash(str(exc), "error")
        return redirect(url_for("vault"))
    return render_template("entry.html", entry=entry, mode="edit")


@app.route("/entry/<record_id>/delete", methods=["POST"])
@login_required
def delete_entry(record_id):
    try:
        g.vault.delete(record_id)
        flash("Credential deleted (DELETE event appended to audit chain).", "ok")
    except VaultError as exc:
        flash(str(exc), "error")
    return redirect(url_for("vault"))


@app.route("/audit")
@login_required
def audit():
    report = g.vault.verify_integrity()
    return render_template("audit.html", report=report, events=g.vault.audit_log())


@app.route("/generator")
@login_required
def generator():
    return render_template("generator.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        new = request.form.get("new", "")
        if new != request.form.get("confirm", ""):
            flash("New passwords do not match.", "error")
        elif not analyse_strength(new)["policy_passed"]:
            flash("New master password does not meet the policy.", "error")
        else:
            try:
                service.change_master_password(g.username, request.form.get("old", ""), new)
                _drop(session.get("token"))
                session.clear()
                flash("Master password changed - only the VMK envelope was re-wrapped. Log in again.", "ok")
                return redirect(url_for("login"))
            except (VaultError, CryptoError):
                flash("Current master password is incorrect.", "error")
    return render_template("settings.html")


# ------------------------------------------------------------------ JSON APIs
@app.route("/api/generate")
def api_generate():
    a = request.args
    try:
        pw = generate_password(int(a.get("length", 20)), a.get("upper", "1") == "1",
                               a.get("lower", "1") == "1", a.get("digits", "1") == "1",
                               a.get("symbols", "1") == "1", a.get("ambiguous", "1") == "1")
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(password=pw, strength=analyse_strength(pw))


@app.route("/api/strength", methods=["POST"])
def api_strength():
    return jsonify(analyse_strength((request.get_json(silent=True) or {}).get("password", "")))


if __name__ == "__main__":
    # Bind to localhost only. Put behind TLS 1.3 (reverse proxy) for any non-local deployment.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
