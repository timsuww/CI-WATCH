import datetime
import io
import json
import re
import sqlite3
import threading
import uuid
from pathlib import Path

from flask import Flask, g, jsonify, redirect, render_template, request, url_for, send_file, abort
from xhtml2pdf import pisa

import scanner

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "ci_watch.db"

app = Flask(__name__)

SCAN_JOBS = {}
SCAN_JOBS_LOCK = threading.Lock()


ZERO_WIDTH_SPACE = "​"

# RFC 1123 hostname: labels of 1-63 alnum/hyphen chars (no leading/trailing
# hyphen), joined by dots, max 253 chars total. Rejects anything containing
# whitespace, credentials ("user@host"), ports, paths, or control characters
# that normalize_domain's string-stripping alone would silently let through.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


@app.template_filter("breaklong")
def break_long_tokens(text, maxlen=45):
    if not text:
        return text
    def _break(m):
        s = m.group(0)
        return ZERO_WIDTH_SPACE.join(s[i:i + maxlen] for i in range(0, len(s), maxlen))
    return re.sub(rf"\S{{{maxlen + 1},}}", _break, text)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            finding_counts TEXT NOT NULL,
            result_json TEXT NOT NULL,
            log_text TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def normalize_domain(raw):
    raw = raw.strip()
    raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
    raw = raw.rstrip("/")
    host = raw.split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1]  # drop any userinfo@ component
    host = host.split(":")[0]   # drop any :port component
    host = host.lower()
    if not DOMAIN_RE.match(host):
        return None
    return host


def severity_counts(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        counts[f.get("severity", "Informational")] = counts.get(f.get("severity", "Informational"), 0) + 1
    return counts


@app.route("/")
def index():
    db = get_db()
    rows = db.execute(
        "SELECT id, domain, scanned_at, finding_counts FROM scans ORDER BY id DESC LIMIT 50"
    ).fetchall()
    history = []
    for r in rows:
        history.append({
            "id": r["id"],
            "domain": r["domain"],
            "scanned_at": r["scanned_at"],
            "counts": json.loads(r["finding_counts"]),
        })
    return render_template("index.html", history=history)


def _run_scan_job(job_id, domain, login_config=None):
    log_lines = []

    def log(msg):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        log_lines.append(line)
        with SCAN_JOBS_LOCK:
            SCAN_JOBS[job_id]["log"].append(line)

    try:
        log(f"===== CI-Watch scan started for {domain} =====")
        if login_config:
            log("Authenticated scan requested (kredensial tidak ditulis ke log)")
        result = scanner.run_full_scan(
            domain, scanner.DEFAULT_HEADER_PATHS, scanner.DEFAULT_SENSITIVE_PATHS, log,
            login_config=login_config,
        )
        log(f"===== CI-Watch scan finished for {domain} =====")
        counts = severity_counts(result["findings"])

        conn = sqlite3.connect(DB_PATH)
        cur = conn.execute(
            "INSERT INTO scans (domain, scanned_at, finding_counts, result_json, log_text) VALUES (?, ?, ?, ?, ?)",
            (domain, result["scanned_at"], json.dumps(counts), json.dumps(result), "\n".join(log_lines)),
        )
        conn.commit()
        scan_id = cur.lastrowid
        conn.close()

        with SCAN_JOBS_LOCK:
            SCAN_JOBS[job_id]["status"] = "done"
            SCAN_JOBS[job_id]["scan_id"] = scan_id
    except Exception as e:
        log(f"ERROR: {e}")
        with SCAN_JOBS_LOCK:
            SCAN_JOBS[job_id]["status"] = "error"
            SCAN_JOBS[job_id]["error"] = str(e)


def _build_login_config():
    login_path = request.form.get("login_path", "").strip()
    username = request.form.get("login_username", "")
    password = request.form.get("login_password", "")
    if not (login_path and username and password):
        return None
    return {
        "login_path": login_path,
        "user_field": request.form.get("login_user_field", "").strip() or "username",
        "pass_field": request.form.get("login_pass_field", "").strip() or "password",
        "username": username,
        "password": password,
    }


@app.route("/scan", methods=["POST"])
def scan():
    domain = normalize_domain(request.form.get("domain", ""))
    if not domain:
        abort(400, "Domain tidak valid atau wajib diisi")
    login_config = _build_login_config()

    job_id = uuid.uuid4().hex
    with SCAN_JOBS_LOCK:
        SCAN_JOBS[job_id] = {"status": "running", "log": [], "scan_id": None, "error": None, "domain": domain}

    threading.Thread(target=_run_scan_job, args=(job_id, domain, login_config), daemon=True).start()
    return redirect(url_for("scanning", job_id=job_id))


@app.route("/scanning/<job_id>")
def scanning(job_id):
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
    if job is None:
        abort(404)
    return render_template("scanning.html", job_id=job_id, domain=job["domain"])


@app.route("/scan-status/<job_id>")
def scan_status(job_id):
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
        if job is None:
            return jsonify({"status": "not_found"}), 404
        return jsonify({
            "status": job["status"],
            "log": job["log"],
            "scan_id": job["scan_id"],
            "error": job["error"],
        })


def load_scan(scan_id):
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        abort(404)
    result = json.loads(row["result_json"])
    counts = json.loads(row["finding_counts"])
    return row, result, counts


@app.route("/report/<int:scan_id>")
def report(scan_id):
    row, result, counts = load_scan(scan_id)
    return render_template(
        "report.html",
        scan_id=scan_id,
        domain=row["domain"],
        scanned_at=row["scanned_at"],
        result=result,
        counts=counts,
        log_text=row["log_text"],
    )


@app.route("/report/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    db = get_db()
    db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    db.commit()
    return redirect(url_for("index"))


@app.route("/report/<int:scan_id>/log")
def report_log(scan_id):
    row, result, counts = load_scan(scan_id)
    buf = io.BytesIO(row["log_text"].encode("utf-8"))
    return send_file(
        buf,
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"CI-Watch_AuditLog_{row['domain']}_{scan_id}.log",
    )


@app.route("/report/<int:scan_id>/pdf")
def report_pdf(scan_id):
    row, result, counts = load_scan(scan_id)
    html = render_template(
        "report_pdf.html",
        scan_id=scan_id,
        domain=row["domain"],
        scanned_at=row["scanned_at"],
        result=result,
        counts=counts,
    )
    pdf_buf = io.BytesIO()
    pisa_status = pisa.CreatePDF(src=html, dest=pdf_buf)
    if pisa_status.err:
        abort(500, "Gagal generate PDF")
    pdf_buf.seek(0)
    return send_file(
        pdf_buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"CI-Watch_Report_{row['domain']}_{scan_id}.pdf",
    )


init_db()

if __name__ == "__main__":
    # debug=False: Werkzeug's interactive debugger allows arbitrary code
    # execution from the browser and must never be enabled, even bound to
    # localhost, on a security-tooling host.
    app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False, threaded=True)
