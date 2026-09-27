import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

APP = Flask(__name__)
DB_PATH = os.environ.get("VEX_DB", os.path.join(os.path.dirname(__file__), "vex.db"))
ADMIN_TOKEN = os.environ.get("VEX_ADMIN_TOKEN", "")
SECRET = os.environ.get("VEX_SERVER_SECRET", "CHANGE_THIS_SECRET")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS license_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            used INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT,
            used_by TEXT,
            device_id TEXT,
            created_at TEXT NOT NULL,
            used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            license_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT,
            FOREIGN KEY (license_id) REFERENCES license_keys(id)
        );
        """)

def hash_key(key):
    return hashlib.sha256(key.strip().upper().encode()).hexdigest()

def now():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.isoformat()

def auth_admin():
    return request.headers.get("X-Admin-Token", "") == ADMIN_TOKEN and bool(ADMIN_TOKEN)

@APP.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "VEX License API"})

@APP.post("/api/register")
def register():
    data=request.get_json(silent=True) or {}
    username=str(data.get("username","")).strip()
    password=str(data.get("password",""))
    key=str(data.get("key","")).strip().upper()
    device_id=str(data.get("device_id","")).strip()

    if len(username) < 3 or len(username) > 32:
        return jsonify({"ok":False,"error":"Usuário deve ter entre 3 e 32 caracteres."}),400
    if len(password) < 6:
        return jsonify({"ok":False,"error":"Senha deve ter pelo menos 6 caracteres."}),400
    if len(device_id) < 8:
        return jsonify({"ok":False,"error":"Identificador do dispositivo inválido."}),400
    if not key:
        return jsonify({"ok":False,"error":"License Key obrigatória."}),400

    kh=hash_key(key)
    with db() as c:
        license_row=c.execute(
            "SELECT * FROM license_keys WHERE key_hash=? AND active=1 AND used=0", (kh,)
        ).fetchone()
        if not license_row:
            return jsonify({"ok":False,"error":"Key inválida, inativa ou já utilizada."}),403

        if license_row["expires_at"]:
            try:
                if datetime.fromisoformat(license_row["expires_at"]) <= now():
                    return jsonify({"ok":False,"error":"Esta Key expirou."}),403
            except ValueError:
                return jsonify({"ok":False,"error":"Key com validade inválida."}),500

        if c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            return jsonify({"ok":False,"error":"Usuário já existe."}),409

        created=iso(now())
        c.execute(
            "INSERT INTO users(username,password_hash,license_id,device_id,created_at) VALUES(?,?,?,?,?)",
            (username,generate_password_hash(password),license_row["id"],device_id,created)
        )
        c.execute(
            "UPDATE license_keys SET used=1,used_by=?,device_id=?,used_at=? WHERE id=?",
            (username,device_id,created,license_row["id"])
        )
        c.commit()

    return jsonify({"ok":True,"message":"Conta criada com sucesso."})

@APP.post("/api/login")
def login():
    data=request.get_json(silent=True) or {}
    username=str(data.get("username","")).strip()
    password=str(data.get("password",""))
    device_id=str(data.get("device_id","")).strip()

    with db() as c:
        row=c.execute("""
            SELECT u.*, l.active, l.expires_at, l.used
            FROM users u JOIN license_keys l ON l.id=u.license_id
            WHERE u.username=?
        """,(username,)).fetchone()

        if not row or not check_password_hash(row["password_hash"],password):
            return jsonify({"ok":False,"error":"Usuário ou senha incorretos."}),401

        if not row["active"]:
            return jsonify({"ok":False,"error":"A License Key desta conta está bloqueada."}),403
        if row["device_id"] != device_id:
            return jsonify({"ok":False,"error":"Esta conta está vinculada a outro dispositivo."}),403
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= now():
            return jsonify({"ok":False,"error":"A License Key expirou."}),403

        c.execute("UPDATE users SET last_login=? WHERE id=?",(iso(now()),row["id"]))
        c.commit()

    # Token simples de sessão: não contém senha nem Key.
    session=secrets.token_urlsafe(32)
    return jsonify({"ok":True,"username":username,"session":session})

@APP.post("/api/admin/keys")
def create_key():
    if not auth_admin():
        return jsonify({"ok":False,"error":"Não autorizado."}),401

    data=request.get_json(silent=True) or {}
    days=data.get("days")
    try:
        days=int(days) if days is not None else None
        if days is not None and days <= 0:
            raise ValueError
    except ValueError:
        return jsonify({"ok":False,"error":"days deve ser um número positivo."}),400

    alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    parts=["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    key="VEX-"+"-".join(parts)
    expires=iso(now()+timedelta(days=days)) if days else None

    with db() as c:
        c.execute(
            "INSERT INTO license_keys(key_hash,expires_at,created_at) VALUES(?,?,?)",
            (hash_key(key),expires,iso(now()))
        )
        c.commit()

    return jsonify({"ok":True,"key":key,"expires_at":expires})

@APP.get("/api/admin/keys")
def list_keys():
    if not auth_admin():
        return jsonify({"ok":False,"error":"Não autorizado."}),401
    with db() as c:
        rows=c.execute("""
            SELECT id,active,used,expires_at,used_by,device_id,created_at,used_at
            FROM license_keys ORDER BY id DESC
        """).fetchall()
    return jsonify({"ok":True,"keys":[dict(r) for r in rows]})

@APP.post("/api/admin/keys/<int:key_id>/toggle")
def toggle_key(key_id):
    if not auth_admin():
        return jsonify({"ok":False,"error":"Não autorizado."}),401
    with db() as c:
        row=c.execute("SELECT active FROM license_keys WHERE id=?",(key_id,)).fetchone()
        if not row:
            return jsonify({"ok":False,"error":"Key não encontrada."}),404
        new=0 if row["active"] else 1
        c.execute("UPDATE license_keys SET active=? WHERE id=?",(new,key_id))
        c.commit()
    return jsonify({"ok":True,"active":bool(new)})

@APP.get("/api/admin/users")
def list_users():
    if not auth_admin():
        return jsonify({"ok":False,"error":"Não autorizado."}),401
    with db() as c:
        rows=c.execute("""
            SELECT u.id,u.username,u.device_id,u.created_at,u.last_login,
                   l.id AS license_id,l.active,l.used,l.expires_at
            FROM users u JOIN license_keys l ON l.id=u.license_id
            ORDER BY u.id DESC
        """).fetchall()
    return jsonify({"ok":True,"users":[dict(r) for r in rows]})

if __name__ == "__main__":
    init_db()
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT","8000")))
