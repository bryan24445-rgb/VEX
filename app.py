import os
import secrets
import sqlite3
import hashlib

from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash


APP = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get(
    "VEX_DB",
    os.path.join(BASE_DIR, "vex.db")
)

ADMIN_TOKEN = os.environ.get(
    "VEX_ADMIN_TOKEN",
    ""
).strip()


# =========================================================
# BANCO DE DADOS
# =========================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:

        db.execute("""
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
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                license_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT,
                FOREIGN KEY (license_id)
                    REFERENCES license_keys(id)
            )
        """)

        db.commit()


# Inicializa o banco quando o servidor iniciar
init_db()


# =========================================================
# FUNÇÕES
# =========================================================

def current_time():
    return datetime.now(timezone.utc)


def hash_key(key):
    return hashlib.sha256(
        key.strip().upper().encode("utf-8")
    ).hexdigest()


def admin_authorized():
    token = request.headers.get(
        "X-Admin-Token",
        ""
    ).strip()

    if not ADMIN_TOKEN:
        return False

    return secrets.compare_digest(
        token,
        ADMIN_TOKEN
    )


# =========================================================
# HOME
# =========================================================

@APP.get("/")
def home():
    return jsonify({
        "ok": True,
        "service": "VEX API",
        "status": "online"
    })


# =========================================================
# HEALTH
# =========================================================

@APP.get("/api/health")
def health():
    return jsonify({
        "ok": True,
        "service": "VEX License API",
        "status": "online"
    })


# =========================================================
# ADMIN - STATUS
# =========================================================

@APP.get("/api/admin/status")
def admin_status():

    if not admin_authorized():
        return jsonify({
            "ok": False,
            "error": "Não autorizado."
        }), 401

    with get_db() as db:

        total = db.execute(
            "SELECT COUNT(*) FROM license_keys"
        ).fetchone()[0]

        active = db.execute(
            "SELECT COUNT(*) FROM license_keys WHERE active = 1"
        ).fetchone()[0]

        used = db.execute(
            "SELECT COUNT(*) FROM license_keys WHERE used = 1"
        ).fetchone()[0]

    return jsonify({
        "ok": True,
        "service": "VEX License API",
        "keys_total": total,
        "keys_active": active,
        "keys_used": used
    })


# =========================================================
# ADMIN - CRIAR KEY
# =========================================================

@APP.post("/api/admin/keys")
def create_key():

    if not admin_authorized():
        return jsonify({
            "ok": False,
            "error": "Não autorizado."
        }), 401

    data = request.get_json(silent=True) or {}

    days = data.get("days")

    if days in ("", None):
        days = None

    else:
        try:
            days = int(days)

            if days <= 0:
                raise ValueError

        except (ValueError, TypeError):

            return jsonify({
                "ok": False,
                "error": "Dias inválidos."
            }), 400

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    while True:

        parts = []

        for _ in range(3):

            part = "".join(
                secrets.choice(alphabet)
                for _ in range(4)
            )

            parts.append(part)

        key = "VEX-" + "-".join(parts)

        key_hash_value = hash_key(key)

        with get_db() as db:

            exists = db.execute(
                """
                SELECT id
                FROM license_keys
                WHERE key_hash = ?
                """,
                (key_hash_value,)
            ).fetchone()

        if not exists:
            break

    expires_at = None

    if days is not None:

        expires_at = (
            current_time() +
            timedelta(days=days)
        ).isoformat()

    with get_db() as db:

        cursor = db.execute(
            """
            INSERT INTO license_keys (
                key_hash,
                active,
                used,
                expires_at,
                created_at
            )
            VALUES (?, 1, 0, ?, ?)
            """,
            (
                key_hash_value,
                expires_at,
                current_time().isoformat()
            )
        )

        key_id = cursor.lastrowid

        db.commit()

    return jsonify({
        "ok": True,
        "id": key_id,
        "key": key,
        "active": True,
        "used": False,
        "expires_at": expires_at
    })


# =========================================================
# ADMIN - LISTAR KEYS
# =========================================================

@APP.get("/api/admin/keys")
def list_keys():

    if not admin_authorized():
        return jsonify({
            "ok": False,
            "error": "Não autorizado."
        }), 401

    with get_db() as db:

        rows = db.execute(
            """
            SELECT
                id,
                active,
                used,
                expires_at,
                used_by,
                device_id,
                created_at,
                used_at
            FROM license_keys
            ORDER BY id DESC
            """
        ).fetchall()

    return jsonify({
        "ok": True,
        "keys": [dict(row) for row in rows]
    })


# =========================================================
# ADMIN - ATIVAR / DESATIVAR KEY
# =========================================================

@APP.post("/api/admin/keys/<int:key_id>/toggle")
def toggle_key(key_id):

    if not admin_authorized():
        return jsonify({
            "ok": False,
            "error": "Não autorizado."
        }), 401

    with get_db() as db:

        row = db.execute(
            """
            SELECT active
            FROM license_keys
            WHERE id = ?
            """,
            (key_id,)
        ).fetchone()

        if not row:
            return jsonify({
                "ok": False,
                "error": "Key não encontrada."
            }), 404

        new_status = 0 if row["active"] else 1

        db.execute(
            """
            UPDATE license_keys
            SET active = ?
            WHERE id = ?
            """,
            (new_status, key_id)
        )

        db.commit()

    return jsonify({
        "ok": True,
        "active": bool(new_status)
    })


# =========================================================
# ADMIN - RESETAR KEY
# =========================================================

@APP.post("/api/admin/keys/<int:key_id>/reset")
def reset_key(key_id):

    if not admin_authorized():
        return jsonify({
            "ok": False,
            "error": "Não autorizado."
        }), 401

    with get_db() as db:

        row = db.execute(
            """
            SELECT id
            FROM license_keys
            WHERE id = ?
            """,
            (key_id,)
        ).fetchone()

        if not row:
            return jsonify({
                "ok": False,
                "error": "Key não encontrada."
            }), 404

        db.execute(
            """
            UPDATE license_keys
            SET used = 0,
                used_by = NULL,
                device_id = NULL,
                used_at = NULL,
                active = 1
            WHERE id = ?
            """,
            (key_id,)
        )

        db.commit()

    return jsonify({
        "ok": True,
        "message": "Key resetada."
    })


# =========================================================
# ADMIN - EXCLUIR KEY
# =========================================================

@APP.delete("/api/admin/keys/<int:key_id>")
def delete_key(key_id):

    if not admin_authorized():
        return jsonify({
            "ok": False,
            "error": "Não autorizado."
        }), 401

    with get_db() as db:

        row = db.execute(
            """
            SELECT id
            FROM license_keys
            WHERE id = ?
            """,
            (key_id,)
        ).fetchone()

        if not row:
            return jsonify({
                "ok": False,
                "error": "Key não encontrada."
            }), 404

        db.execute(
            """
            DELETE FROM license_keys
            WHERE id = ?
            """,
            (key_id,)
        )

        db.commit()

    return jsonify({
        "ok": True,
        "message": "Key excluída."
    })


# =========================================================
# REGISTRO DE USUÁRIO
# =========================================================

@APP.post("/api/register")
def register():

    data = request.get_json(silent=True) or {}

    username = str(
        data.get("username", "")
    ).strip()

    password = str(
        data.get("password", "")
    )

    key = str(
        data.get("key", "")
    ).strip().upper()

    device_id = str(
        data.get("device_id", "")
    ).strip()

    if len(username) < 3:
        return jsonify({
            "ok": False,
            "error": "Usuário muito curto."
        }), 400

    if len(username) > 32:
        return jsonify({
            "ok": False,
            "error": "Usuário muito grande."
        }), 400

    if len(password) < 6:
        return jsonify({
            "ok": False,
            "error": "Senha deve ter pelo menos 6 caracteres."
        }), 400

    if len(device_id) < 8:
        return jsonify({
            "ok": False,
            "error": "Device ID inválido."
        }), 400

    if not key:
        return jsonify({
            "ok": False,
            "error": "License Key obrigatória."
        }), 400

    key_hash_value = hash_key(key)

    with get_db() as db:

        license_row = db.execute(
            """
            SELECT *
            FROM license_keys
            WHERE key_hash = ?
              AND active = 1
              AND used = 0
            """,
            (key_hash_value,)
        ).fetchone()

        if not license_row:
            return jsonify({
                "ok": False,
                "error": "Key inválida, inativa ou já utilizada."
            }), 403

        if license_row["expires_at"]:

            expires = datetime.fromisoformat(
                license_row["expires_at"]
            )

            if expires <= current_time():

                return jsonify({
                    "ok": False,
                    "error": "Esta Key expirou."
                }), 403

        user_exists = db.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if user_exists:

            return jsonify({
                "ok": False,
                "error": "Usuário já existe."
            }), 409

        created_at = current_time().isoformat()

        db.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                license_id,
                device_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                generate_password_hash(password),
                license_row["id"],
                device_id,
                created_at
            )
        )

        db.execute(
            """
            UPDATE license_keys
            SET used = 1,
                used_by = ?,
                device_id = ?,
                used_at = ?
            WHERE id = ?
            """,
            (
                username,
                device_id,
                created_at,
                license_row["id"]
            )
        )

        db.commit()

    return jsonify({
        "ok": True,
        "message": "Conta criada com sucesso."
    })


# =========================================================
# LOGIN
# =========================================================

@APP.post("/api/login")
def login():

    data = request.get_json(silent=True) or {}

    username = str(
        data.get("username", "")
    ).strip()

    password = str(
        data.get("password", "")
    )

    device_id = str(
        data.get("device_id", "")
    ).strip()

    with get_db() as db:

        user = db.execute(
            """
            SELECT
                u.*,
                l.active,
                l.expires_at
            FROM users u
            JOIN license_keys l
                ON l.id = u.license_id
            WHERE u.username = ?
            """,
            (username,)
        ).fetchone()

        if not user:

            return jsonify({
                "ok": False,
                "error": "Usuário ou senha incorretos."
            }), 401

        if not check_password_hash(
            user["password_hash"],
            password
        ):

            return jsonify({
                "ok": False,
                "error": "Usuário ou senha incorretos."
            }), 401

        if not user["active"]:

            return jsonify({
                "ok": False,
                "error": "License Key bloqueada."
            }), 403

        if user["device_id"] != device_id:

            return jsonify({
                "ok": False,
                "error": "Dispositivo diferente."
            }), 403

        if user["expires_at"]:

            expires = datetime.fromisoformat(
                user["expires_at"]
            )

            if expires <= current_time():

                return jsonify({
                    "ok": False,
                    "error": "License Key expirada."
                }), 403

        session = secrets.token_urlsafe(32)

        db.execute(
            """
            UPDATE users
            SET last_login = ?
            WHERE id = ?
            """,
            (
                current_time().isoformat(),
                user["id"]
            )
        )

        db.commit()

    return jsonify({
        "ok": True,
        "username": username,
        "session": session
    })


# =========================================================
# INICIAR SERVIDOR
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "8000"
        )
    )

    APP.run(
        host="0.0.0.0",
        port=port
    )