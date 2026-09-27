import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, redirect, render_template_string, request, session, url_for

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.environ.get("VEX_DB", os.path.join(BASE_DIR, "vex.db"))
ADMIN_TOKEN = os.environ.get("VEX_ADMIN_TOKEN", "")
SECRET = os.environ.get("VEX_SERVER_SECRET", "CHANGE_THIS_SECRET")

APP = Flask(__name__)
APP.secret_key = SECRET
APP.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

LOGIN_HTML = r'''
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VEX Admin</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#0b0d12;color:#eef1f6;font-family:Inter,Segoe UI,Arial,sans-serif;min-height:100vh;display:grid;place-items:center}.card{width:min(430px,92vw);background:#151922;border:1px solid #252b38;border-radius:18px;padding:34px;box-shadow:0 20px 70px #0008}.brand{font-size:34px;font-weight:900;color:#ed1747;letter-spacing:1px}.sub{color:#8f98a8;margin:7px 0 28px}label{display:block;font-size:13px;font-weight:700;margin:16px 0 8px}input{width:100%;padding:13px 14px;border-radius:10px;border:1px solid #303746;background:#0e1117;color:#fff;outline:none}input:focus{border-color:#ed1747}button{width:100%;margin-top:22px;padding:13px;border:0;border-radius:10px;background:#ed1747;color:#fff;font-weight:800;cursor:pointer}button:hover{filter:brightness(1.08)}.err{background:#3a1520;color:#ff9db5;border:1px solid #6e2338;padding:11px;border-radius:10px;margin-bottom:12px}
</style></head><body><div class="card"><div class="brand">VEX</div><div class="sub">PC Optimizer · Painel Administrativo</div>{% with messages=get_flashed_messages() %}{% for m in messages %}<div class="err">{{m}}</div>{% endfor %}{% endwith %}<form method="post"><label>Admin Token</label><input type="password" name="token" placeholder="Digite seu token administrativo" autofocus required><button>ENTRAR NO PAINEL</button></form></div></body></html>
'''

PANEL_HTML = r'''
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VEX Admin</title>
<style>
:root{--bg:#0b0d12;--panel:#151922;--panel2:#1b202b;--line:#29303d;--muted:#8f98a8;--text:#f2f4f8;--red:#ed1747;--green:#28c76f;--yellow:#ffb020}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif}.layout{display:flex;min-height:100vh}.side{width:230px;background:#12151c;border-right:1px solid var(--line);padding:25px 15px;position:fixed;inset:0 auto 0 0}.logo{font-size:34px;font-weight:900;color:var(--red);padding:0 10px}.desc{font-size:12px;color:var(--muted);padding:2px 10px 28px}.nav a{display:block;padding:12px 13px;border-radius:9px;color:#dce0e8;text-decoration:none;margin:4px 0}.nav a:hover,.nav a.active{background:#222733}.logout{position:absolute;bottom:22px;left:15px;right:15px}.logout a{display:block;text-align:center;padding:10px;border:1px solid var(--line);border-radius:9px;color:#cdd3de;text-decoration:none}.main{margin-left:230px;padding:30px;width:calc(100% - 230px)}h1{margin:0 0 6px;font-size:30px}.sub{color:var(--muted);margin-bottom:24px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}.stat .n{font-size:30px;font-weight:900}.stat .l{font-size:12px;color:var(--muted);margin-top:4px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin-top:18px}.top{display:flex;justify-content:space-between;align-items:center;gap:15px}.top h2{margin:0;font-size:18px}.btn{display:inline-block;border:0;border-radius:8px;padding:10px 13px;background:var(--red);color:#fff;text-decoration:none;font-weight:800;cursor:pointer}.btn.gray{background:#252b36}.btn.green{background:#176c43}.btn.warn{background:#77560b}.btn.danger{background:#7b1830}.row{display:flex;gap:10px;flex-wrap:wrap}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}.formgrid input{width:100%;padding:11px;border-radius:8px;border:1px solid var(--line);background:#0d1016;color:#fff}.formgrid .full{grid-column:1/-1}.tablewrap{overflow:auto;margin-top:15px}table{width:100%;border-collapse:collapse;min-width:850px}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:middle}th{color:#9fa8b7;font-size:11px;text-transform:uppercase}code{background:#0c0f14;border:1px solid var(--line);padding:5px 7px;border-radius:6px;color:#f5f6f8}.status{font-size:11px;padding:5px 8px;border-radius:999px;font-weight:800}.on{background:#123a28;color:#6ee7a1}.off{background:#3a1520;color:#ff9db5}.used{background:#2b303a;color:#c4cad5}.flash{margin:0 0 15px;padding:11px 13px;border-radius:9px;background:#152e22;color:#8ff0b6;border:1px solid #245d40}.muted{color:var(--muted)}@media(max-width:900px){.side{width:190px}.main{margin-left:190px;width:calc(100% - 190px)}.grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:650px){.side{position:static;width:100%;height:auto}.layout{display:block}.main{margin-left:0;width:100%;padding:18px}.logout{position:static;margin-top:20px}.grid{grid-template-columns:1fr}.formgrid{grid-template-columns:1fr}}
</style></head><body><div class="layout"><aside class="side"><div class="logo">VEX</div><div class="desc">PC Optimizer · Admin</div><nav class="nav"><a class="{{'active' if page=='dashboard' else ''}}" href="{{url_for('dashboard')}}">▦ Dashboard</a><a class="{{'active' if page=='keys' else ''}}" href="{{url_for('keys')}}">🔑 Keys</a><a class="{{'active' if page=='users' else ''}}" href="{{url_for('users')}}">👥 Usuários</a></nav><div class="logout"><a href="{{url_for('logout')}}">Sair</a></div></aside><main class="main">{% with messages=get_flashed_messages() %}{% for m in messages %}<div class="flash">{{m}}</div>{% endfor %}{% endwith %}{{ content|safe }}</main></div></body></html>
'''

DASH = r'''
<h1>Dashboard</h1><div class="sub">Visão geral das licenças e usuários do VEX.</div>
<div class="grid"><div class="stat"><div class="n">{{stats.total}}</div><div class="l">Keys totais</div></div><div class="stat"><div class="n">{{stats.active}}</div><div class="l">Keys ativas</div></div><div class="stat"><div class="n">{{stats.used}}</div><div class="l">Keys utilizadas</div></div><div class="stat"><div class="n">{{stats.users}}</div><div class="l">Usuários</div></div></div>
<div class="panel"><div class="top"><h2>Últimas Keys</h2><a class="btn" href="{{url_for('keys')}}">Gerenciar Keys</a></div><div class="tablewrap"><table><tr><th>ID</th><th>Key</th><th>Status</th><th>Uso</th><th>Expiração</th><th>Criada</th></tr>{% for k in recent %}<tr><td>{{k.id}}</td><td><code>{{k.display_key}}</code></td><td><span class="status {{'on' if k.active else 'off'}}">{{'ATIVA' if k.active else 'BLOQUEADA'}}</span></td><td>{{'Usada' if k.used else 'Disponível'}}</td><td>{{k.expires_at or 'Lifetime'}}</td><td>{{k.created_at}}</td></tr>{% else %}<tr><td colspan="6" class="muted">Nenhuma Key criada.</td></tr>{% endfor %}</table></div></div>
'''

KEYS = r'''
<h1>Gerenciar Keys</h1><div class="sub">Crie, bloqueie, reative e exclua licenças do VEX.</div>
<div class="panel"><div class="top"><h2>Nova Key</h2></div><form method="post" action="{{url_for('create_key')}}" class="formgrid"><div><label>Validade em dias</label><input type="number" name="days" min="1" placeholder="30"></div><div><label>Tipo</label><input value="Digite os dias ou deixe vazio para Lifetime" disabled></div><div class="full"><button class="btn" type="submit">GERAR KEY</button></div></form></div>
<div class="panel"><div class="top"><h2>Todas as Keys</h2><div class="muted">{{keys|length}} registros</div></div><div class="tablewrap"><table><tr><th>ID</th><th>Key</th><th>Status</th><th>Uso</th><th>Expiração</th><th>Usuário</th><th>Ações</th></tr>{% for k in keys %}<tr><td>{{k.id}}</td><td><code>{{k.display_key}}</code></td><td><span class="status {{'on' if k.active else 'off'}}">{{'ATIVA' if k.active else 'BLOQUEADA'}}</span></td><td><span class="status {{'used' if k.used else 'on'}}">{{'USADA' if k.used else 'DISPONÍVEL'}}</span></td><td>{{k.expires_at or 'Lifetime'}}</td><td>{{k.used_by or '—'}}</td><td><div class="row"><form method="post" action="{{url_for('toggle_key',key_id=k.id)}}"><button class="btn {{'warn' if k.active else 'green'}}" type="submit">{{'Bloquear' if k.active else 'Ativar'}}</button></form><form method="post" action="{{url_for('delete_key',key_id=k.id)}}" onsubmit="return confirm('Excluir esta Key? Esta ação não pode ser desfeita.');"><button class="btn danger" type="submit">Excluir</button></form></div></td></tr>{% endfor %}</table></div></div>
'''

USERS = r'''
<h1>Usuários</h1><div class="sub">Contas registradas no VEX e suas licenças.</div><div class="panel"><div class="tablewrap"><table><tr><th>ID</th><th>Usuário</th><th>Key ID</th><th>Licença</th><th>Dispositivo</th><th>Cadastro</th><th>Último login</th></tr>{% for u in users %}<tr><td>{{u.id}}</td><td><b>{{u.username}}</b></td><td>{{u.license_id}}</td><td><span class="status {{'on' if u.active else 'off'}}">{{'ATIVA' if u.active else 'BLOQUEADA'}}</span></td><td><code>{{u.device_id[:18]}}...</code></td><td>{{u.created_at}}</td><td>{{u.last_login or 'Nunca'}}</td></tr>{% else %}<tr><td colspan="7" class="muted">Nenhum usuário registrado.</td></tr>{% endfor %}</table></div></div>
'''


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_ok"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def render_page(content, page="dashboard", **context):
    body = render_template_string(content, **context)
    return render_template_string(PANEL_HTML, content=body, page=page)


def make_key():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "VEX-" + "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


def hash_key(key):
    import hashlib
    return hashlib.sha256(key.strip().upper().encode()).hexdigest()


def key_exists_hash(kh):
    with db() as c:
        return c.execute("SELECT 1 FROM license_keys WHERE key_hash=?", (kh,)).fetchone() is not None


def get_stats():
    with db() as c:
        total = c.execute("SELECT COUNT(*) FROM license_keys").fetchone()[0]
        active = c.execute("SELECT COUNT(*) FROM license_keys WHERE active=1").fetchone()[0]
        used = c.execute("SELECT COUNT(*) FROM license_keys WHERE used=1").fetchone()[0]
        users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return type("Stats", (), {"total": total, "active": active, "used": used, "users": users})()


@APP.route("/", methods=["GET", "POST"])
def login():
    if session.get("admin_ok"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        token = request.form.get("token", "")
        if ADMIN_TOKEN and secrets.compare_digest(token, ADMIN_TOKEN):
            session.clear()
            session["admin_ok"] = True
            session["csrf"] = secrets.token_urlsafe(24)
            return redirect(url_for("dashboard"))
        flash("Token administrativo inválido.")
    return render_template_string(LOGIN_HTML)


@APP.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@APP.get("/dashboard")
@login_required
def dashboard():
    with db() as c:
        rows = c.execute("SELECT id, key_hash, active, used, expires_at, used_by, created_at FROM license_keys ORDER BY id DESC LIMIT 10").fetchall()
    # The server intentionally stores only hashes. For old/generated keys we cannot reconstruct the original key.
    # Show a safe identifier instead of pretending the full secret can be recovered.
    recent=[]
    for r in rows:
        d=dict(r)
        d["display_key"] = "VEX-" + d["key_hash"][:4].upper() + "-" + d["key_hash"][4:8].upper() + "-••••"
        recent.append(type("K", (), d)())
    return render_page(DASH, "dashboard", stats=get_stats(), recent=recent)


@APP.get("/keys")
@login_required
def keys():
    with db() as c:
        rows = c.execute("SELECT id,key_hash,active,used,expires_at,used_by,created_at FROM license_keys ORDER BY id DESC").fetchall()
    data=[]
    for r in rows:
        d=dict(r)
        d["display_key"] = "VEX-" + d["key_hash"][:4].upper() + "-" + d["key_hash"][4:8].upper() + "-••••"
        data.append(type("K", (), d)())
    return render_page(KEYS, "keys", keys=data)


@APP.post("/keys/create")
@login_required
def create_key():
    raw=request.form.get("days", "").strip()
    if raw:
        try:
            days=int(raw)
            if days <= 0: raise ValueError
        except ValueError:
            flash("A validade precisa ser um número de dias maior que zero.")
            return redirect(url_for("keys"))
    else:
        days=None
    key=make_key()
    while key_exists_hash(hash_key(key)):
        key=make_key()
    from datetime import timedelta
    expires=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat() if days else None
    with db() as c:
        c.execute("INSERT INTO license_keys(key_hash,expires_at,created_at) VALUES(?,?,?)", (hash_key(key),expires,datetime.now(timezone.utc).isoformat()))
        c.commit()
    session["new_key"] = key
    flash("Key criada: " + key)
    return redirect(url_for("keys"))


@APP.post("/keys/<int:key_id>/toggle")
@login_required
def toggle_key(key_id):
    with db() as c:
        row=c.execute("SELECT active FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            flash("Key não encontrada.")
            return redirect(url_for("keys"))
        new=0 if row["active"] else 1
        c.execute("UPDATE license_keys SET active=? WHERE id=?", (new,key_id))
        c.commit()
    flash("Key " + ("ativada." if new else "bloqueada."))
    return redirect(url_for("keys"))


@APP.post("/keys/<int:key_id>/delete")
@login_required
def delete_key(key_id):
    with db() as c:
        row=c.execute("SELECT used,used_by FROM license_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            flash("Key não encontrada.")
        elif row["used"]:
            flash("Esta Key já foi utilizada e não pode ser excluída pelo painel.")
        else:
            c.execute("DELETE FROM license_keys WHERE id=?", (key_id,))
            c.commit()
            flash("Key excluída.")
    return redirect(url_for("keys"))


@APP.get("/users")
@login_required
def users():
    with db() as c:
        rows=c.execute("""SELECT u.id,u.username,u.license_id,u.device_id,u.created_at,u.last_login,l.active FROM users u JOIN license_keys l ON l.id=u.license_id ORDER BY u.id DESC""").fetchall()
    return render_page(USERS, "users", users=[type("U", (), dict(r))() for r in rows])


if __name__ == "__main__":
    if not ADMIN_TOKEN:
        raise SystemExit("Defina VEX_ADMIN_TOKEN antes de iniciar o painel.")
    APP.run(host="127.0.0.1", port=int(os.environ.get("ADMIN_PORT", "8001")), debug=False)
