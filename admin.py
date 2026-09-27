import os
import requests

URL=os.environ.get("VEX_API_URL","http://127.0.0.1:8000")
TOKEN=os.environ.get("VEX_ADMIN_TOKEN","")

def call(method,path,**kwargs):
    headers=kwargs.pop("headers",{})
    headers["X-Admin-Token"]=TOKEN
    r=requests.request(method,URL+path,headers=headers,timeout=10,**kwargs)
    print(r.status_code)
    print(r.text)

print("1 - Criar Key")
print("2 - Listar Keys")
print("3 - Ativar/Desativar Key")
choice=input("> ").strip()

if choice=="1":
    days=input("Validade em dias (vazio = sem expiração): ").strip()
    payload={"days": int(days)} if days else {}
    call("POST","/api/admin/keys",json=payload)
elif choice=="2":
    call("GET","/api/admin/keys")
elif choice=="3":
    key_id=input("ID da Key: ").strip()
    call("POST",f"/api/admin/keys/{key_id}/toggle")
