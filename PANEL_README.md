# VEX Admin Panel

Painel web local para administrar as Keys e visualizar usuários do VEX PC Optimizer.

## Iniciar

1. Deixe a API rodando em um terminal:

```powershell
$env:VEX_ADMIN_TOKEN="VEX-ADMIN-123456789"
py app.py
```

2. Em outro terminal, na mesma pasta `server`:

```powershell
$env:VEX_ADMIN_TOKEN="VEX-ADMIN-123456789"
$env:VEX_SERVER_SECRET="VEX-CHANGE-THIS-SECRET"
$env:ADMIN_PORT="8001"
py web_admin.py
```

3. Abra no navegador:

`http://127.0.0.1:8001`

4. Entre usando o mesmo `VEX_ADMIN_TOKEN`.

## O que o painel faz

- Dashboard com totais de Keys e usuários
- Criar Key mensal ou Lifetime
- Ativar/bloquear Key
- Excluir Keys ainda não utilizadas
- Ver usuários, dispositivo, cadastro e último login
- Logout e sessão administrativa

## Importante sobre segurança

O banco armazena somente o hash das Keys. Por isso, depois que uma Key é criada, o painel não consegue recuperar o texto original de uma Key antiga. A Key recém-criada é exibida na mensagem de sucesso para você copiar e entregar ao cliente.

Para colocar o painel na internet, use HTTPS, um token forte, `VEX_SERVER_SECRET` forte, firewall e um proxy reverso. Não publique o painel diretamente na internet com o token de exemplo.
