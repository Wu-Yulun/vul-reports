import hashlib
import httpx

def prng(seed, length):
    h = 2166136261
    for ch in seed.encode():
        h ^= ch
        h = (h * 16777619) & 0xffffffff
    state = h
    out = ""
    while len(out) < length:
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        out += "%08x" % state
    return out[:length]

def solve(base, kb):
    c = httpx.post(base + "/share/v1/captcha/challenge", headers={"X-KB-ID": kb}, verify=False).json()
    tok, ch = c["token"], c["challenge"]
    sols = []
    for i in range(ch["c"]):
        seed = tok + str(i + 1)
        target = prng(seed + "d", ch["d"])
        salt = prng(seed, ch["s"])
        n = 0
        while not hashlib.sha256((salt + str(n)).encode()).hexdigest().startswith(target):
            n += 1
        sols.append(n)
    return httpx.post(base + "/share/v1/captcha/redeem", headers={"X-KB-ID": kb},
                      json={"token": tok, "solutions": sols}, verify=False).json()["token"]
