#!/usr/bin/env python3
"""Attack Map — живая карта алертов Graylog. Бэкенд на stdlib http.server.

GET /           — страница радара
GET /api/overview — сводка: лента, топы за 24ч, счётчики

ENV: GRAYLOG_URL, GRAYLOG_USER, GRAYLOG_PASS, AM_PORT (по умолчанию 8097)
"""
import gzip, json, os, ssl, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

GRAYLOG = os.environ.get("GRAYLOG_URL", "https://graylog.apps.monitoring.test").rstrip("/")
USER = os.environ.get("GRAYLOG_USER", "admin")
PASS = os.environ.get("GRAYLOG_PASS", "admin")
PORT = int(os.environ.get("AM_PORT", "8097"))

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

_cache = {"ts": 0, "data": None}
CACHE_TTL = 8  # секунд


def fetch_events():
    """Последние события из Graylog (до 500, свежие первыми)."""
    body = json.dumps({"query": "", "page": 1, "per_page": 500}).encode()
    req = urllib.request.Request(
        f"{GRAYLOG}/api/events/search", data=body,
        headers={"Content-Type": "application/json", "X-Requested-By": "attackmap"},
        method="POST")
    import base64
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode())
    with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
        return json.load(r)


def overview():
    now = time.time()
    if _cache["data"] and now - _cache["ts"] < CACHE_TTL:
        return _cache["data"]
    raw = fetch_events()
    day_ago = now - 86400
    feed, top, prio, nodes = [], {}, {"1": 0, "2": 0, "3": 0}, {}
    total24 = 0
    for e in raw.get("events", []):
        ev = e.get("event", {})
        try:
            ts = time.mktime(time.strptime(ev["timestamp"][:19], "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            continue
        title = ev.get("message", "")
        prefix = title.split(" - ")[0].split(":")[0].strip() or "Прочее"
        p = str(ev.get("priority", 2))
        item = {"ts": ev["timestamp"], "prio": int(p), "title": title,
                "detail": (ev.get("fields") or {}).get("event", "")[:220],
                "node": prefix}
        if ts >= day_ago:
            total24 += 1
            top[title] = top.get(title, 0) + 1
            prio[p] = prio.get(p, 0) + 1
            nodes[prefix] = nodes.get(prefix, 0) + 1
        if len(feed) < 60:
            feed.append(item)
    data = {
        "now": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total24": total24,
        "feed": feed,
        "top24": sorted(({"rule": k, "count": v} for k, v in top.items()),
                        key=lambda x: -x["count"])[:10],
        "prio24": prio,
        "nodes24": sorted(({"node": k, "count": v} for k, v in nodes.items()),
                          key=lambda x: -x["count"]),
    }
    _cache.update(ts=now, data=data)
    return data


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/api/overview"):
            self._json(overview())
        elif self.path in ("/", "/index.html"):
            self._html()
        else:
            self.send_error(404)

    def _json(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self):
        data = (Path(__file__).parent / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print(f"Attack Map: http://0.0.0.0:{PORT} (Graylog: {GRAYLOG})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
