#!/usr/bin/env python3
"""Attack Map — живая карта алертов Graylog. Бэкенд на stdlib http.server.

GET /                  — страница радара
GET /favicon.svg       — логотип
GET /api/events?hours=N — события за окно N часов (1..168), до 500, свежие первыми
GET /api/overview      — legacy-сводка за 24ч (совместимость)

ENV: GRAYLOG_URL, GRAYLOG_USER, GRAYLOG_PASS, AM_PORT (по умолчанию 8097)
"""
import base64, json, os, ssl, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

GRAYLOG = os.environ.get("GRAYLOG_URL", "https://graylog.apps.monitoring.test").rstrip("/")
USER = os.environ.get("GRAYLOG_USER", "admin")
PASS = os.environ.get("GRAYLOG_PASS", "admin")
PORT = int(os.environ.get("AM_PORT", "8097"))

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

_cache = {}          # hours -> {"ts": ..., "data": ...}
CACHE_TTL = 8        # секунд
MAX_EVENTS = 500


def fetch_events(hours):
    """События Graylog за последние hours часов (свежие первыми)."""
    body = json.dumps({
        "query": "",
        "timerange": {"type": "relative", "range": int(hours * 3600)},
        "page": 1,
        "per_page": MAX_EVENTS,
    }).encode()
    req = urllib.request.Request(
        f"{GRAYLOG}/api/events/search", data=body,
        headers={"Content-Type": "application/json", "X-Requested-By": "attackmap"},
        method="POST")
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode())
    with urllib.request.urlopen(req, context=CTX, timeout=25) as r:
        return json.load(r)


def normalize(raw):
    """events/search -> компактный список для радара."""
    out = []
    for e in raw.get("events", []):
        ev = e.get("event", {})
        try:
            ts_ms = int(time.mktime(time.strptime(
                ev["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")) * 1000)
        except Exception:
            continue
        title = ev.get("message", "")
        node = title.split(" - ")[0].split(":")[0].strip() or "Прочее"
        out.append({
            "ts": ts_ms,
            "prio": int(ev.get("priority", 2)),
            "title": title,
            "detail": (ev.get("fields") or {}).get("event", "")[:220],
            "node": node,
        })
    return out


def events_window(hours):
    hours = max(1, min(168, hours))
    c = _cache.get(hours)
    now = time.time()
    if c and now - c["ts"] < CACHE_TTL:
        return c["data"]
    data = {
        "now": int(now * 1000),
        "hours": hours,
        "truncated": False,
        "events": normalize(fetch_events(hours)),
    }
    if len(data["events"]) >= MAX_EVENTS:
        data["truncated"] = True
    _cache[hours] = {"ts": now, "data": data}
    return data


def overview():
    """Старая сводка за 24ч — оставлена для совместимости."""
    now_ms = int(time.time() * 1000)
    day_ago = now_ms - 86400_000
    feed, top, prio, nodes = [], {}, {"1": 0, "2": 0, "3": 0}, {}
    total24 = 0
    for item in events_window(24)["events"]:
        if item["ts"] >= day_ago:
            total24 += 1
            top[item["title"]] = top.get(item["title"], 0) + 1
            prio[str(item["prio"])] = prio.get(str(item["prio"]), 0) + 1
            nodes[item["node"]] = nodes.get(item["node"], 0) + 1
        if len(feed) < 60:
            feed.append({"ts": time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                                             time.gmtime(item["ts"] / 1000)),
                         "prio": item["prio"], "title": item["title"],
                         "detail": item["detail"], "node": item["node"]})
    return {
        "now": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total24": total24, "feed": feed,
        "top24": sorted(({"rule": k, "count": v} for k, v in top.items()),
                        key=lambda x: -x["count"])[:10],
        "prio24": prio,
        "nodes24": sorted(({"node": k, "count": v} for k, v in nodes.items()),
                          key=lambda x: -x["count"]),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/events":
            qs = parse_qs(urlparse(self.path).query)
            try:
                hours = float(qs.get("hours", ["24"])[0])
            except ValueError:
                hours = 24
            self._json(events_window(hours))
        elif path == "/api/overview":
            self._json(overview())
        elif path == "/favicon.svg":
            self._file("attackmap.svg", "image/svg+xml")
        elif path in ("/", "/index.html"):
            self._file("index.html", "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def _json(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _file(self, name, ctype):
        data = (Path(__file__).parent / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print(f"Attack Map: http://0.0.0.0:{PORT} (Graylog: {GRAYLOG})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
