"""
webdemo.py - ThreatBoard web page + terminal output          OWNER: Sandeep
Runs a tiny local web server (Python standard library only). It only CALLS the
existing code, and every result shows on the page AND prints in this terminal.

    python -m sandeep.webdemo                  (1M events, opens the browser)
    python -m sandeep.webdemo --n 200000 --port 8001 --no-browser
Stop with Ctrl + C.
"""
import argparse, contextlib, io, json, random, threading, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

from nishanth.threatboard import build_all, cmd_stats, cmd_query, cmd_burst
from sandeep.datagen import generate_events, FLAGS

STATE = {}


def capture(fn, *args):
    """Run a terminal-demo function and return the text it printed."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args)
    return buf.getvalue()


def rows():
    S = STATE["structs"]
    return [[f, len(S["Roaring"][f])] + [S[k][f].size_bytes() for k in ("Roaring", "Bitset", "HashSet")]
            for f in FLAGS]


def stats(body):
    return {"text": capture(cmd_stats, STATE["structs"]), "rows": rows()}


def query(body):
    return {"text": capture(cmd_query, STATE["structs"], str(body.get("q", "")))}


def burst(body):
    text = capture(cmd_burst, STATE["structs"], STATE["n"], STATE["rng"])
    return {"text": text, "rows": rows()}


ACTIONS = {"/api/stats": stats, "/api/query": query, "/api/burst": burst}

PAGE = """<!doctype html><meta charset="utf-8"><title>ThreatBoard</title>
<style>:root{color-scheme:light dark}body{font:15px system-ui;max-width:900px;margin:20px auto;padding:0 12px}
input{width:100%;padding:8px;font:14px monospace}button{padding:7px 12px;margin:8px 8px 8px 0}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #888;padding:4px 8px;text-align:right}
th:first-child,td:first-child{text-align:left}pre{background:#111;color:#cde;padding:12px;overflow:auto}</style>
<h2>ThreatBoard - RoarIndex (Roaring Bitmap vs Bitset vs HashSet)</h2>
<input id="q" value="failed_login AND suspicious_ip AND NOT whitelisted">
<button id="run">Run query</button><button id="burst">Inject attack burst</button><button id="stats">Memory</button>
<table id="mem"></table><pre id="log">Ready.</pre>
<script>
const $ = id => document.getElementById(id);
async function call(path, body) {
  const r = await fetch(path, body ? {method: 'POST', body: JSON.stringify(body)} : undefined);
  const j = await r.json();
  if (!r.ok) throw new Error(j.error);
  if (j.rows) $('mem').innerHTML = '<tr><th>flag</th><th>IDs</th><th>Roaring KB</th><th>Bitset KB</th><th>HashSet KB</th></tr>' +
    j.rows.map(x => '<tr><td>' + x[0] + '</td><td>' + x[1].toLocaleString() + '</td>' +
      x.slice(2).map(b => '<td>' + (b / 1024).toFixed(1) + '</td>').join('') + '</tr>').join('');
  $('log').textContent = j.text + '\\n' + $('log').textContent;
}
const go = (p, b) => call(p, b).catch(e => { $('log').textContent = 'Error: ' + e.message + '\\n' + $('log').textContent; });
$('run').onclick = () => go('/api/query', {q: $('q').value});
$('burst').onclick = () => go('/api/burst', {});
$('stats').onclick = () => go('/api/stats');
go('/api/stats');
</script>"""


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json"):
        data = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_api(self, raw=b"{}"):
        action = ACTIONS.get(self.path)
        if not action:
            return self.reply(404, {"error": "not found"})
        try:
            result = action(json.loads(raw or b"{}"))
            print("\n[web]" + result["text"])               # same text in the terminal
            self.reply(200, result)
        except ValueError as e:                              # bad query text
            self.reply(400, {"error": str(e)})
        except Exception as e:
            self.reply(500, {"error": str(e)})

    def do_GET(self):
        self.reply(200, PAGE, "text/html") if self.path == "/" else self.handle_api()

    def do_POST(self):
        self.handle_api(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 10000)))

    def log_message(self, *args):                            # keep the terminal clean
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1_000_000)
    ap.add_argument("--mode", choices=["mixed", "sparse", "dense"], default="mixed")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    print(f"Generating {a.n:,} synthetic security events (mode={a.mode}) ...")
    STATE.update(n=a.n, structs=build_all(generate_events(a.n, a.mode), a.n), rng=random.Random(7))
    try:
        server = HTTPServer(("127.0.0.1", a.port), Handler)   # this computer only
    except OSError:
        return print(f"Port {a.port} is busy. Try: python -m sandeep.webdemo --port {a.port + 1}")
    url = f"http://localhost:{a.port}"
    print(f"\nThreatBoard web page: {url}   (Ctrl + C to stop)")
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()