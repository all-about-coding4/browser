#!/usr/bin/env python3
"""
Lynkio Browser — v17.1
Built on the lynkio framework v1.4.2.

Complete build with:
  • Streaming proxy — HTML / CSS / HLS rewritten, everything else raw
    passthrough with original Content-Encoding (browser decodes natively).
  • Multi-IP connect via DoH + system DNS, IPv4 preferred.
  • Per-session editable cookie jar.
  • File viewer, site tree crawler, directory brute.
  • 400+ vulnerability scanner (scanner.py) exposed at /tool/vulnscan.
  • 30+ extended reconnaissance / injection / CORS / takeover tools.
  • Correct static asset serving with proper MIME types.
"""

import asyncio
import base64 as _b64
import gzip
import hashlib as _hashlib
import ipaddress as _ipaddress
import json
import logging
import mimetypes
import os
import random as _random
import re
import socket
import ssl
import string as _string
import time
import uuid
import zlib
from collections import deque
from urllib.parse import (
    urljoin, urlparse, quote, unquote, parse_qs, parse_qsl, urlencode,
)

from bs4 import BeautifulSoup

from lynkio import (
    Lynk, Request, RawResponse, StreamingResponse,
    json_response, framework_version,
)

import scanner

# ----------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------
HERE          = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR    = os.path.join(HERE, "static")
TEMPLATES_DIR = os.path.join(HERE, "templates")

HOST              = "0.0.0.0"
PORT              = 8080

CONNECT_TIMEOUT   = 8.0
SSL_HANDSHAKE_TL  = 8.0
HEADER_TIMEOUT    = 40.0
BODY_IDLE_TIMEOUT = 90.0
DOH_TIMEOUT       = 5.0

MAX_REWRITE_BYTES = 8 * 1024 * 1024
MAX_CSS_BYTES     = 4 * 1024 * 1024
MAX_HLS_BYTES     = 2 * 1024 * 1024
MAX_HEADER_BYTES  = 128 * 1024
MAX_VIEW_BYTES    = 2 * 1024 * 1024

SESSION_COOKIE = "__lynk_sid"
ORIGIN_COOKIE  = "__lynk_origin"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("lynk.browser")


SEARCH_ENGINES = {
    "google":     ("Google",     "https://www.google.com/search?q={q}"),
    "bing":       ("Bing",       "https://www.bing.com/search?q={q}"),
    "ddg":        ("DuckDuckGo", "https://duckduckgo.com/html/?q={q}"),
    "duckduckgo": ("DuckDuckGo", "https://duckduckgo.com/html/?q={q}"),
    "brave":      ("Brave",      "https://search.brave.com/search?q={q}"),
    "wikipedia":  ("Wikipedia",  "https://en.wikipedia.org/w/index.php?search={q}"),
    "github":     ("GitHub",     "https://github.com/search?q={q}"),
}

BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/124.0.0.0 Safari/537.36"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Priority": "u=0, i",
}

FORWARD_REQUEST_HEADERS = {
    "authorization", "origin", "content-type",
    "if-none-match", "if-modified-since", "if-match", "if-unmodified-since",
    "range", "if-range",
    "accept-language", "x-requested-with",
}

FORWARD_RESPONSE_HEADERS = {
    "cache-control", "etag", "last-modified", "expires", "vary",
    "content-language", "content-disposition", "accept-ranges",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-expose-headers", "access-control-max-age",
    "access-control-allow-methods", "access-control-allow-headers",
    "content-encoding",
}

NEVER_EMIT = {"content-length", "transfer-encoding", "connection", "keep-alive"}

# ----------------------------------------------------------------------
# App
# ----------------------------------------------------------------------
app = Lynk(
    host=HOST, port=PORT, protocol="TCP", debug=False,
    serve_client=True, max_body_size=64 * 1024 * 1024,
)


# ======================================================================
# Sessions + cookie jar
# ======================================================================
class CookieJar:
    def __init__(self):
        self.by_origin = {}

    def set(self, origin, name, value, **attrs):
        jar = self.by_origin.setdefault(origin, {})
        jar[name] = {"value": value, **attrs}

    def delete(self, origin, name):
        if origin in self.by_origin:
            self.by_origin[origin].pop(name, None)

    def clear(self, origin):
        self.by_origin.pop(origin, None)

    def list(self, origin):
        return dict(self.by_origin.get(origin, {}))

    def header_for(self, origin):
        jar = self.by_origin.get(origin) or {}
        return "; ".join(f"{k}={v['value']}" for k, v in jar.items()
                         if v.get("value"))

    def merge_set_cookie(self, origin, raw):
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            return
        first = parts[0]
        if "=" not in first:
            return
        name, value = first.split("=", 1)
        name = name.strip(); value = value.strip()
        attrs = {}
        for p in parts[1:]:
            pl = p.lower()
            if pl.startswith("path="):      attrs["path"] = p.split("=", 1)[1]
            elif pl.startswith("domain="):  attrs["domain"] = p.split("=", 1)[1]
            elif pl.startswith("expires="): attrs["expires"] = p.split("=", 1)[1]
            elif pl.startswith("max-age="): attrs["max_age"] = p.split("=", 1)[1]
            elif pl.startswith("samesite="):attrs["samesite"] = p.split("=", 1)[1]
            elif pl == "secure":   attrs["secure"] = True
            elif pl == "httponly": attrs["httponly"] = True
        self.set(origin, name, value, **attrs)


class Session:
    def __init__(self):
        self.injected       = []
        self.source_cache   = {}
        self.history        = deque(maxlen=1000)
        self.last_origin    = ""
        self.recent_origins = deque(maxlen=24)
        self.cookies        = CookieJar()

    def note_origin(self, origin):
        now = time.time()
        self.recent_origins = deque(
            [(o, t) for (o, t) in self.recent_origins
             if o != origin and now - t < 300],
            maxlen=24,
        )
        self.recent_origins.appendleft((origin, now))


SESSIONS = {}


def get_session(sid):
    s = SESSIONS.get(sid)
    if s is None:
        s = SESSIONS[sid] = Session()
    return s


def session_from_req(req):
    sid = req.cookies.get(SESSION_COOKIE, "")
    if not sid or sid not in SESSIONS:
        sid = uuid.uuid4().hex
        get_session(sid)
        return sid, True
    return sid, False


# ======================================================================
# Small helpers
# ======================================================================
def esc(t):
    return (str(t).replace("&", "&amp;").replace("<", "&lt;")
                   .replace(">", "&gt;").replace('"', "&quot;"))


def _decompress(body, encoding):
    enc = (encoding or "").lower().strip()
    if not enc or enc == "identity":
        return body
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        pass
    return body


def detect_charset(ct, body):
    m = re.search(r'charset\s*=\s*["\']?([A-Za-z0-9_\-]+)', ct or "", re.I)
    if m:
        return m.group(1)
    m2 = re.search(rb'charset\s*=\s*["\']?([a-z0-9_\-]+)', body[:4096].lower())
    if m2:
        return m2.group(1).decode("ascii", "ignore")
    return "utf-8"


def extract_upstream(referer):
    if not referer:
        return ""
    try:
        p = urlparse(referer)
        if p.path != "/proxy":
            return ""
        u = (parse_qs(p.query).get("url") or [""])[0]
        up = urlparse(u)
        if up.scheme in ("http", "https") and up.netloc:
            return u
    except Exception:
        pass
    return ""


_SKIP = ("data:", "javascript:", "mailto:", "tel:", "blob:",
         "about:", "file:", "#")


def skip_url(v):
    return not v or any(v.strip().lower().startswith(s) for s in _SKIP)


def proxy_url(absu):
    return f"/proxy?url={quote(absu, safe='')}"


def looks_like_url(s):
    s = (s or "").strip()
    if not s:
        return False
    if s.startswith(("http://", "https://")):
        return True
    if " " in s:
        return False
    first = s.split("/", 1)[0]
    return "." in first and not first.startswith(".") and not first.endswith(".")


def _norm_host(h):
    if not h:
        return h
    if ":" in h:
        base, port = h.rsplit(":", 1)
        if port in ("80", "443"):
            return base
    return h


def _headers_all(hdrs, name):
    name = name.lower()
    return [v for k, v in hdrs if k == name]


def _header(hdrs, name, default=""):
    name = name.lower()
    for k, v in hdrs:
        if k == name:
            return v
    return default


def _rewrite_set_cookie(value, origin_host):
    parts = [p.strip() for p in value.split(";")]
    if not parts:
        return value
    kept = [parts[0]]
    has_samesite = False
    for p in parts[1:]:
        pl = p.lower()
        if pl.startswith("domain="):
            continue
        if pl == "secure":
            continue
        if pl.startswith("samesite="):
            has_samesite = True
        kept.append(p)
    if not has_samesite:
        kept.append("SameSite=Lax")
    return "; ".join(kept)


def is_self_target(req, target_url):
    try:
        p = urlparse(target_url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    incoming = (req.headers.get("host") or "").lower()
    if not incoming:
        return False
    in_host = _norm_host(incoming).split(":", 1)[0]
    t_host = (p.hostname or "").lower()
    if not t_host:
        return False
    return in_host == t_host


def _recover_origin(req, sess):
    ref = req.headers.get("referer", "")
    up = extract_upstream(ref)
    if up:
        p = urlparse(up)
        if p.scheme in ("http", "https") and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    cv = req.cookies.get(ORIGIN_COOKIE, "")
    if cv:
        p = urlparse(unquote(cv))
        if p.scheme in ("http", "https") and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    oh = req.headers.get("origin", "")
    if oh:
        p = urlparse(oh)
        if p.scheme in ("http", "https") and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    incoming = (req.headers.get("host") or "").lower()
    in_host = _norm_host(incoming).split(":", 1)[0]
    if sess.last_origin:
        p = urlparse(sess.last_origin)
        if p.netloc and (p.hostname or "").lower() != in_host:
            return sess.last_origin
    for entry in reversed(list(sess.history)):
        u = entry.get("url", "")
        p = urlparse(u)
        if (p.scheme in ("http", "https") and p.netloc
                and (p.hostname or "").lower() != in_host):
            return f"{p.scheme}://{p.netloc}"
    return ""


def error_page(title, message, status=500):
    return RawResponse(
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f'<title>{esc(title)} · Lynk</title><style>'
        'body{font-family:Inter,system-ui,sans-serif;background:#070b16;color:#e2e8f0;'
        'display:flex;align-items:center;justify-content:center;min-height:100vh;'
        'margin:0;padding:24px}'
        '.card{background:rgba(15,23,42,.68);border:1px solid rgba(148,163,184,.16);'
        'border-radius:20px;max-width:620px;width:100%;padding:32px;text-align:left}'
        '.ic{width:56px;height:56px;border-radius:16px;display:inline-grid;'
        'place-items:center;font-size:1.5rem;margin-bottom:18px;'
        'background:rgba(248,113,113,.2)}'
        'h1{font-size:1.35rem;margin:0 0 8px}'
        'p{color:#94a3b8;font-size:.92rem;line-height:1.6;margin:0 0 22px;'
        'word-break:break-word}'
        'a{display:inline-flex;gap:6px;background:linear-gradient(135deg,#38bdf8,#818cf8);'
        'color:#0b1220;padding:11px 20px;border-radius:10px;font-weight:700;'
        'text-decoration:none}'
        '</style></head><body><div class="card">'
        f'<div class="ic">⚠</div><h1>{esc(title)}</h1><p>{message}</p>'
        '<a href="/">← Back to Lynk</a></div></body></html>',
        status=status, content_type="text/html; charset=utf-8")


# ======================================================================
# HTML rewriter
# ======================================================================
class HTMLRewriter:
    def __init__(self, base_url, ctype, ctx):
        self.base = base_url
        self.ctype = ctype
        self.ctx = ctx

    def _rw_srcset(self, srcset, base):
        out = []
        for entry in srcset.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(None, 1)
            u = parts[0]
            tail = parts[1] if len(parts) > 1 else ""
            if skip_url(u):
                out.append(entry)
                continue
            absu = urljoin(base, u)
            out.append(f"{proxy_url(absu)} {tail}".strip() if tail
                       else proxy_url(absu))
        return ", ".join(out)

    def _rw_css(self, css, base):
        def sub_url(m):
            inner = m.group(1).strip().strip("'\"")
            if not inner or inner.startswith("data:"):
                return m.group(0)
            if inner.startswith("//"):
                return f"url('{proxy_url(urljoin(base, inner))}')"
            if skip_url(inner):
                return m.group(0)
            return f"url('{proxy_url(urljoin(base, inner))}')"

        def sub_import(m):
            q, inner = m.group(1), m.group(2).strip()
            if skip_url(inner) or inner.startswith("//"):
                return m.group(0)
            return f"@import {q}{proxy_url(urljoin(base, inner))}{q}"

        css = re.sub(r"url\(\s*([^)]+?)\s*\)", sub_url, css)
        css = re.sub(r"""@import\s+(["'])([^"']+)\1""", sub_import, css)
        return css

    def rewrite(self, raw):
        charset = detect_charset(self.ctype, raw)
        try:
            text = raw.decode(charset, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        try:
            soup = BeautifulSoup(text, "html.parser")
        except Exception:
            return raw
        base = self.base

        for tag in soup.find_all("base"):
            tag.decompose()
        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower().startswith("content-security"):
                meta.decompose()

        for tag in soup.find_all(["a", "link", "area"], href=True):
            h = tag["href"]
            if not skip_url(h):
                tag["href"] = proxy_url(urljoin(base, h))

        for tag in soup.find_all(
            ["img", "script", "iframe", "embed", "source", "video",
             "audio", "track", "input"], src=True):
            s = tag["src"]
            if not skip_url(s):
                tag["src"] = proxy_url(urljoin(base, s))

        for tag in soup.find_all("object", data=True):
            d = tag["data"]
            if not skip_url(d):
                tag["data"] = proxy_url(urljoin(base, d))

        for attr in ("data-src", "data-original", "data-lazy-src",
                     "data-url", "data-href", "data-image"):
            for tag in soup.find_all(attrs={attr: True}):
                v = tag[attr]
                if not skip_url(v):
                    tag[attr] = proxy_url(urljoin(base, v))

        for attr in ("srcset", "data-srcset"):
            for tag in soup.find_all(attrs={attr: True}):
                tag[attr] = self._rw_srcset(tag[attr], base)

        for tag in soup.find_all("video", poster=True):
            p = tag["poster"]
            if not skip_url(p):
                tag["poster"] = proxy_url(urljoin(base, p))

        for meta in soup.find_all("meta", attrs={"property": True}):
            prop = (meta.get("property") or "").lower()
            if prop in ("og:image", "og:url", "og:video",
                        "twitter:image", "twitter:url"):
                v = meta.get("content", "")
                if v and not skip_url(v):
                    meta["content"] = proxy_url(urljoin(base, v))

        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            action = form.get("action") or base
            absu = urljoin(base, action)
            if method == "get":
                form["action"] = "/proxy"
                for ex in form.find_all("input", attrs={"name": "url"}):
                    ex.decompose()
                h = soup.new_tag("input")
                h["type"] = "hidden"; h["name"] = "url"; h["value"] = absu
                form.append(h)
            else:
                form["action"] = proxy_url(absu)

        for tag in soup.find_all(style=True):
            tag["style"] = self._rw_css(tag["style"], base)
        for st in soup.find_all("style"):
            if st.string:
                st.string = self._rw_css(st.string, base)

        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower() == "refresh":
                content = meta.get("content", "")
                m = re.search(r"url\s*=\s*([^;]+)", content, re.I)
                if m:
                    u = m.group(1).strip().strip("'\"")
                    if not skip_url(u):
                        meta["content"] = re.sub(
                            r"url\s*=\s*[^;]+",
                            f"url={proxy_url(urljoin(base, u))}",
                            content, flags=re.I)

        for tag in soup.find_all(["script", "link"]):
            for a in ("integrity", "crossorigin", "nonce", "referrerpolicy"):
                tag.attrs.pop(a, None)

        head = soup.head or soup.new_tag("head")
        if not soup.head:
            soup.insert(0, head)

        boot = soup.new_tag("script")
        boot.string = (
            "if('serviceWorker' in navigator&&!window.__LYNK_SW__){"
            "window.__LYNK_SW__=1;"
            "navigator.serviceWorker.register('/lynkio/service-ws.js',{scope:'/'})"
            ".catch(function(e){})}"
        )
        head.insert(0, boot)

        target = soup.body or soup.html or soup
        ctx_s = soup.new_tag("script")
        ctx_s.string = f"window.__LYNK_CTX__={json.dumps(self.ctx)};"
        target.insert(0, ctx_s)

        ui = soup.new_tag("script"); ui["src"] = "/static/js/ui.js"
        icpt = soup.new_tag("script"); icpt["src"] = "/static/js/interceptor.js"
        target.insert(1, icpt)
        target.insert(2, ui)

        for snip in self.ctx.get("_injected", []):
            s = soup.new_tag("script"); s.string = snip; target.append(s)

        return str(soup).encode("utf-8", errors="ignore")


def rewrite_css_body(raw, base_url, ctype):
    charset = detect_charset(ctype, raw)
    try:
        text = raw.decode(charset, errors="replace")
    except LookupError:
        text = raw.decode("utf-8", errors="replace")
    return HTMLRewriter(base_url, ctype, {})._rw_css(text, base_url).encode("utf-8")


# ======================================================================
# HLS / M3U8 rewriter
# ======================================================================
_M3U8_URI_ATTR = re.compile(r'URI="([^"]+)"')


def rewrite_m3u8(text, base_url):
    out_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            out_lines.append(line)
            continue
        if stripped.startswith("#"):
            def sub_uri(m):
                u = m.group(1)
                if skip_url(u):
                    return m.group(0)
                absu = urljoin(base_url, u)
                return f'URI="{proxy_url(absu)}"'
            line = _M3U8_URI_ATTR.sub(sub_uri, line)
            out_lines.append(line)
            continue
        if skip_url(stripped):
            out_lines.append(line)
            continue
        absu = urljoin(base_url, stripped)
        out_lines.append(proxy_url(absu))
    return "\n".join(out_lines)


# ======================================================================
# DoH resolver
# ======================================================================
async def _doh_resolve(host, timeout=DOH_TIMEOUT):
    ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("1.1.1.1", 443, ssl=ctx,
                                    server_hostname="cloudflare-dns.com"),
            timeout=timeout)
    except Exception:
        return []
    try:
        path = f"/dns-query?name={quote(host)}&type=A"
        req = (f"GET {path} HTTP/1.1\r\nHost: cloudflare-dns.com\r\n"
               f"Accept: application/dns-json\r\nConnection: close\r\n\r\n").encode()
        writer.write(req); await writer.drain()
        buf = bytearray(); deadline = time.monotonic() + timeout
        while b"\r\n\r\n" not in buf:
            if time.monotonic() > deadline:
                return []
            chunk = await asyncio.wait_for(reader.read(4096), timeout=1.0)
            if not chunk:
                break
            buf.extend(chunk)
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        text = head.decode("latin-1")
        cl = re.search(r"Content-Length:\s*(\d+)", text, re.I)
        if cl:
            need = int(cl.group(1)) - len(rest)
            while need > 0:
                chunk = await asyncio.wait_for(
                    reader.read(min(4096, need)), timeout=1.0)
                if not chunk:
                    break
                rest += chunk; need -= len(chunk)
        data = json.loads(rest.decode("utf-8", errors="replace"))
        return [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
    except Exception:
        return []
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _resolve_host(host, port, prefer_ipv4=True, use_doh=True):
    ips = []
    if use_doh:
        try:
            for ip in await _doh_resolve(host):
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
    try:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET if prefer_ipv4 else 0
        infos = await loop.getaddrinfo(host, port, family=family,
                                       type=socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if prefer_ipv4 and ":" in ip:
                continue
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


# ======================================================================
# Upstream request builder
# ======================================================================
def _build_request(method, target_url, headers, body):
    p = urlparse(target_url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    method = method.upper()
    lines = [f"{method} {path} HTTP/1.1", f"Host: {p.netloc}"]
    sent_conn = False
    for k, v in headers.items():
        kl = k.lower()
        if kl == "host":       continue
        if kl == "connection": sent_conn = True; continue
        if kl == "content-length": continue
        lines.append(f"{k}: {v}")
    body_bytes = b""
    if body is not None:
        if isinstance(body, bytes):
            body_bytes = body
        elif isinstance(body, (bytearray, memoryview)):
            body_bytes = bytes(body)
        else:
            body_bytes = str(body).encode("utf-8")
    if body_bytes or method in ("POST", "PUT", "PATCH"):
        lines.append(f"Content-Length: {len(body_bytes)}")
    if not sent_conn:
        lines.append("Connection: close")
    lines.append(""); lines.append("")
    payload = "\r\n".join(lines).encode("latin-1", errors="replace")
    if body_bytes:
        payload += body_bytes
    return host, port, p.scheme, payload


def _get_proxy_for(scheme):
    var_list = (("HTTPS_PROXY", "https_proxy") if scheme == "https"
                else ("HTTP_PROXY", "http_proxy"))
    for var in var_list:
        v = os.environ.get(var)
        if v:
            p = urlparse(v)
            if p.hostname:
                return p.hostname, (p.port or
                                    (443 if p.scheme == "https" else 80))
    return None


async def _open_via_proxy(proxy, target_host, target_port, ssl_ctx):
    proxy_host, proxy_port = proxy
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    connect = (f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
               f"Host: {target_host}:{target_port}\r\n\r\n").encode()
    writer.write(connect); await writer.drain()
    status = await asyncio.wait_for(reader.readline(), timeout=10.0)
    if b"200" not in status:
        try: writer.close()
        except Exception: pass
        raise ConnectionError(f"proxy CONNECT rejected: {status!r}")
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if line in (b"\r\n", b"\n", b""):
            break
    if ssl_ctx is not None:
        transport = writer.transport
        protocol = transport.get_protocol()
        loop = asyncio.get_running_loop()
        new_transport = await loop.start_tls(transport, protocol, ssl_ctx,
                                             server_hostname=target_host)
        writer._transport = new_transport
    return reader, writer


async def _open_upstream_stream(target_url, method, headers, body):
    host, port, scheme, payload = _build_request(method, target_url,
                                                  headers, body)
    ssl_ctx = None
    if scheme == "https":
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = True
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ssl_ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass

    proxy = _get_proxy_for(scheme)
    if proxy:
        try:
            reader, writer = await asyncio.wait_for(
                _open_via_proxy(proxy, host, port, ssl_ctx),
                timeout=CONNECT_TIMEOUT)
        except Exception as e:
            raise ConnectionError(f"proxy CONNECT failed: {e}")
    else:
        resolved = await _resolve_host(host, port, prefer_ipv4=True,
                                        use_doh=True)
        candidates = resolved if resolved else [host]
        reader = writer = None
        last_exc = None
        for ip in candidates:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        ip, port, ssl=ssl_ctx,
                        server_hostname=host if ssl_ctx else None,
                        ssl_handshake_timeout=SSL_HANDSHAKE_TL),
                    timeout=CONNECT_TIMEOUT)
                break
            except Exception as e:
                last_exc = e
                reader = writer = None
        if writer is None:
            raise ConnectionError(
                f"all addresses for {host}:{port} failed; last: "
                f"{type(last_exc).__name__}: {last_exc}")

    try:
        writer.write(payload); await writer.drain()
    except Exception as e:
        try: writer.close()
        except Exception: pass
        raise ConnectionError(f"write failed: {e}")

    buf = bytearray(); deadline = time.monotonic() + HEADER_TIMEOUT
    while b"\r\n\r\n" not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try: writer.close()
            except Exception: pass
            raise TimeoutError("headers timeout")
        try:
            chunk = await asyncio.wait_for(reader.read(8192),
                                           timeout=remaining)
        except asyncio.TimeoutError:
            try: writer.close()
            except Exception: pass
            raise TimeoutError("headers timeout")
        if not chunk:
            try: writer.close()
            except Exception: pass
            raise ConnectionError("closed before headers")
        buf.extend(chunk)
        if len(buf) > MAX_HEADER_BYTES:
            try: writer.close()
            except Exception: pass
            raise ConnectionError("headers too large")

    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    text = head.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        try: writer.close()
        except Exception: pass
        raise ConnectionError("empty response")
    parts = lines[0].split(" ", 2)
    try:
        status = int(parts[1])
    except Exception:
        try: writer.close()
        except Exception: pass
        raise ConnectionError(f"bad status line: {lines[0]!r}")

    hdrs = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs.append((k.strip().lower(), v.strip()))

    log.info("upstream %s %s → %d", method, target_url, status)
    return reader, writer, status, hdrs, rest


# ======================================================================
# Body readers
# ======================================================================
async def _iter_body(reader, headers, first_chunk=b"", chunk_size=65536):
    te = _header(headers, "transfer-encoding").lower()
    cl = _header(headers, "content-length")

    if "chunked" in te:
        buf = bytearray(first_chunk)
        while True:
            while b"\r\n" not in buf:
                chunk = await asyncio.wait_for(reader.read(4096),
                                               timeout=BODY_IDLE_TIMEOUT)
                if not chunk:
                    return
                buf.extend(chunk)
            le = buf.find(b"\r\n")
            size_line = bytes(buf[:le]).split(b";", 1)[0].strip()
            del buf[:le + 2]
            try:
                size = int(size_line, 16)
            except ValueError:
                return
            if size == 0:
                while True:
                    while b"\r\n" not in buf:
                        try:
                            more = await asyncio.wait_for(
                                reader.read(1024), timeout=1.0)
                        except asyncio.TimeoutError:
                            return
                        if not more:
                            return
                        buf.extend(more)
                    le = buf.find(b"\r\n")
                    line = bytes(buf[:le])
                    del buf[:le + 2]
                    if line == b"":
                        return
            while len(buf) < size + 2:
                chunk = await asyncio.wait_for(
                    reader.read(min(chunk_size, size + 2 - len(buf))),
                    timeout=BODY_IDLE_TIMEOUT)
                if not chunk:
                    return
                buf.extend(chunk)
            yield bytes(buf[:size]); del buf[:size + 2]
        return

    if cl:
        try:
            length = int(cl)
        except ValueError:
            length = -1
        if length >= 0:
            sent = 0
            if first_chunk:
                take = min(len(first_chunk), length)
                if take:
                    yield bytes(first_chunk[:take]); sent = take
            while sent < length:
                to_read = min(chunk_size, length - sent)
                chunk = await asyncio.wait_for(reader.read(to_read),
                                               timeout=BODY_IDLE_TIMEOUT)
                if not chunk:
                    return
                sent += len(chunk); yield chunk
            return

    if first_chunk:
        yield first_chunk
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(chunk_size),
                                           timeout=BODY_IDLE_TIMEOUT)
        except asyncio.TimeoutError:
            return
        if not chunk:
            return
        yield chunk


async def _iter_body_identity(reader, headers, first_chunk=b""):
    ce = _header(headers, "content-encoding").lower().strip()
    raw = _iter_body(reader, headers, first_chunk)
    if not ce or ce == "identity":
        async for chunk in raw:
            yield chunk
        return
    if "gzip" in ce:
        wbits = 31
    elif "deflate" in ce:
        wbits = 15
    else:
        async for chunk in raw:
            yield chunk
        return
    decomp = zlib.decompressobj(wbits)
    tried_raw = (wbits != 15)
    async for chunk in raw:
        try:
            out = decomp.decompress(chunk)
        except zlib.error:
            if not tried_raw and wbits == 15:
                tried_raw = True
                decomp = zlib.decompressobj(-15)
                try:
                    out = decomp.decompress(chunk)
                except Exception:
                    out = b""
            else:
                out = b""
        if out:
            yield out
    try:
        tail = decomp.flush()
        if tail:
            yield tail
    except Exception:
        pass


# ======================================================================
# Header assembly
# ======================================================================
def _collect_request_headers(req):
    h = dict(BROWSER_HEADERS)
    for k, v in req.headers.items():
        if k.lower() in FORWARD_REQUEST_HEADERS and v:
            h[k] = v
    if "Range" in h or "range" in h:
        h["Accept-Encoding"] = "identity"
    return h


def _incoming_cookie_for_upstream(req):
    cookie = req.headers.get("cookie", "")
    if not cookie:
        return ""
    parts = []
    for p in cookie.split(";"):
        p = p.strip()
        if not p:
            continue
        name = p.split("=", 1)[0].strip().lower()
        if name in (SESSION_COOKIE, ORIGIN_COOKIE):
            continue
        parts.append(p)
    return "; ".join(parts)


def _build_response_headers(up_headers_list, is_rewritten):
    out = {}
    for k, v in up_headers_list:
        kl = k.lower()
        if kl in NEVER_EMIT:
            continue
        if kl == "location":
            continue
        if kl == "set-cookie":
            continue
        if kl == "content-encoding":
            if is_rewritten:
                continue
            out["Content-Encoding"] = v
            continue
        if kl in FORWARD_RESPONSE_HEADERS:
            if kl in out:
                if not isinstance(out[kl], list):
                    out[kl] = [out[kl]]
                out[kl].append(v)
            else:
                out[kl] = v
    return out


def _add_cookies_to_response(resp, up_headers_list, origin_host):
    for sc in _headers_all(up_headers_list, "set-cookie"):
        if not sc.strip():
            continue
        resp.add_header("Set-Cookie", _rewrite_set_cookie(sc, origin_host))


def _add_cookies_to_streaming(headers_dict, up_headers_list, origin_host):
    cookies = [_rewrite_set_cookie(sc, origin_host)
               for sc in _headers_all(up_headers_list, "set-cookie")
               if sc.strip()]
    if cookies:
        headers_dict["Set-Cookie"] = cookies


# ======================================================================
# Main proxy
# ======================================================================
async def serve_proxied(req, target_url, sid):
    sess = get_session(sid)
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    if is_self_target(req, target_url):
        recovered = _recover_origin(req, sess)
        if recovered:
            rp = urlparse(recovered)
            if (rp.hostname or "").lower() != (parsed.hostname or "").lower():
                new_target = f"{rp.scheme}://{rp.netloc}{parsed.path}"
                if parsed.query:
                    new_target += "?" + parsed.query
                target_url = new_target
                parsed = urlparse(target_url)
                origin = f"{parsed.scheme}://{parsed.netloc}"
        if is_self_target(req, target_url):
            return error_page(
                "Refusing to proxy to itself",
                f"<code>{esc(target_url)}</code> is this proxy.",
                508)

    sess.last_origin = origin
    sess.note_origin(origin)

    if target_url in sess.source_cache:
        return RawResponse(sess.source_cache[target_url],
                           content_type="text/html; charset=utf-8")

    out_headers = _collect_request_headers(req)
    out_headers["Referer"] = (extract_upstream(req.headers.get("referer", ""))
                              or (origin + "/"))

    browser_cookie = _incoming_cookie_for_upstream(req)
    jar_cookie = sess.cookies.header_for(origin)
    merged = {}
    for c in (browser_cookie or "").split(";"):
        c = c.strip()
        if "=" in c:
            k, v = c.split("=", 1)
            merged[k.strip()] = v.strip()
    for c in (jar_cookie or "").split(";"):
        c = c.strip()
        if "=" in c:
            k, v = c.split("=", 1)
            merged[k.strip()] = v.strip()
    if merged:
        out_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in merged.items())

    try:
        reader, writer, status, up_headers, first = \
            await _open_upstream_stream(target_url, req.method,
                                        out_headers, req.body)
    except Exception as e:
        log.warning("upstream open failed for %s: %s", target_url, e)
        return error_page(
            "Fetch failed",
            f"<b>{esc(type(e).__name__)}</b><br>{esc(str(e))}<br>"
            f"<span style=\"color:#64748b;font-size:.8rem\">"
            f"target: {esc(target_url)}</span>",
            502)

    for sc in _headers_all(up_headers, "set-cookie"):
        try:
            sess.cookies.merge_set_cookie(origin, sc)
        except Exception:
            pass

    ctype = (_header(up_headers, "content-type")
             or "application/octet-stream").strip()
    low_ct = ctype.lower()
    ce = _header(up_headers, "content-encoding").lower().strip()
    origin_host = parsed.hostname or ""
    path_lower = (parsed.path or "").lower()

    sess.history.append({"url": target_url, "status": status,
                         "method": req.method, "ts": time.time()})

    if 300 <= status < 400:
        loc = _header(up_headers, "location")
        resp_headers = _build_response_headers(up_headers, is_rewritten=True)
        if loc:
            try:
                resp_headers["Location"] = proxy_url(urljoin(target_url, loc))
            except Exception:
                resp_headers["Location"] = loc
        try: writer.close()
        except Exception: pass
        resp = RawResponse(b"", status=status, headers=resp_headers,
                           content_type="text/plain; charset=utf-8")
        _add_cookies_to_response(resp, up_headers, origin_host)
        resp.add_header("Set-Cookie",
                        f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
        resp.add_header("Set-Cookie",
                        f"{ORIGIN_COOKIE}={quote(origin, safe='')}; Path=/; Max-Age=86400; SameSite=Lax")
        return resp

    is_m3u8 = ("mpegurl" in low_ct
               or "application/vnd.apple" in low_ct
               or path_lower.endswith(".m3u8"))
    if is_m3u8:
        buf = bytearray(); oversized = False
        try:
            async for chunk in _iter_body(reader, up_headers, first):
                buf.extend(chunk)
                if len(buf) > MAX_HLS_BYTES:
                    oversized = True
                    break
        except Exception:
            pass
        try: writer.close()
        except Exception: pass

        if oversized:
            head_bytes = bytes(buf)
            resp_headers = _build_response_headers(up_headers,
                                                    is_rewritten=False)

            async def phls_raw():
                try:
                    async for chunk in _iter_body_identity(
                            reader, up_headers, head_bytes):
                        yield chunk
                except Exception:
                    pass

            _add_cookies_to_streaming(resp_headers, up_headers, origin_host)
            return StreamingResponse(
                phls_raw(),
                content_type="application/vnd.apple.mpegurl",
                headers=resp_headers, status=status)

        raw = bytes(buf)
        if ce and ce != "identity":
            raw = _decompress(raw, ce)
        charset = detect_charset(ctype, raw) or "utf-8"
        try:
            text = raw.decode(charset, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        rewritten = rewrite_m3u8(text, target_url)
        resp_headers = _build_response_headers(up_headers, is_rewritten=True)
        resp = RawResponse(rewritten.encode("utf-8"), status=status,
                           content_type="application/vnd.apple.mpegurl; charset=utf-8",
                           headers=resp_headers)
        _add_cookies_to_response(resp, up_headers, origin_host)
        resp.add_header("Set-Cookie",
                        f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
        resp.add_header("Set-Cookie",
                        f"{ORIGIN_COOKIE}={quote(origin, safe='')}; Path=/; Max-Age=86400; SameSite=Lax")
        return resp

    if "text/html" in low_ct or "application/xhtml" in low_ct:
        buf = bytearray(); rewritable = True
        try:
            async for chunk in _iter_body(reader, up_headers, first):
                buf.extend(chunk)
                if len(buf) > MAX_REWRITE_BYTES:
                    rewritable = False
                    break
        except Exception as e:
            log.debug("html read stopped: %s", e)
        try: writer.close()
        except Exception: pass

        if rewritable:
            raw = bytes(buf)
            if ce and ce != "identity":
                raw = _decompress(raw, ce)
            ctx = {"upstream": target_url, "sid": sid,
                   "_injected": [s["code"] for s in sess.injected
                                 if s["enabled"]]}
            body = HTMLRewriter(target_url, ctype, ctx).rewrite(raw)
            resp_headers = _build_response_headers(up_headers,
                                                    is_rewritten=True)
            resp = RawResponse(body, status=status,
                               content_type="text/html; charset=utf-8",
                               headers=resp_headers)
            _add_cookies_to_response(resp, up_headers, origin_host)
            resp.add_header("Set-Cookie",
                            f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
            resp.add_header("Set-Cookie",
                            f"{ORIGIN_COOKIE}={quote(origin, safe='')}; Path=/; Max-Age=86400; SameSite=Lax")
            return resp

        head_bytes = bytes(buf)
        resp_headers = _build_response_headers(up_headers, is_rewritten=False)

        async def passthrough_html():
            try:
                async for chunk in _iter_body_identity(
                        reader, up_headers, head_bytes):
                    yield chunk
            finally:
                try: writer.close()
                except Exception: pass

        _add_cookies_to_streaming(resp_headers, up_headers, origin_host)
        return StreamingResponse(passthrough_html(),
                                 content_type="text/html; charset=utf-8",
                                 headers=resp_headers, status=status)

    if "text/css" in low_ct:
        buf = bytearray(); oversized = False
        try:
            async for chunk in _iter_body(reader, up_headers, first):
                buf.extend(chunk)
                if len(buf) > MAX_CSS_BYTES:
                    oversized = True
                    break
        except Exception:
            pass
        try: writer.close()
        except Exception: pass

        if oversized:
            head_bytes = bytes(buf)
            resp_headers = _build_response_headers(up_headers,
                                                    is_rewritten=False)

            async def pcss():
                try:
                    async for chunk in _iter_body_identity(
                            reader, up_headers, head_bytes):
                        yield chunk
                finally:
                    try: writer.close()
                    except Exception: pass

            _add_cookies_to_streaming(resp_headers, up_headers, origin_host)
            return StreamingResponse(pcss(),
                                     content_type="text/css; charset=utf-8",
                                     headers=resp_headers, status=status)

        raw = bytes(buf)
        if ce and ce != "identity":
            raw = _decompress(raw, ce)
        rewritten = rewrite_css_body(raw, target_url, ctype)
        resp_headers = _build_response_headers(up_headers, is_rewritten=True)
        resp = RawResponse(rewritten, status=status,
                           content_type="text/css; charset=utf-8",
                           headers=resp_headers)
        _add_cookies_to_response(resp, up_headers, origin_host)
        return resp

    resp_headers = _build_response_headers(up_headers, is_rewritten=False)
    _add_cookies_to_streaming(resp_headers, up_headers, origin_host)

    async def passthrough():
        try:
            async for chunk in _iter_body(reader, up_headers, first):
                yield chunk
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            log.debug("stream aborted for %s: %s", target_url, e)
        finally:
            try: writer.close()
            except Exception: pass

    return StreamingResponse(passthrough(),
                             content_type=ctype,
                             headers=resp_headers, status=status)


async def _try_proxy_candidates(req, sess, sid, path_only, qs, candidates):
    for origin in candidates:
        target = origin.rstrip("/") + path_only
        if qs:
            target += "?" + qs
        try:
            out_headers = _collect_request_headers(req)
            out_headers["Referer"] = (
                extract_upstream(req.headers.get("referer", ""))
                or (origin + "/"))
            incoming_cookie = _incoming_cookie_for_upstream(req)
            if incoming_cookie:
                out_headers["Cookie"] = incoming_cookie

            reader, writer, status, up_headers, first = \
                await _open_upstream_stream(target, req.method,
                                            out_headers, req.body)
            if 400 <= status < 500 and status not in (401, 403):
                try: writer.close()
                except Exception: pass
                continue
            try: writer.close()
            except Exception: pass
            return await serve_proxied(req, target, sid)
        except Exception as e:
            log.debug("candidate %s failed: %s", origin, e)
            continue
    return None


# ======================================================================
# WebSocket control plane
# ======================================================================
WS_CLIENTS = set()


async def _broadcast(event, data, exclude_id=None):
    payload = json.dumps({"event": event, "data": data})
    for cid in list(app._clients_all.keys()):
        if cid == exclude_id:
            continue
        c = app._clients_all.get(cid)
        if c and not c.closed:
            try:
                await c.send(payload)
            except Exception:
                pass


@app.on("subscribe")
async def _on_subscribe(client, data):
    WS_CLIENTS.add(client.id)
    await client.send(json.dumps({
        "event": "subscribed",
        "data": {"client_id": client.id, "peer_count": len(WS_CLIENTS)},
    }))


@app.on("nav")
async def _on_nav(client, data):
    await _broadcast("nav", data, exclude_id=client.id)


@app.on("progress")
async def _on_progress(client, data):
    await _broadcast("progress", data, exclude_id=client.id)


@app.on("console")
async def _on_console(client, data):
    await _broadcast("console", data, exclude_id=client.id)


@app.on("ping")
async def _on_ping(client, data):
    await client.send(json.dumps({
        "event": "pong",
        "data": {"ts": time.time()},
    }))


@app.on_internal("connect")
async def _on_connect(client, data=None):
    log.info("ws connect %s", client.id)


@app.on_internal("disconnect")
async def _on_disconnect(client, data=None):
    WS_CLIENTS.discard(client.id)
    log.info("ws disconnect %s", client.id)


# ======================================================================
# Tool dispatch
# ======================================================================
TOOLS = {}


def tool(name):
    def deco(fn):
        TOOLS[name] = fn
        return fn
    return deco


async def _get_form(req):
    try:
        data = await req.form()
    except Exception:
        return {}
    if isinstance(data, dict) and "fields" in data:
        return data["fields"]
    return data


# ---- recon ----
@tool("headers")
async def t_headers(req):
    url = req.query_params.get("url") or ""
    if not url:
        return {"error": "missing url"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=15.0,
                            method="HEAD", allow_redirects=True, max_redirects=3,
                            prefer_http2=True, use_doh=True)
        return {"status": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        return {"status": 0, "headers": {"error": str(e)}}


@tool("source")
async def t_source(req):
    url = req.query_params.get("url") or ""
    if not url:
        return {"error": "missing url"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=20.0)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce:
            body = _decompress(body, ce)
        return {"body": body.decode("utf-8", errors="replace")[:500000]}
    except Exception as e:
        return {"error": str(e)}


@tool("dns")
async def t_dns(req):
    url = req.query_params.get("url") or ""
    host = urlparse(url).hostname or url
    addrs = []
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
        for info in infos:
            fam, _, _, _, sa = info
            ip = sa[0]
            tag = "IPv6" if fam == socket.AF_INET6 else "IPv4"
            entry = f"{ip} ({tag})"
            if entry not in addrs:
                addrs.append(entry)
    except Exception:
        pass
    return {"host": host, "addresses": addrs}


@tool("diag")
async def t_diag(req):
    url = req.query_params.get("url") or ""
    if not url:
        return {"error": "missing url"}
    return await app.diagnose_url(url)


@tool("history")
async def t_history(req):
    sid, _ = session_from_req(req)
    return {"entries": list(get_session(sid).history)[-60:][::-1]}


# ---- inject ----
@tool("inject/list")
async def t_inject_list(req):
    sid, _ = session_from_req(req)
    return {"snippets": [{"id": s["id"], "name": s["name"],
                          "enabled": s["enabled"], "size": len(s["code"])}
                         for s in get_session(sid).injected]}


@tool("inject/add")
async def t_inject_add(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    name = (fields.get("name") or "unnamed").strip()
    code = fields.get("code") or ""
    if not code.strip():
        return {"ok": False, "reason": "empty"}
    sess.injected.append({"id": uuid.uuid4().hex[:8], "name": name,
                          "code": code, "enabled": True})
    return {"ok": True}


# ---- cookies ----
@tool("cookies/list")
async def t_cookies_list(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    url = req.query_params.get("url") or sess.last_origin or ""
    origin = ""
    try:
        p = urlparse(url)
        origin = f"{p.scheme}://{p.netloc}"
    except Exception:
        pass
    jar = sess.cookies.list(origin) if origin else {}
    return {"origin": origin, "cookies": jar}


@tool("cookies/set")
async def t_cookies_set(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    origin = (fields.get("origin") or "").strip()
    name = (fields.get("name") or "").strip()
    value = fields.get("value") or ""
    if not origin or not name:
        return {"ok": False, "error": "origin and name required"}
    attrs = {}
    for k in ("path", "domain", "samesite", "expires"):
        v = fields.get(k)
        if v:
            attrs[k] = v
    if fields.get("secure"):
        attrs["secure"] = True
    if fields.get("httponly"):
        attrs["httponly"] = True
    sess.cookies.set(origin, name, value, **attrs)
    return {"ok": True}


@tool("cookies/delete")
async def t_cookies_delete(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    origin = (fields.get("origin") or "").strip()
    name = (fields.get("name") or "").strip()
    if not origin or not name:
        return {"ok": False}
    sess.cookies.delete(origin, name)
    return {"ok": True}


@tool("cookies/clear")
async def t_cookies_clear(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    origin = (fields.get("origin") or "").strip()
    if not origin:
        return {"ok": False}
    sess.cookies.clear(origin)
    return {"ok": True}


# ---- file view ----
def _classify_content(ctype, url):
    ct = (ctype or "").lower()
    path = urlparse(url).path.lower()
    if any(x in ct for x in ("text/", "json", "xml", "javascript", "yaml",
                              "csv", "html", "css", "x-sh", "sql")):
        return "text"
    if path.endswith((".txt", ".json", ".xml", ".html", ".htm", ".css",
                      ".js", ".mjs", ".ts", ".md", ".log", ".yml", ".yaml",
                      ".env", ".ini", ".conf", ".cfg", ".sh", ".sql", ".csv")):
        return "text"
    if any(x in ct for x in ("image/", "video/", "audio/")):
        return "media"
    if "pdf" in ct:
        return "pdf"
    if any(x in ct for x in ("zip", "gzip", "tar", "7z", "rar",
                              "octet-stream")):
        return "binary"
    return "binary"


@tool("file/view")
async def t_file_view(req):
    url = req.query_params.get("url") or ""
    if not url:
        return {"error": "missing url"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=20.0,
                            allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce:
            body = _decompress(body, ce)
        ctype = r.headers.get("content-type", "application/octet-stream")
        kind = _classify_content(ctype, url)
        result = {"url": url, "status": r.status_code, "content_type": ctype,
                  "size": len(body), "kind": kind}
        if kind == "text":
            charset = detect_charset(ctype, body)
            try:
                result["body"] = body.decode(charset,
                                             errors="replace")[:200000]
            except LookupError:
                result["body"] = body.decode("utf-8",
                                             errors="replace")[:200000]
            result["truncated"] = len(body) > 200000
        return result
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ---- tree ----
@tool("tree")
async def t_tree(req):
    base = req.query_params.get("url") or ""
    depth = int(req.query_params.get("depth") or 2)
    depth = max(1, min(3, depth))
    if not base:
        return {"error": "missing url"}
    try:
        p = urlparse(base)
        origin = f"{p.scheme}://{p.netloc}"
    except Exception:
        return {"error": "invalid url"}

    seen = set()
    tree = {"url": base, "type": "dir", "name": "/", "children": []}
    by_url = {base: tree}
    queue = [(base, 0)]
    max_nodes = 400

    while queue and len(seen) < max_nodes:
        current, cur_depth = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            r = await app.fetch(current, headers=BROWSER_HEADERS, timeout=15.0,
                                allow_redirects=True, max_redirects=3)
            if r.status_code != 200:
                continue
            ct = (r.headers.get("content-type", "") or "").lower()
            if "text/html" not in ct and "application/xhtml" not in ct:
                node = by_url.get(current)
                if node:
                    node["size"] = len(r.content)
                    node["content_type"] = ct
                continue
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce:
                body = _decompress(body, ce)
            charset = detect_charset(ct, body)
            try:
                text = body.decode(charset, errors="replace")
            except LookupError:
                text = body.decode("utf-8", errors="replace")
            try:
                soup = BeautifulSoup(text, "html.parser")
            except Exception:
                continue
            parent = by_url.get(current)
            if parent is None:
                continue
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or href.startswith(("#", "javascript:",
                                                "mailto:", "tel:")):
                    continue
                try:
                    absu = urljoin(current, href)
                except Exception:
                    continue
                ap = urlparse(absu)
                if ap.scheme not in ("http", "https"):
                    continue
                if ap.netloc != p.netloc:
                    continue
                if absu in seen:
                    continue
                name = a.get_text(" ", strip=True)[:60] or absu.split("/")[-1] or "/"
                is_dir = absu.endswith("/") or not name.count(".")
                child = {"url": absu, "type": "dir" if is_dir else "file",
                         "name": name, "children": [] if is_dir else None}
                if parent.get("children") is not None:
                    parent["children"].append(child)
                by_url[absu] = child
                if is_dir and cur_depth + 1 < depth:
                    queue.append((absu, cur_depth + 1))
        except Exception as e:
            log.debug("tree crawl %s failed: %s", current, e)

    return {"root": tree, "visited": len(seen), "origin": origin}


# ---- vulnerability scan ----
@tool("vulnscan")
async def t_vulnscan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    active = (fields.get("active")
              or req.query_params.get("active") or "1") == "1"
    if not url:
        return {"error": "missing url"}
    return await scanner.run_scan(url, app.fetch, active=active)


# ======================================================================
# Extended tools — every endpoint toolkit.js calls
# ======================================================================
_BRUTE_DEFAULT = [
    "admin","login","dashboard","api","api/v1","api/v2","graphql","swagger",
    "swagger.json","swagger-ui.html","openapi.json","docs","api-docs",
    "config","config.json","config.yml",".env","env",".git/config",
    "robots.txt","sitemap.xml","backup.zip","backup.tar.gz","backup.sql",
    "db.sql","dump.sql","test","dev","staging","uploads","files","static",
    "assets","console","manage","manager","panel","cpanel","phpinfo.php",
    "info.php","server-status","server-info","actuator","actuator/health",
    "metrics","health","healthz","status","version","VERSION","README.md",
    "CHANGELOG.md",".well-known/security.txt",".well-known/openid-configuration",
    "user","users","account","profile","settings","register","signup",
    "auth","oauth","token","tokens","keys","secret","secrets","internal",
    "private","tmp","temp","log","logs","debug","trace","test.php","index.php",
    "wp-login.php","wp-admin/","administrator/","xmlrpc.php",
]

_COMMON_PORTS = [
    (21,"FTP"),(22,"SSH"),(23,"Telnet"),(25,"SMTP"),(53,"DNS"),
    (80,"HTTP"),(110,"POP3"),(111,"rpcbind"),(135,"msrpc"),
    (139,"netbios"),(143,"IMAP"),(161,"snmp"),(389,"LDAP"),
    (443,"HTTPS"),(445,"SMB"),(465,"SMTPS"),(514,"syslog"),
    (587,"SMTP"),(636,"LDAPS"),(993,"IMAPS"),(995,"POP3S"),
    (1080,"SOCKS"),(1433,"MSSQL"),(1521,"Oracle"),(2049,"NFS"),
    (3000,"Node/Dev"),(3306,"MySQL"),(3389,"RDP"),(4443,"HTTPS-alt"),
    (5000,"Dev"),(5432,"PostgreSQL"),(5900,"VNC"),(5985,"WinRM-HTTP"),
    (6379,"Redis"),(6443,"K8s-API"),(7001,"WebLogic"),(8000,"HTTP-alt"),
    (8080,"HTTP-alt"),(8443,"HTTPS-alt"),(8888,"HTTP-alt"),
    (9000,"PHP-FPM/FastCGI"),(9090,"Prometheus"),(9200,"Elasticsearch"),
    (9300,"Elasticsearch"),(11211,"Memcached"),(27017,"MongoDB"),
    (50000,"SAP"),(50070,"Hadoop"),
]

_WAF_SIGNATURES = [
    ("Cloudflare",  ["cf-ray","cf-cache-status","server:cloudflare"]),
    ("AWS WAF",     ["x-amzn-requestid","x-amz-cf-id","awselb"]),
    ("Akamai",      ["akamai-grn","x-akamai"]),
    ("Sucuri",      ["x-sucuri-id","x-sucuri-cache"]),
    ("Imperva",     ["x-iinfo","visid_incap"]),
    ("F5 BIG-IP",   ["x-wa-info","bigipserver"]),
    ("Fastly",      ["x-served-by:cache","x-fastly"]),
    ("ModSecurity", ["mod_security","modsecurity"]),
    ("Barracuda",   ["barra_counter_session"]),
    ("Wordfence",   ["wordfence"]),
]

_TAKEOVER_SIGS = [
    ("GitHub Pages", ["there isn't a github pages site here",
                       "for root urls (like http://example.com) you must provide an index.html"]),
    ("Heroku",       ["no such app","heroku | no such app"]),
    ("AWS S3",       ["nosuchbucket","the specified bucket does not exist"]),
    ("Azure",        ["404 web site not found","the resource you are looking for has been removed"]),
    ("Shopify",      ["sorry, this shop is currently unavailable"]),
    ("Netlify",      ["not found - request id"]),
    ("Vercel",       ["the deployment you are trying to access was not found"]),
    ("Zendesk",      ["help center closed"]),
    ("Fastly",       ["fastly error: unknown domain"]),
    ("Surge.sh",     ["project not found"]),
    ("Bitbucket",    ["repository not found"]),
    ("Tumblr",       ["there's nothing here","whatever you were looking for doesn't currently exist"]),
    ("Pantheon",     ["the gods are wise, but do not know of the site which you seek"]),
    ("Cargo",        ["<title>404 &mdash; file not found</title>"]),
    ("WordPress",    ["do you want to register"]),
]


async def _fetch_json(url, headers=None, timeout=15.0):
    try:
        r = await app.fetch(url, headers=headers or BROWSER_HEADERS,
                            timeout=timeout, allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce:
            body = _decompress(body, ce)
        return json.loads(body.decode("utf-8", errors="replace")), r
    except Exception:
        return None, None


async def _fetch_text(url, headers=None, timeout=15.0):
    try:
        r = await app.fetch(url, headers=headers or BROWSER_HEADERS,
                            timeout=timeout, allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce:
            body = _decompress(body, ce)
        return body.decode("utf-8", errors="replace"), r
    except Exception:
        return "", None


def _origin_of(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _host_of(url):
    return urlparse(url).hostname or ""


@tool("agent-run")
async def t_agent_run(req):
    fields = await _get_form(req)
    code = fields.get("code") or ""
    if not code.strip():
        return {"ok": False, "error": "empty code"}
    def _no_import(*a, **k):
        raise ImportError("imports disabled in agent sandbox")
    safe_builtins = {
        "abs": abs, "all": all, "any": any, "bool": bool, "bytes": bytes,
        "chr": chr, "dict": dict, "dir": dir, "divmod": divmod,
        "enumerate": enumerate, "filter": filter, "float": float,
        "format": format, "frozenset": frozenset, "getattr": getattr,
        "hasattr": hasattr, "hash": hash, "hex": hex, "id": id,
        "int": int, "isinstance": isinstance, "issubclass": issubclass,
        "iter": iter, "len": len, "list": list, "map": map,
        "max": max, "min": min, "next": next, "oct": oct, "ord": ord,
        "pow": pow, "print": print, "range": range, "repr": repr,
        "reversed": reversed, "round": round, "set": set, "slice": slice,
        "sorted": sorted, "str": str, "sum": sum, "tuple": tuple,
        "type": type, "zip": zip, "True": True, "False": False, "None": None,
        "__import__": _no_import,
    }
    ns = {"__builtins__": safe_builtins, "result": None}
    try:
        compiled = compile(code, "<lynk-agent>", "exec")
        exec(compiled, ns, ns)
        return {"ok": True, "result": ns.get("result")}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


@tool("subdomains")
async def t_subdomains(req):
    fields = await _get_form(req)
    domain = (fields.get("domain") or req.query_params.get("domain") or "").strip().lower()
    if not domain:
        return {"error": "domain required"}
    data, _ = await _fetch_json(
        "https://crt.sh/?q=%25." + quote(domain) + "&output=json",
        timeout=25.0)
    if data is None:
        return {"error": "crt.sh unreachable"}
    subs = set()
    for entry in (data if isinstance(data, list) else []):
        for n in (entry.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain) and n:
                subs.add(n)
    return {"domain": domain, "subdomains": sorted(subs)}


@tool("portscan")
async def t_portscan(req):
    fields = await _get_form(req)
    host = (fields.get("host") or req.query_params.get("host") or "").strip()
    if not host:
        return {"error": "host required"}
    try:
        ip = host
        try:
            _ipaddress.ip_address(host)
        except ValueError:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None)
            ip = infos[0][4][0]
    except Exception as e:
        return {"error": f"resolve failed: {e}"}
    open_ports = []
    async def _probe(port, label):
        try:
            fut = asyncio.open_connection(ip, port)
            r, w = await asyncio.wait_for(fut, timeout=2.5)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            return {"port": port, "service": label}
        except Exception:
            return None
    results = await asyncio.gather(*[_probe(p, l) for p, l in _COMMON_PORTS])
    for r in results:
        if r: open_ports.append(r)
    return {"host": host, "ip": ip, "open": open_ports}


@tool("ssltls")
async def t_ssltls(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url if "://" in url else "https://" + url)
    host = p.hostname
    port = p.port or 443
    if not host:
        return {"error": "no host"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        loop = asyncio.get_running_loop()
        fut = loop.create_connection(
            asyncio.Protocol, host, port, ssl=ctx, server_hostname=host)
        _, writer = await asyncio.wait_for(fut, timeout=10.0)
        tls_obj = writer.get_extra_info("ssl_object")
        cert = tls_obj.getpeercert() if tls_obj else None
        cipher = tls_obj.cipher() if tls_obj else None
        version = tls_obj.version() if tls_obj else None
        alpn = tls_obj.selected_alpn_protocol() if tls_obj else None
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        out = {
            "host": host, "port": port,
            "tls_version": version or "",
            "cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else "",
            "alpn": alpn or "",
        }
        if cert:
            out["subject"] = {k: v for tup in cert.get("subject", ()) for k, v in tup}
            out["issuer"] = {k: v for tup in cert.get("issuer", ()) for k, v in tup}
            out["not_before"] = cert.get("notBefore", "")
            out["not_after"] = cert.get("notAfter", "")
            out["serial"] = str(cert.get("serialNumber", ""))
            out["subject_alt_names"] = [v for k, v in cert.get("subjectAltName", ())]
        return out
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@tool("tls-audit")
async def t_tls_audit(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url if "://" in url else "https://" + url)
    host, port = p.hostname, p.port or 443
    if not host:
        return {"error": "no host"}
    versions = []
    findings = []
    for label, proto in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                          ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
                          ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
                          ("TLS 1.3", ssl.TLSVersion.TLSv1_3)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto
            ctx.maximum_version = proto
            fut = asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
            r, w = await asyncio.wait_for(fut, timeout=8.0)
            cipher = w.get_extra_info("ssl_object").cipher()
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            versions.append({"version": label, "supported": True,
                             "cipher": cipher[0] if cipher else ""})
            if proto in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                findings.append({
                    "severity": "high", "name": f"{label} enabled",
                    "description": f"{label} is deprecated and insecure.",
                    "evidence": f"{label} handshake succeeded with {cipher[0] if cipher else '?'}",
                    "remediation": f"Disable {label} on the server.",
                })
        except Exception as e:
            versions.append({"version": label, "supported": False,
                             "error": type(e).__name__})
    return {"url": url, "versions": versions, "findings": findings}


@tool("waf")
async def t_waf(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    probes = []
    detected = set()
    attack_url = url + ("&" if "?" in url else "?") + "q=" + quote("<script>alert(1)</script>' OR 1=1--")
    try:
        r = await app.fetch(attack_url, headers=BROWSER_HEADERS, timeout=12.0,
                            allow_redirects=False, max_redirects=0)
        hl = {k.lower(): v for k, v in dict(r.headers).items()}
        blob = " ".join(f"{k}:{v}" for k, v in hl.items()).lower()
        for name, sigs in _WAF_SIGNATURES:
            for s in sigs:
                if s in blob:
                    detected.add(name); break
        probes.append({"label": "Attack probe", "status": r.status_code,
                       "blocked": r.status_code in (403, 406, 419, 429, 503)})
    except Exception as e:
        probes.append({"label": "Attack probe", "error": str(e)})
    try:
        r2 = await app.fetch(url, headers=BROWSER_HEADERS, timeout=10.0)
        hl2 = {k.lower(): v for k, v in dict(r2.headers).items()}
        blob2 = " ".join(f"{k}:{v}" for k, v in hl2.items()).lower()
        for name, sigs in _WAF_SIGNATURES:
            for s in sigs:
                if s in blob2:
                    detected.add(name); break
        probes.append({"label": "Baseline", "status": r2.status_code})
    except Exception as e:
        probes.append({"label": "Baseline", "error": str(e)})
    return {"url": url, "detected": sorted(detected), "probes": probes}


@tool("wayback")
async def t_wayback(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    data, _ = await _fetch_json(
        "https://web.archive.org/cdx/search/cdx?output=json&limit=40&url=" + quote(url),
        timeout=20.0)
    if not data or len(data) < 2:
        return {"url": url, "snapshots": []}
    snaps = []
    for row in data[1:]:
        if len(row) >= 3:
            ts, orig = row[1], row[2]
            snaps.append({
                "timestamp": ts,
                "url": f"https://web.archive.org/web/{ts}/{orig}",
            })
    return {"url": url, "snapshots": snaps[::-1]}


@tool("favicon")
async def t_favicon(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    out = {"url": url, "origin": origin, "hash": "", "size": 0, "mmh3": "", "status": 0}
    try:
        r = await app.fetch(origin + "/favicon.ico", headers=BROWSER_HEADERS,
                            timeout=12.0, allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        out["status"] = r.status_code
        out["size"] = len(body)
        if body:
            b64 = _b64.encodebytes(body).decode()
            out["hash"] = _hashlib.md5(b64.encode()).hexdigest()
            out["mmh3"] = _hashlib.sha1(body).hexdigest()[:16]
    except Exception as e:
        out["error"] = str(e)
    return out


@tool("well-known")
async def t_wellknown(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    paths = [
        "/.well-known/security.txt", "/.well-known/change-password",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json", "/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/host-meta", "/.well-known/nodeinfo",
        "/.well-known/webfinger", "/.well-known/dnt-policy.txt",
        "/.well-known/gpc.json", "/.well-known/mta-sts.txt",
        "/security.txt", "/humans.txt", "/robots.txt", "/sitemap.xml",
    ]
    results = []
    async def probe(path):
        try:
            r = await app.fetch(origin + path, headers=BROWSER_HEADERS,
                                timeout=8.0, allow_redirects=False, max_redirects=0)
            body = r.content
            return {"path": path, "url": origin + path,
                    "status": r.status_code, "length": len(body)}
        except Exception:
            return None
    rs = await asyncio.gather(*[probe(p) for p in paths])
    for r in rs:
        if r: results.append(r)
    return {"url": url, "results": results}


@tool("reverse-ip")
async def t_reverse_ip(req):
    fields = await _get_form(req)
    ip = (fields.get("ip") or req.query_params.get("ip") or "").strip()
    if not ip:
        return {"error": "ip or host required"}
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(ip, None)
            ip = infos[0][4][0]
        except Exception as e:
            return {"error": f"resolve failed: {e}"}
    text, _ = await _fetch_text(
        f"https://api.hackertarget.com/reverseiplookup/?q={quote(ip)}",
        timeout=15.0)
    if not text or "error" in text.lower()[:60] or "API count exceeded" in text:
        return {"ip": ip, "domains": [], "note": text[:200] if text else "no data"}
    domains = [d.strip() for d in text.splitlines() if d.strip() and not d.startswith("No")]
    return {"ip": ip, "domains": domains}


_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "\" autofocus onfocus=alert(1) x=\"",
]
_REDIRECT_PAYLOADS = [
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",
    "https:evil.example",
    "////evil.example",
    "/%09/evil.example",
]


async def _param_urls(url):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    return [(k, v[0] if v else "") for k, v in qs.items()]


def _replace_param(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    new_q = urlencode(qs, doseq=True)
    return p._replace(query=new_q).geturl()


@tool("xss-scan")
async def t_xss_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    params = await _param_urls(url)
    if not params:
        return {"url": url, "results": [], "note": "no query params"}
    results = []
    for pname, _ in params[:12]:
        for payload in _XSS_PAYLOADS:
            test = _replace_param(url, pname, payload)
            try:
                r = await app.fetch(test, headers=BROWSER_HEADERS,
                                    timeout=12.0, allow_redirects=True, max_redirects=3)
                body = r.content
                ce = r.headers.get("content-encoding")
                if ce: body = _decompress(body, ce)
                text = body.decode("utf-8", errors="replace")
                if payload in text:
                    idx = text.find(payload)
                    window = text[max(0, idx - 60):idx + len(payload) + 60]
                    results.append({
                        "param": pname, "payload": payload,
                        "verified": True, "tag": window,
                        "url": test, "status": r.status_code,
                    })
                    break
            except Exception:
                continue
    return {"url": url, "results": results}


@tool("open-redirect-scan")
async def t_open_redirect_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    params = await _param_urls(url)
    if not params:
        params = [("url", ""), ("redirect", ""), ("next", ""), ("return", ""),
                  ("returnUrl", ""), ("continue", ""), ("dest", "")]
    results = []
    for pname, _ in params[:12]:
        for payload in _REDIRECT_PAYLOADS:
            test = _replace_param(url, pname, payload)
            try:
                r = await app.fetch(test, headers=BROWSER_HEADERS, timeout=10.0,
                                    allow_redirects=False, max_redirects=0)
                loc = r.headers.get("location", "")
                if loc and "evil.example" in loc:
                    results.append({"param": pname, "payload": payload,
                                    "location": loc, "status": r.status_code,
                                    "url": test, "vulnerable": True})
                    break
            except Exception:
                continue
    return {"url": url, "results": results}


@tool("subdomain-takeover")
async def t_subdomain_takeover(req):
    fields = await _get_form(req)
    domain_field = (fields.get("domain") or req.query_params.get("domain") or "").strip()
    if not domain_field:
        return {"error": "domain required"}
    subs = [s.strip() for s in re.split(r"[\s,]+", domain_field) if s.strip()]
    results = []
    findings = []
    for sub in subs[:50]:
        entry = {"subdomain": sub, "cname": "", "matched": "", "confirmed": False,
                 "status": 0}
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(sub, None)
            entry["status"] = 200
        except Exception:
            pass
        data, _ = await _fetch_json(
            f"https://cloudflare-dns.com/dns-query?name={quote(sub)}&type=CNAME",
            headers={"Accept": "application/dns-json",
                     "User-Agent": BROWSER_HEADERS["User-Agent"]}, timeout=6.0)
        if data and data.get("Answer"):
            for a in data["Answer"]:
                if a.get("type") == 5:
                    entry["cname"] = a.get("data", "").rstrip(".")
                    break
        try:
            r = await app.fetch("https://" + sub, headers=BROWSER_HEADERS,
                                timeout=10.0, allow_redirects=True, max_redirects=3)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            text = body.decode("utf-8", errors="replace").lower()
            entry["status"] = r.status_code
            for svc, sigs in _TAKEOVER_SIGS:
                for s in sigs:
                    if s in text:
                        entry["matched"] = svc
                        entry["confirmed"] = True
                        findings.append({
                            "severity": "high",
                            "cwe": "CWE-1327",
                            "title": f"Subdomain takeover: {sub} → {svc}",
                            "desc": f"CNAME points at {svc} but the resource is unclaimed.",
                            "evidence": f"CNAME: {entry['cname']}\nMatched: {s}",
                            "remediation": f"Remove the {svc} DNS record or claim the resource.",
                            "tabUrl": f"https://{sub}",
                        })
                        break
                if entry["confirmed"]: break
        except Exception:
            pass
        results.append(entry)
    return {"results": results, "findings": findings}


@tool("mass-assign")
async def t_mass_assign(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    base_fields = (fields.get("fields") or "").strip()
    if not url:
        return {"error": "url required"}
    baseline = dict(parse_qsl(base_fields))
    extra_keys = ["admin","is_admin","isAdmin","role","roles","superuser",
                  "user_type","userType","permissions","verified","active",
                  "enabled","owner","account_id","tenant_id","group","groups",
                  "plan","tier","premium","balance","credits"]
    async def submit(fs):
        try:
            r = await app.fetch(url, method="POST", headers={
                **BROWSER_HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
            }, body=urlencode(fs).encode(), timeout=12.0,
                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return r.status_code, len(body), body[:200].decode("utf-8","replace")
        except Exception as e:
            return 0, 0, str(e)
    base_status, base_len, _ = await submit(baseline)
    results = []
    for k in extra_keys:
        fs = dict(baseline); fs[k] = "true"
        st, ln, snip = await submit(fs)
        differs = (st != base_status) or (abs(ln - base_len) > 24)
        results.append({"field": k, "status": st, "length": ln,
                        "differs": differs, "diff": snip[:120]})
    return {"url": url, "baseline": {"status": base_status, "length": base_len},
            "results": results}


@tool("host-header")
async def t_host_header(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url)
    origin_host = p.netloc
    tests = [
        ("Host", "evil.example"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Forwarded-Server", "evil.example"),
        ("X-Original-URL", "evil.example"),
        ("X-Rewrite-URL", "evil.example"),
        ("X-HTTP-Host-Override", "evil.example"),
        ("Forwarded", "host=evil.example"),
        ("X-Forwarded-For", "127.0.0.1"),
    ]
    results = []
    for hdr, val in tests:
        try:
            hdrs = dict(BROWSER_HEADERS); hdrs[hdr] = val
            r = await app.fetch(url, headers=hdrs, timeout=10.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            text = body.decode("utf-8", errors="replace")
            loc = r.headers.get("location", "")
            reflected = ("evil.example" in text) or ("evil.example" in loc) \
                        or (r.headers.get("host", "") == "evil.example")
            results.append({"header": hdr, "value": val,
                            "status": r.status_code,
                            "reflected": reflected,
                            "location": loc})
        except Exception as e:
            results.append({"header": hdr, "value": val, "error": str(e),
                            "reflected": False})
    return {"url": url, "results": results, "origin_host": origin_host}


@tool("crlf-scan")
async def t_crlf_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    payloads = ["%0d%0aX-Injected:lynk", "%0aX-Injected:lynk",
                "%0d%0aSet-Cookie:lynk=1", "%E5%98%8A%E5%98%8DX-Injected:lynk",
                "%23%0d%0aX-Injected:lynk"]
    results = []
    for pl in payloads:
        test = url + ("&" if "?" in url else "?") + "x=" + pl
        try:
            r = await app.fetch(test, headers=BROWSER_HEADERS, timeout=10.0,
                                allow_redirects=False, max_redirects=0)
            hl = {k.lower(): v for k, v in dict(r.headers).items()}
            injected = "x-injected" in hl or "lynk" in hl.get("set-cookie", "").lower()
            results.append({"payload": pl, "status": r.status_code,
                            "injected": injected,
                            "headers_seen": list(hl.keys())[:8]})
        except Exception as e:
            results.append({"payload": pl, "error": str(e), "injected": False})
    return {"url": url, "results": results}


@tool("smuggling")
async def t_smuggling(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    tests = [
        ("CL.TE", {"Content-Length": "6", "Transfer-Encoding": "chunked"}, b"0\r\n\r\nG"),
        ("TE.CL", {"Transfer-Encoding": "chunked", "Content-Length": "3"}, b"8\r\nSMUGGLED\r\n0\r\n\r\n"),
        ("TE space", {"Transfer-Encoding": "chunked ", "Content-Length": "4"}, b"5c\r\nGPOST / HTTP/1.1\r\n0\r\n\r\n"),
        ("TE obfusc", {"Transfer-Encoding": "xchunked", "Content-Length": "6"}, b"0\r\n\r\nG"),
        ("CL.CL", {"Content-Length": "6", "Content-Length": "4"}, b"0\r\n\r\nG"),
    ]
    results = []
    for label, hdrs, body in tests:
        t0 = time.monotonic()
        try:
            merged = {**BROWSER_HEADERS, **hdrs}
            r = await app.fetch(url, method="POST", headers=merged,
                                body=body, timeout=10.0,
                                allow_redirects=False, max_redirects=0)
            results.append({"label": label, "status": r.status_code,
                            "time": int((time.monotonic() - t0) * 1000)})
        except Exception as e:
            results.append({"label": label, "error": str(e),
                            "time": int((time.monotonic() - t0) * 1000)})
    return {"url": url, "results": results}


@tool("cache-poison")
async def t_cache_poison(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    headers = ["X-Forwarded-Host","X-Forwarded-Scheme","X-Forwarded-Proto",
               "X-Host","X-Forwarded-Server","X-Original-URL","X-Rewrite-URL",
               "X-Forwarded-Port","Forwarded"]
    results = []
    marker = "lynk" + uuid.uuid4().hex[:6]
    for hdr in headers:
        try:
            hdrs = dict(BROWSER_HEADERS); hdrs[hdr] = marker + ".example"
            r = await app.fetch(url, headers=hdrs, timeout=10.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            text = body.decode("utf-8", errors="replace")
            loc = r.headers.get("location", "")
            reflected = marker in text or marker in loc
            results.append({"header": hdr, "status": r.status_code,
                            "reflected": reflected,
                            "cache_control": r.headers.get("cache-control", ""),
                            "age": r.headers.get("age", "")})
        except Exception as e:
            results.append({"header": hdr, "error": str(e), "reflected": False})
    return {"url": url, "results": results}


@tool("cache-deception")
async def t_cache_deception(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url)
    path = p.path.rstrip("/")
    tricks = [path + "/nonexistent.css", path + "/nonexistent.js",
              path + "/nonexistent.jpg", path + "/;lynk.css",
              path + "/%2e%2e/lynk.css", path + "/.css", path + "/?x=.css"]
    results = []
    async def probe(u):
        try:
            r = await app.fetch(u, headers=BROWSER_HEADERS, timeout=8.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return {"url": u, "status": r.status_code, "length": len(body),
                    "cc": r.headers.get("cache-control", ""),
                    "xc": r.headers.get("x-cache", ""),
                    "differs": "?"}
        except Exception as e:
            return {"url": u, "error": str(e), "differs": "?"}
    origin = f"{p.scheme}://{p.netloc}"
    base_len = 0
    try:
        r0 = await app.fetch(url, headers=BROWSER_HEADERS, timeout=8.0)
        base_len = len(r0.content)
    except Exception: pass
    for t in tricks:
        u = origin + t
        out = await probe(u)
        out["differs"] = "same" if out.get("length") == base_len else "differs"
        results.append(out)
    return {"url": url, "results": results}


_WEBSHELL_PATHS = [
    "/shell.php","/cmd.php","/c99.php","/r57.php","/b374k.php","/webshell.php",
    "/backdoor.php","/indoxploit.php","/wso.php","/alfa.php","/marijuana.php",
    "/upload.php","/uploader.php","/uploadify.php","/adminer.php","/adminer/",
    "/phpinfo.php","/info.php","/test.php","/.shell.php","/1.php","/x.php",
    "/wp-content/uploads/shell.php","/uploads/shell.php",
]

@tool("webshell-scan")
async def t_webshell_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    hits = []
    async def probe(path):
        try:
            r = await app.fetch(origin + path, headers=BROWSER_HEADERS,
                                timeout=8.0, allow_redirects=False, max_redirects=0)
            if r.status_code in (200, 403, 401):
                body = r.content
                ce = r.headers.get("content-encoding")
                if ce: body = _decompress(body, ce)
                return {"path": path, "url": origin + path,
                        "status": r.status_code, "length": len(body),
                        "content_type": r.headers.get("content-type", "")}
        except Exception:
            pass
        return None
    rs = await asyncio.gather(*[probe(p) for p in _WEBSHELL_PATHS])
    for r in rs:
        if r: hits.append(r)
    return {"url": url, "hits": hits, "total": len(_WEBSHELL_PATHS)}


_BACKUP_PATHS = [
    "/backup.zip","/backup.tar","/backup.tar.gz","/backup.tgz","/backup.rar",
    "/backup.7z","/backup.sql","/backup.sql.gz","/backup.bak","/site.zip",
    "/www.zip","/html.zip","/public.zip","/web.zip","/files.zip","/source.zip",
    "/src.zip","/dist.zip","/release.zip",".env",".env.local",".env.production",
    "/.env",".git/config",".git/HEAD","/config.json","/config.yml","/config.yaml",
    "/wp-config.php.bak","/wp-config.php.old","/wp-config.php~",
    "/database.yml","/settings.py","/web.config","/appsettings.json",
    "/appsettings.Development.json","/dump.sql","/db.sql","/database.sql",
    "/.ssh/id_rsa","/.aws/credentials","/.npmrc","/.netrc",
    "/terraform.tfstate","/id_rsa",
]

@tool("backup-scan")
async def t_backup_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    hits = []
    results = []
    async def probe(path):
        try:
            r = await app.fetch(origin + path, headers=BROWSER_HEADERS,
                                timeout=8.0, allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return {"path": path, "url": origin + path,
                    "status": r.status_code, "length": len(body),
                    "content_type": r.headers.get("content-type", "")}
        except Exception as e:
            return {"path": path, "error": str(e), "status": 0}
    rs = await asyncio.gather(*[probe(p) for p in _BACKUP_PATHS])
    for r in rs:
        results.append(r)
        if r.get("status") in (200, 206) and r.get("length", 0) > 20:
            hits.append(r)
    return {"url": url, "hits": hits, "results": results}


@tool("brute")
async def t_brute(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    paths_raw = fields.get("paths") or req.query_params.get("paths") or ""
    paths = []
    if paths_raw:
        try:
            parsed = json.loads(paths_raw)
            if isinstance(parsed, list):
                paths = [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            paths = [p.strip() for p in paths_raw.splitlines() if p.strip()]
    if not paths:
        paths = list(_BRUTE_DEFAULT)
    origin = _origin_of(url)
    results = []
    async def probe(path):
        target = origin + "/" + path.lstrip("/")
        try:
            r = await app.fetch(target, headers=BROWSER_HEADERS, timeout=6.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return {"path": path, "url": target,
                    "status": r.status_code, "size": len(body),
                    "content_type": r.headers.get("content-type", "")}
        except Exception:
            return None
    sem = asyncio.Semaphore(20)
    async def guarded(p):
        async with sem:
            return await probe(p)
    rs = await asyncio.gather(*[guarded(p) for p in paths])
    for r in rs:
        if r: results.append(r)
    return {"url": url, "results": results}


@tool("js-endpoints")
async def t_js_endpoints(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=15.0,
                            allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        html = body.decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": str(e)}
    soup = BeautifulSoup(html, "html.parser")
    scripts = []
    for sc in soup.find_all("script"):
        if sc.get("src"):
            try:
                scripts.append(urljoin(url, sc["src"]))
            except Exception:
                pass
        elif sc.string:
            scripts.append(None)
    blobs = [html]
    for src in scripts[:15]:
        if not src: continue
        try:
            rr = await app.fetch(src, headers=BROWSER_HEADERS, timeout=12.0)
            b = rr.content
            ce2 = rr.headers.get("content-encoding")
            if ce2: b = _decompress(b, ce2)
            blobs.append(b.decode("utf-8", errors="replace"))
        except Exception:
            continue
    combined = "\n".join(blobs)
    abs_urls = set(re.findall(r'https?://[^\s"\'\)\}\]<>]+', combined))
    paths = set(re.findall(r'["\'](/[A-Za-z0-9_\-./%?=&]+)["\']', combined))
    endpoints = []
    base_origin = _origin_of(url)
    for u in abs_urls:
        endpoints.append({"absolute": u, "kind": "absolute"})
    for p in paths:
        if len(p) < 3 or p.startswith("//"): continue
        try:
            absu = urljoin(base_origin, p)
            endpoints.append({"absolute": absu, "kind": "relative"})
        except Exception:
            pass
    seen = set(); deduped = []
    for e in endpoints:
        if e["absolute"] in seen: continue
        seen.add(e["absolute"]); deduped.append(e)
    return {"url": url, "endpoints": deduped[:400]}


_API_PATHS = ["/api","/api/v1","/api/v2","/api/v3","/api/health","/api/status",
              "/api/users","/api/user","/api/login","/api/auth","/api/token",
              "/api/me","/api/config","/api/version","/api/docs","/api/search",
              "/api/items","/api/products","/api/orders","/api/admin",
              "/api/graphql","/api/internal","/api/debug","/rest","/rest/api",
              "/v1","/v2","/v3","/graphql","/gql","/query","/rpc"]

@tool("api-discover")
async def t_api_discover(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    results = []
    async def probe(path):
        target = origin + path
        try:
            r = await app.fetch(target, headers={**BROWSER_HEADERS, "Accept":"application/json, */*"},
                                timeout=6.0, allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return {"path": path, "url": target, "status": r.status_code,
                    "content_type": r.headers.get("content-type", ""),
                    "size": len(body)}
        except Exception:
            return None
    rs = await asyncio.gather(*[probe(p) for p in _API_PATHS])
    for r in rs:
        if r: results.append(r)
    return {"url": url, "results": results}


_PARAM_WORDLIST = [
    "id","q","s","search","query","page","limit","offset","lang","locale",
    "redirect","next","url","return","returnUrl","callback","file","path",
    "dir","folder","template","view","action","method","type","mode","format",
    "debug","test","admin","token","key","apikey","api_key","access_token",
    "user","username","email","name","category","tag","sort","order","filter",
    "start","end","from","to","date","include","exclude","fields","expand",
]

@tool("params")
async def t_params(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        base_r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=10.0,
                                 allow_redirects=False, max_redirects=0)
        base_body = base_r.content
        ce = base_r.headers.get("content-encoding")
        if ce: base_body = _decompress(base_body, ce)
        base_hash = _hashlib.md5(base_body).hexdigest()
        base_len = len(base_body)
        base_status = base_r.status_code
    except Exception as e:
        return {"error": str(e)}
    results = []
    async def probe(name):
        marker = "lynk" + uuid.uuid4().hex[:6]
        test = _replace_param(url, name, marker)
        try:
            r = await app.fetch(test, headers=BROWSER_HEADERS, timeout=8.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce2 = r.headers.get("content-encoding")
            if ce2: body = _decompress(body, ce2)
            h = _hashlib.md5(body).hexdigest()
            reflected = marker.encode() in body
            differs = (h != base_hash) or (r.status_code != base_status)
            delta = abs(len(body) - base_len)
            if reflected or differs:
                return {"name": name, "reflected": reflected,
                        "differs": differs, "diff": f"{'+' if delta>=0 else '-'}{abs(delta)}B",
                        "status": r.status_code}
        except Exception:
            pass
        return None
    rs = await asyncio.gather(*[probe(p) for p in _PARAM_WORDLIST])
    for r in rs:
        if r: results.append(r)
    return {"url": url, "results": results}


_GRAPHQL_INTROSPECTION = {
    "query": "{ __schema { queryType { name } mutationType { name } "
             "types { name kind } } }"
}

@tool("graphql")
async def t_graphql(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        r = await app.fetch(url, method="POST",
                            headers={**BROWSER_HEADERS,
                                     "Content-Type": "application/json",
                                     "Accept": "application/json"},
                            body=json.dumps(_GRAPHQL_INTROSPECTION).encode(),
                            timeout=15.0, allow_redirects=False, max_redirects=0)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    if "errors" in data and "data" not in data:
        return {"error": "introspection disabled or not a GraphQL endpoint",
                "raw": data}
    schema = (data.get("data") or {}).get("__schema") or {}
    types = [t.get("name") for t in (schema.get("types") or []) if t.get("name")]
    return {
        "url": url,
        "queries": [schema.get("queryType", {}).get("name", "")] if schema.get("queryType") else [],
        "mutations": [schema.get("mutationType", {}).get("name", "")] if schema.get("mutationType") else [],
        "types": types[:300],
    }


@tool("graphql-fuzz")
async def t_graphql_fuzz(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    probes = []
    def mk(label, payload):
        probes.append((label, payload))
    mk("Introspection", {"query": "{__schema{queryType{name}}}"})
    mk("Depth bomb", {"query": "{" + "a{" * 40 + "id" + "}" * 40 + "}"})
    mk("Alias bomb", {"query": "{" + " ".join(f"a{i}:__typename" for i in range(200)) + "}"})
    mk("Field suggestion", {"query": "{ __type(name: \"___nonexistent___){name}} "})
    mk("Mutation probe", {"query": "mutation{__typename}"})
    mk("Bad type", {"query": "{ __typename( ) }"})
    out = []
    for label, payload in probes:
        t0 = time.monotonic()
        try:
            r = await app.fetch(url, method="POST",
                                headers={**BROWSER_HEADERS,
                                         "Content-Type": "application/json"},
                                body=json.dumps(payload).encode(),
                                timeout=15.0, allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            out.append({"label": label, "status": r.status_code,
                        "length": len(body),
                        "time": int((time.monotonic() - t0) * 1000),
                        "snippet": body[:200].decode("utf-8", "replace")})
        except Exception as e:
            out.append({"label": label, "error": str(e),
                        "time": int((time.monotonic() - t0) * 1000)})
    return {"url": url, "probes": out}


@tool("cors-deep")
async def t_cors_deep(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url)
    host = p.netloc
    origins = [
        "https://evil.example", "null", "http://evil.example",
        "https://" + host + ".evil.example", "https://evil" + host,
        "https://" + host.replace(".", "x", 1),
        "https://sub." + host,
    ]
    probes = []
    findings = []
    for o in origins:
        try:
            r = await app.fetch(url, headers={**BROWSER_HEADERS, "Origin": o},
                                timeout=8.0, allow_redirects=False, max_redirects=0)
            hl = {k.lower(): v for k, v in dict(r.headers).items()}
            acao = hl.get("access-control-allow-origin", "")
            acac = hl.get("access-control-allow-credentials", "").lower()
            probes.append({"origin": o, "acao": acao, "acac": acac,
                           "status": r.status_code})
            if acac == "true" and (acao == o or acao == "*"):
                findings.append({
                    "severity": "high",
                    "name": f"CORS: origin '{o}' with credentials",
                    "evidence": f"ACAO: {acao}\nACAC: {acac}",
                    "tabUrl": url,
                })
        except Exception as e:
            probes.append({"origin": o, "error": str(e)})
    return {"url": url, "probes": probes, "findings": findings}


@tool("hsts-audit")
async def t_hsts_audit(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=10.0,
                            allow_redirects=False, max_redirects=0)
        hsts = r.headers.get("strict-transport-security", "")
    except Exception as e:
        return {"error": str(e)}
    low = hsts.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    return {
        "url": url,
        "hsts_header": hsts,
        "present": bool(hsts),
        "has_include_subdomains": "includesubdomains" in low,
        "has_preload": "preload" in low,
        "max_age": int(m.group(1)) if m else 0,
    }


@app.get("/tool/fetch")
async def t_fetch(req):
    url = req.query_params.get("url") or ""
    if not url:
        return json_response({"error": "url required"}, status=400)
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=30.0,
                            allow_redirects=True, max_redirects=5)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        ctype = r.headers.get("content-type", "application/octet-stream")
        resp = RawResponse(body, status=200, content_type=ctype)
        resp.add_header("Content-Disposition",
                        'attachment; filename="' + (urlparse(url).path.rsplit("/", 1)[-1] or "file") + '"')
        return resp
    except Exception as e:
        return json_response({"error": str(e)}, status=502)


# ======================================================================
# Static file serving
# ======================================================================
def _guess_mime(path):
    mt, _ = mimetypes.guess_type(path)
    if mt:
        return mt
    ext = os.path.splitext(path)[1].lower()
    return {
        ".js":   "application/javascript; charset=utf-8",
        ".mjs":  "application/javascript; charset=utf-8",
        ".cjs":  "application/javascript; charset=utf-8",
        ".css":  "text/css; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".htm":  "text/html; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".map":  "application/json; charset=utf-8",
        ".svg":  "image/svg+xml",
        ".wasm": "application/wasm",
        ".woff": "font/woff",
        ".woff2":"font/woff2",
        ".ttf":  "font/ttf",
        ".otf":  "font/otf",
        ".ico":  "image/x-icon",
        ".png":  "image/png",
        ".jpg":  "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif":  "image/gif",
        ".webp": "image/webp",
        ".avif": "image/avif",
        ".mp4":  "video/mp4",
        ".webm": "video/webm",
        ".mp3":  "audio/mpeg",
        ".wav":  "audio/wav",
        ".ogg":  "audio/ogg",
        ".txt":  "text/plain; charset=utf-8",
        ".md":   "text/markdown; charset=utf-8",
        ".xml":  "application/xml; charset=utf-8",
    }.get(ext, "application/octet-stream")


def _serve_static_file(rel_path):
    base_dir = STATIC_DIR
    sub = rel_path
    if rel_path.startswith("templates/"):
        base_dir = TEMPLATES_DIR
        sub = rel_path[len("templates/"):]

    sub = os.path.normpath(sub).lstrip("/\\")
    if sub.startswith("..") or os.path.isabs(sub):
        return None
    full = os.path.join(base_dir, sub)
    real_base = os.path.realpath(base_dir)
    real_full = os.path.realpath(full)
    if (not real_full.startswith(real_base + os.sep)
            and real_full != real_base):
        return None
    if not os.path.isfile(real_full):
        return None

    try:
        with open(real_full, "rb") as f:
            body = f.read()
    except Exception as e:
        log.warning("static read failed %s: %s", real_full, e)
        return None

    ctype = _guess_mime(real_full)
    resp = RawResponse(body, status=200, content_type=ctype)
    resp.add_header("Cache-Control", "no-cache, no-store, must-revalidate")
    resp.add_header("Access-Control-Allow-Origin", "*")
    return resp


@app.get("/static/*")
async def static_file(req, wildcard=""):
    path = (wildcard or "").split("?", 1)[0]
    resp = _serve_static_file(path)
    if resp is None:
        return error_page("Not found",
                          f"<code>/static/{esc(path)}</code> not found.", 404)
    return resp


@app.get("/favicon.ico")
async def favicon(req):
    for name in ("favicon.ico", "favicon.png", "favicon.svg"):
        resp = _serve_static_file(name)
        if resp is not None:
            return resp
    return RawResponse(b"", status=204, content_type="image/x-icon")


# ======================================================================
# Tool dispatcher (matches /tool/<name>)
# ======================================================================
@app.route("/tool/*", methods=["GET", "POST", "OPTIONS"])
async def tool_dispatch(req, wildcard=""):
    parts = (wildcard or "").split("?", 1)
    name = parts[0].strip("/")
    fn = TOOLS.get(name)
    if fn is None:
        return json_response({"error": f"unknown tool: {name}"}, status=404)
    try:
        result = await fn(req)
        if isinstance(result, (RawResponse, StreamingResponse)):
            return result
        return json_response(result)
    except Exception as e:
        log.exception("tool %s failed", name)
        return json_response({"error": f"{type(e).__name__}: {e}"}, status=500)


# ======================================================================
# HTTP routes
# ======================================================================
@app.get("/")
async def index(req):
    resp = _serve_static_file("templates/home.html")
    if resp is None:
        return error_page("Not found", "templates/home.html missing.", 404)
    return resp


@app.get("/tabs")
async def tabs_page(req):
    resp = _serve_static_file("templates/tabs.html")
    if resp is None:
        return error_page("Not found", "templates/tabs.html missing.", 404)
    return resp


@app.get("/search")
async def search(req):
    q = (req.query_params.get("q") or "").strip()
    engine = (req.query_params.get("engine") or "google").lower()
    if not q:
        return error_page("Empty query", "Type a search query.", 400)
    if engine not in SEARCH_ENGINES:
        engine = "google"
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
            try:
                urls = parse_qs(
                    req.body.decode("utf-8", errors="ignore")).get("url", [])
            except Exception:
                pass
    if not urls or not urls[0].strip():
        return error_page("Missing URL", "No <code>url</code> parameter.", 400)
    target = urls[0].strip()
    if qs:
        target += ("&" if "?" in target else "?") + urlencode(qs, doseq=True)
    if not target.startswith(("http://", "https://")):
        if looks_like_url(target):
            target = "https://" + target
        else:
            sid, _ = session_from_req(req)
            s_url = SEARCH_ENGINES["google"][1].replace("{q}", quote(target))
            return await serve_proxied(req, s_url, sid)
    p = urlparse(target)
    if p.scheme not in ("http", "https") or not p.netloc:
        return error_page("Invalid URL",
                          f"Could not parse: {esc(target)}", 400)
    sid, _ = session_from_req(req)
    return await serve_proxied(req, target, sid)


@app.route("/*", methods=["GET", "POST", "PUT", "PATCH",
                           "DELETE", "OPTIONS", "HEAD"])
async def catch_all(req, wildcard=""):
    parts = req.path.split("?", 1)
    path_only = parts[0] or "/"
    qs = parts[1] if len(parts) > 1 else ""

    if path_only == "/favicon.ico":
        return RawResponse(b"", status=204, content_type="image/x-icon")
    if path_only.startswith(("/static/", "/lynkio/", "/tool/", "/__lynk_")):
        return error_page("Not found",
                          f"<code>{esc(path_only)}</code> not found.", 404)

    sid, _ = session_from_req(req)
    sess = get_session(sid)

    candidates = []
    ref_origin = ""
    ref = req.headers.get("referer", "")
    up = extract_upstream(ref)
    if up:
        p = urlparse(up)
        if p.scheme in ("http", "https") and p.netloc:
            ref_origin = f"{p.scheme}://{p.netloc}"
            candidates.append(ref_origin)
    for (o, ts) in sess.recent_origins:
        if o not in candidates:
            candidates.append(o)
    cv = req.cookies.get(ORIGIN_COOKIE, "")
    if cv:
        p = urlparse(unquote(cv))
        if p.scheme in ("http", "https") and p.netloc:
            o = f"{p.scheme}://{p.netloc}"
            if o not in candidates:
                candidates.append(o)

    if not candidates:
        return error_page(
            "Lost context",
            f"Received <code>{esc(path_only)}</code> but couldn't determine "
            "the upstream host. <a href='/'>Go home</a> and start a new session.",
            404)

    result = await _try_proxy_candidates(req, sess, sid,
                                          path_only, qs, candidates)
    if result is not None:
        return result

    return error_page(
        "Not found",
        f"<code>{esc(path_only)}</code> — no origin served it.", 404)


@app.get("/healthz")
async def healthz(req):
    return json_response({
        "status": "ok",
        "framework": framework_version,
        "sessions": len(SESSIONS),
        "ws_clients": len(WS_CLIENTS),
        "https_proxy": bool(os.environ.get("HTTPS_PROXY")
                            or os.environ.get("https_proxy")),
        "static_dir": STATIC_DIR,
        "static_dir_exists": os.path.isdir(STATIC_DIR),
        "templates_dir": TEMPLATES_DIR,
        "templates_dir_exists": os.path.isdir(TEMPLATES_DIR),
        "scanner_loaded": True,
        "tools_registered": len(TOOLS),
    })


# ======================================================================
# Boot
# ======================================================================
if __name__ == "__main__":
    print("=" * 68)
    print(f"  🛠  Lynkio Browser — v17.1   (framework {framework_version})")
    print("=" * 68)
    print(f"  Home       →  http://localhost:{PORT}/")
    print(f"  Browser    →  http://localhost:{PORT}/tabs")
    print(f"  Proxy      →  http://localhost:{PORT}/proxy?url=…")
    print(f"  WS         →  ws://localhost:{PORT}/__lynk_ws")
    print(f"  Tools      →  /tool/<name>   ({len(TOOLS)} registered)")
    print(f"  Static     →  /static/*   (from {STATIC_DIR})")
    print(f"  Templates  →  /static/templates/*  (from {TEMPLATES_DIR})")
    print("=" * 68)
    print(f"  static exists:    {os.path.isdir(STATIC_DIR)}")
    print(f"  templates exists: {os.path.isdir(TEMPLATES_DIR)}")
    if os.path.isdir(STATIC_DIR):
        try:
            for root, dirs, files in os.walk(STATIC_DIR):
                for f in files:
                    rel = os.path.relpath(os.path.join(root, f), STATIC_DIR)
                    print(f"    static/{rel}")
        except Exception:
            pass
    if os.path.isdir(TEMPLATES_DIR):
        try:
            for f in sorted(os.listdir(TEMPLATES_DIR)):
                if os.path.isfile(os.path.join(TEMPLATES_DIR, f)):
                    print(f"    templates/{f}")
        except Exception:
            pass
    print("=" * 68)
    print(f"  Scanner: 400+ checks ready at /tool/vulnscan")
    print(f"  Toolkit: {len(TOOLS)} endpoints wired")
    print("=" * 68)
    app.run()