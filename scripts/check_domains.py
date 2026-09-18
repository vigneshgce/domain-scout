#!/usr/bin/env python3
"""check_domains.py - batch availability + price triage for product domains.

Zero dependencies: Python 3.8+ standard library only.

Examples
  python3 check_domains.py name1 name2 name3
  python3 check_domains.py --file names.txt --tlds ai,com,dev --md domain-report.md --json domain-report.json
  PORKBUN_API_KEY=pk1_... PORKBUN_SECRET_API_KEY=sk1_... python3 check_domains.py example --exact
  python3 check_domains.py example --open unclear     # open registrar pages for anything UNCLEAR

How a verdict is reached (per domain, cheapest signal first)
  1. DNS-over-HTTPS NS lookup ....... NS records exist -> TAKEN
  2. RDAP at the registry ........... HTTP 200 -> TAKEN, HTTP 404 -> FREE
     (server found via the IANA bootstrap file; rdap.org used as a fallback)
  3. `whois` CLI, if installed ...... only when RDAP is unreachable
  4. Porkbun checkDomain (needs keys) purchasable? premium? exact price?

FREE means "not registered at the registry". Premium and reserved names also
look unregistered, so confirm the price at a registrar before announcing a winner.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

UA = "domain-scout/1.0 (batch availability triage)"
IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_ORG = "https://rdap.org/"
KNOWN_RDAP = {  # used only when the IANA bootstrap file cannot be fetched
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "ai": "https://rdap.identitydigital.services/rdap/",
    "dev": "https://www.registry.google/rdap/",
    "app": "https://www.registry.google/rdap/",
}
DOH = "https://cloudflare-dns.com/dns-query"
REGISTRARS = ("porkbun", "namecheap", "dynadot")
DEFAULT_REGISTRAR = "porkbun"
PORKBUN_PRICING = "https://api.porkbun.com/api/json/v3/pricing/get"
PORKBUN_CHECK = "https://api.porkbun.com/api/json/v3/domain/checkDomain/"

DEFAULT_TLDS = ["ai", "com", "dev"]
TIMEOUT = 12
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

WHOIS_TAKEN = re.compile(
    r"^\s*(domain name|registrar|creation date|registry domain id)\s*:", re.I | re.M
)
WHOIS_FREE = re.compile(
    r"(no match for|not found|no data found|no entries found|no object found|"
    r"domain not found|is available for|status:\s*available|available for registration)",
    re.I,
)

_bootstrap_lock = threading.Lock()
_bootstrap: dict | None = None


# ----------------------------------------------------------------------------- http
def http(url, method="GET", body=None, headers=None, timeout=TIMEOUT):
    """Return (status_code, parsed_json_or_None, raw_text, final_url). Never raises.
    status_code 0 means a network-level failure (DNS, TLS, timeout, no route)."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=hdrs, method=method)
    final_url = url
    try:
        with urlopen(req, timeout=timeout) as r:
            code, raw, final_url = r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except HTTPError as e:
        code, final_url = e.code, getattr(e, "url", url) or url
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            raw = ""
    except (URLError, OSError, ValueError) as e:  # OSError covers socket timeouts
        return 0, None, str(e), final_url
    try:
        return code, (json.loads(raw) if raw.strip() else None), raw, final_url
    except json.JSONDecodeError:
        return code, None, raw, final_url


# ----------------------------------------------------------------------------- signals
def rdap_base(tld: str) -> str | None:
    """RDAP base URL for a TLD from the IANA bootstrap file (cached), else a known default."""
    global _bootstrap
    with _bootstrap_lock:
        if _bootstrap is None:
            _bootstrap = {}
            code, js, _, _ = http(IANA_BOOTSTRAP)
            if code == 200 and isinstance(js, dict):
                for entry in js.get("services", []):
                    if len(entry) != 2:
                        continue
                    tlds, urls = entry
                    https = [u for u in urls if u.startswith("https://")] or urls
                    if not https:
                        continue
                    for t in tlds:
                        _bootstrap[t.lower()] = https[0].rstrip("/") + "/"
    return _bootstrap.get(tld) or KNOWN_RDAP.get(tld)


def doh_ns(domain: str):
    """True = NS records exist (taken). False = NXDOMAIN. None = inconclusive."""
    code, js, _, _ = http(f"{DOH}?name={quote(domain)}&type=NS",
                          headers={"Accept": "application/dns-json"})
    if code != 200 or not isinstance(js, dict):
        return None
    status = js.get("Status")
    if status == 3:
        return False
    if status == 0:
        return any(a.get("type") == 2 for a in (js.get("Answer") or [])) or None
    return None


def rdap_lookup(domain: str, tld: str):
    """Return (status, detail) with status in {'taken', 'free', 'unclear'}."""
    bases = [b for b in (rdap_base(tld), RDAP_ORG) if b]
    for base in bases:
        url = f"{base}domain/{quote(domain)}"
        for attempt in range(3):
            code, js, _, final = http(url, headers={"Accept": "application/rdap+json, application/json"})
            if code == 200 and isinstance(js, dict):
                if js.get("errorCode") == 404:
                    if urlparse(final).hostname == "rdap.org":
                        continue
                    return "free", f"rdap:{base}"
                if js.get("objectClassName") == "domain" or "ldhName" in js:
                    return "taken", f"rdap:{base}"
                return "unclear", f"rdap 200 with unrecognised body ({base})"
            if code == 404:
                if urlparse(final).hostname == "rdap.org":
                    continue  # Redirector does not know this TLD; not registry evidence.
                if isinstance(js, dict) and js.get("errorCode") == 404:
                    return "free", f"rdap:{base}"
                continue  # HTML/proxy 404s do not establish domain availability.
            if code == 429 or 500 <= code < 600:
                time.sleep(2 * (attempt + 1))  # back off, then retry the same server
                continue
            if code in (400, 422):
                return "unclear", f"rdap {code}: name rejected"
            break  # network failure (0) or an unexpected code: try the next base
    return "unclear", "rdap unreachable"


def whois_lookup(domain: str):
    exe = shutil.which("whois")
    if not exe:
        return "unclear", "whois CLI not installed"
    try:
        out = subprocess.run([exe, domain], capture_output=True, text=True, timeout=25).stdout
    except Exception as e:  # noqa: BLE001
        return "unclear", f"whois failed: {e}"
    if WHOIS_TAKEN.search(out):
        return "taken", "whois"
    if WHOIS_FREE.search(out):
        return "free", "whois"
    return "unclear", "whois output unrecognised"


def check_one(domain: str, tld: str, delay: float) -> dict:
    res = {"domain": domain, "tld": tld, "status": "unclear", "signal": "", "note": ""}
    ns = doh_ns(domain)
    if ns is True:
        res.update(status="taken", signal="dns: NS records exist")
        return res
    time.sleep(delay)
    status, detail = rdap_lookup(domain, tld)
    if status == "unclear":
        w_status, w_detail = whois_lookup(domain)
        if w_status != "unclear":
            status, detail = w_status, w_detail
        else:
            detail = f"{detail}; {w_detail}"
    res.update(status=status, signal=detail)
    return res


# ----------------------------------------------------------------------------- porkbun
def porkbun_pricing() -> dict:
    """{tld: {'registration': '9.13', 'renewal': '...'}} - public endpoint, no auth."""
    for method, body in (("POST", {}), ("GET", None)):
        code, js, _, _ = http(PORKBUN_PRICING, method=method, body=body)
        if code == 200 and isinstance(js, dict) and js.get("status") == "SUCCESS":
            return js.get("pricing") or {}
    return {}


def porkbun_exact(domain: str, key: str, secret: str) -> dict:
    code, js, _, _ = http(PORKBUN_CHECK + quote(domain), method="POST",
                          body={"apikey": key, "secretapikey": secret},
                          headers={"X-API-Key": key, "X-Secret-API-Key": secret})
    if code == 200 and isinstance(js, dict) and js.get("status") == "SUCCESS":
        r = js.get("response") or {}
        if not isinstance(r, dict) or r.get("avail") not in ("yes", "no"):
            return {"error": "unrecognised availability response"}
        return {
            "avail": r.get("avail"), "premium": r.get("premium"), "price": r.get("price"),
            "regular_price": r.get("regularPrice"), "first_year_promo": r.get("firstYearPromo"),
            "limits": js.get("limits") or {},
        }
    msg = js.get("message") if isinstance(js, dict) else None
    return {"error": msg or f"http {code}"}


# ----------------------------------------------------------------------------- helpers
def registrar_urls(domain: str) -> dict:
    return {
        "porkbun": f"https://porkbun.com/checkout/search?q={quote(domain)}",
        "namecheap": f"https://www.namecheap.com/domains/registration/results/?domain={quote(domain)}",
        "dynadot": f"https://www.dynadot.com/domain/search?domain={quote(domain)}",
    }


def parse_names(raw_names, file_path):
    names = list(raw_names)
    if file_path:
        with open(file_path, encoding="utf-8") as f:
            names += [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    seen, items, skipped = set(), [], []
    for n in names:
        n = n.strip().lower().replace("https://", "").replace("http://", "").strip("/").lstrip("@")
        if not n:
            continue
        label, _, tld = n.partition(".")
        override = [tld] if tld else None
        if not LABEL_RE.match(label) or (tld and not LABEL_RE.match(tld)):
            skipped.append(n)
            continue
        key = (label, tuple(override or []))
        if key in seen:
            continue
        seen.add(key)
        items.append((label, override))
    return items, skipped


def fmt_price(p):
    if p in (None, ""):
        return ""
    try:
        return f"${float(p):,.2f}"
    except (TypeError, ValueError):
        return str(p)


def cell(r: dict | None) -> str:
    if r is None:
        return "-"
    if r["status"] == "free":
        s = "FREE"
        if r.get("premium") == "yes":
            s += "*"
        price = fmt_price(r.get("price"))
        return f"{s} {price}".strip()
    if r["status"] == "taken":
        return "taken"
    return "?"


def best_tld(per_tld: dict, pref: list) -> str | None:
    for t in pref:
        r = per_tld.get(t)
        if r and r["status"] == "free" and r.get("premium") != "yes":
            return t
    for t in pref:  # premium is still "free", just expensive - rank it after regular
        r = per_tld.get(t)
        if r and r["status"] == "free":
            return t
    return None


def render_markdown(ranked, pref, pricing_source, exact_used, elapsed, registrar=DEFAULT_REGISTRAR):
    lines = ["# Domain check", "",
             f"_Checked {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC in {elapsed:.0f}s. "
             f"Preference order: {' > '.join('.' + t for t in pref)}. "
             f"Prices: {pricing_source or 'unavailable'}"
             f"{' + Porkbun exact check' if exact_used else ''}._", ""]
    head = "| # | name | " + " | ".join(f".{t}" for t in pref) + " | best |"
    sep = "|---|------|" + "|".join("------" for _ in pref) + "|------|"
    lines += [head, sep]
    for i, (name, per_tld, best) in enumerate(ranked, 1):
        cells = " | ".join(cell(per_tld.get(t)) for t in pref)
        lines.append(f"| {i} | {name} | {cells} | {('.' + best) if best else '-'} |")
    lines += ["", "FREE = registry evidence of no registration; list prices are estimates, not confirmed quotes. "
                  "FREE* = premium, priced per name. ? = could not determine, check by hand.", ""]

    counts = {t: sum(1 for _, p, _ in ranked if p.get(t) and p[t]["status"] == "free") for t in pref}
    lines.append("Summary: " + ", ".join(f"{counts[t]} free .{t}" for t in pref) + f" out of {len(ranked)} names.")

    unclear = [r for _, p, _ in ranked for r in p.values() if r["status"] == "unclear"]
    if unclear:
        lines += ["", "## Needs a manual look", ""]
        for r in unclear:
            u = registrar_urls(r["domain"])
            lines.append(f"- {r['domain']} ({r['signal']}) -> {u[registrar]}")
    winners = [(n, b) for n, p, b in ranked if b]
    if winners:
        lines += ["", "## Confirm before registering", "",
                  "Registry data cannot show premium or reserved pricing. Legacy gTLDs such as .com and .net "
                  "have no registry premium tiers, so an unregistered name there is standard-priced; many newer "
                  "TLDs (.dev, .ai and others) do tier names, so confirm those at a registrar:", ""]
        for n, b in winners[:5]:
            lines.append(f"- {n}.{b} -> {registrar_urls(f'{n}.{b}')[registrar]}")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="bare names (example) or full domains (example.ai)")
    ap.add_argument("--file", help="text file with one name per line (# comments allowed)")
    ap.add_argument("--tlds", default=",".join(DEFAULT_TLDS),
                    help="comma-separated, in preference order (default: ai,com,dev)")
    ap.add_argument("--json", dest="json_out", help="write full results to this JSON file")
    ap.add_argument("--md", dest="md_out", help="write the markdown report to this file")
    ap.add_argument("--no-price", action="store_true", help="skip the Porkbun price list")
    ap.add_argument("--exact", action="store_true",
                    help="confirm FREE names with Porkbun checkDomain (needs PORKBUN_API_KEY + PORKBUN_SECRET_API_KEY)")
    ap.add_argument("--max-exact", type=int, default=10, help="cap on exact checks (they are rate limited)")
    ap.add_argument("--registrar", choices=REGISTRARS, default=DEFAULT_REGISTRAR,
                    help=f"registrar for confirmation links and --open (default: {DEFAULT_REGISTRAR})")
    ap.add_argument("--open", choices=["none", "unclear", "free"], default="none",
                    help="open registrar pages in your browser for UNCLEAR or FREE results")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.3, help="pause before each RDAP call (be polite)")
    args = ap.parse_args(argv)

    pref = list(dict.fromkeys(t.strip().lower().lstrip(".") for t in args.tlds.split(",") if t.strip()))
    if not pref or any(not LABEL_RE.fullmatch(t) for t in pref):
        ap.error("--tlds must contain valid single-label TLDs, e.g. ai,com,dev")
    if args.delay < 0 or args.max_exact < 0:
        ap.error("--delay and --max-exact must be nonnegative")
    items, skipped = parse_names(args.names, args.file)
    if not items:
        ap.error("no valid names given (letters, digits, inner hyphens only)")
    for s in skipped:
        print(f"skipped invalid name: {s}", file=sys.stderr)

    jobs = [(f"{label}.{tld}", tld) for label, override in items for tld in (override or pref)]
    jobs = list(dict.fromkeys(jobs))
    for _, tld in jobs:
        if tld not in pref:
            pref.append(tld)  # Keep explicit domains visible even outside --tlds.
    for t in {tld for _, tld in jobs}:
        rdap_base(t)  # warm the bootstrap cache once, on the main thread
    print(f"checking {len(jobs)} domain/TLD combinations...", file=sys.stderr)
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        results = list(pool.map(lambda j: check_one(j[0], j[1], args.delay), jobs))

    pricing_source = None
    if not args.no_price:
        prices = porkbun_pricing()
        if prices:
            pricing_source = "Porkbun TLD list estimates (USD; confirm registration term)"
            for r in results:
                p = prices.get(r["tld"]) or {}
                if r["status"] == "free":
                    r["price"], r["renewal"] = p.get("registration"), p.get("renewal")
        else:
            print("price list unavailable (api.porkbun.com unreachable)", file=sys.stderr)

    exact_used = False
    key, secret = os.environ.get("PORKBUN_API_KEY"), os.environ.get("PORKBUN_SECRET_API_KEY")
    if args.exact:
        if not (key and secret):
            print("--exact ignored: set PORKBUN_API_KEY and PORKBUN_SECRET_API_KEY", file=sys.stderr)
        else:
            todo = [r for r in results if r["status"] == "free"][: args.max_exact]
            print(f"exact-checking {len(todo)} FREE names via Porkbun (rate limited, ~10s each)...", file=sys.stderr)
            for r in todo:
                x = porkbun_exact(r["domain"], key, secret)
                if "error" in x:
                    r["note"] = f"exact check failed: {x['error']}"
                else:
                    exact_used = True
                    r["exact"] = x
                    if x.get("avail") == "no":
                        r.update(status="taken", signal="porkbun: not available")
                    else:
                        r["premium"] = x.get("premium")
                        r["price"] = x.get("price") or r.get("price")
                        r["signal"] += "; porkbun confirmed"
                lim = x.get("limits") or {}
                try:
                    wait = float(lim.get("TTL", 10)) if float(lim.get("used", 1)) >= float(lim.get("limit", 1)) else 1
                except (TypeError, ValueError):
                    wait = 10
                if r is not todo[-1]:
                    time.sleep(wait)

    by_name: dict[str, dict] = {}
    for r in results:
        name = r["domain"][: -(len(r["tld"]) + 1)]
        by_name.setdefault(name, {})[r["tld"]] = r
    ranked = [(n, p, best_tld(p, pref)) for n, p in by_name.items()]
    ranked.sort(key=lambda x: (pref.index(x[2]) if x[2] in pref else 99,
                               1 if x[1].get(x[2], {}).get("premium") == "yes" else 0, len(x[0]), x[0]))

    md = render_markdown(ranked, pref, pricing_source, exact_used, time.time() - t0, args.registrar)
    print(md)
    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as f:
            f.write(md)
    if args.json_out:
        payload = {
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tld_preference": pref, "pricing_source": pricing_source, "exact_check": exact_used,
            "names": [{"name": n, "best": b, "checks": p,
                       "registrar_urls": registrar_urls(f"{n}.{b}") if b else None} for n, p, b in ranked],
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    if args.open != "none":
        want = "unclear" if args.open == "unclear" else "free"
        urls = [registrar_urls(r["domain"])[args.registrar] for r in results if r["status"] == want][:10]
        for u in urls:
            webbrowser.open(u)
        print(f"opened {len(urls)} registrar page(s) in your browser", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
