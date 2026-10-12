"""Build Retry-Safety Index badges from the named rows in retry-safety/index.html.

For every named row (not the aggregate rows) this writes:
  retry-safety/badge/<slug>.svg   a small README badge, colour by verdict tier
and adds id="r-<slug>" to the row so the badge can link straight to it.
retry-safety/badge/badges.json lists every badge with its verdict and target.

Tiers: "verified · battery run" (strongest), "verified · code read", "fixed".
Run: python3 scripts/make_badges.py   (idempotent)
"""
import html
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "retry-safety", "index.html")
OUT = os.path.join(ROOT, "retry-safety", "badge")
SITE = "https://aurumflux.co/retry-safety/"
SKIP = {"21 implementations", "16 implementations", "Everything else"}
COLORS = {"battery": "#1a7f37", "code": "#0b7285", "fixed": "#1f6feb"}
LABEL = "retry-safety"


def slugify(name):
    return re.sub(r"[^a-z0-9]+", "-", html.unescape(name).lower()).strip("-")


def text_width(s):
    # Verdana 11px approximation (as shields.io): narrow chars count less.
    w = 0.0
    for ch in s:
        w += 4.0 if ch in "il.,:;|!'·" else (5.0 if ch in "fjrt() " else (8.5 if ch in "mwMW" else 6.6))
    return int(w) + 10


def svg(label, message, color):
    lw, mw = text_width(label), text_width(message)
    w = lw + mw
    e = html.escape
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{e(label)}: {e(message)}">
<title>{e(label)}: {e(message)}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#2b2f33"/><rect x="{lw}" width="{mw}" height="20" fill="{color}"/><rect width="{w}" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="{lw/2:.1f}" y="15" fill="#010101" fill-opacity=".3">{e(label)}</text><text x="{lw/2:.1f}" y="14">{e(label)}</text>
<text x="{lw+mw/2:.1f}" y="15" fill="#010101" fill-opacity=".3">{e(message)}</text><text x="{lw+mw/2:.1f}" y="14">{e(message)}</text></g></svg>
'''


def main():
    s = open(PAGE, encoding="utf-8").read()
    rows = re.findall(r'<tr(?: id="r-[^"]+")?><td data-h="Implementation"><b>(.*?)</b>.*?<span class="pill (p-safe|p-fixed|p-open)">([^<]+)</span>(?:<br><span class="tier">([^<]*)</span>)?', s)
    badges = []
    for name, pill, verdict, tier in rows:
        plain = html.unescape(name)
        if plain in SKIP or pill == "p-open":
            continue
        slug = slugify(name)
        tier = (tier or "").strip()
        if pill == "p-safe" and tier.startswith("by battery run"):
            msg, color = "verified · battery run", COLORS["battery"]
        elif pill == "p-safe":
            msg, color = "verified · code read", COLORS["code"]
        else:
            msg, color = "fixed", COLORS["fixed"]
        with open(os.path.join(OUT, f"{slug}.svg"), "w", encoding="utf-8") as f:
            f.write(svg(LABEL, msg, color))
        badges.append({"name": plain, "slug": slug, "badge": f"{SITE}badge/{slug}.svg",
                       "row": f"{SITE}#r-{slug}", "verdict": msg})
        anchor = f'<tr><td data-h="Implementation"><b>{name}</b>'
        if anchor in s:
            s = s.replace(anchor, f'<tr id="r-{slug}"><td data-h="Implementation"><b>{name}</b>', 1)
    open(PAGE, "w", encoding="utf-8").write(s)
    with open(os.path.join(OUT, "badges.json"), "w", encoding="utf-8") as f:
        json.dump(badges, f, indent=1, ensure_ascii=False)
    print(f"{len(badges)} badges")
    for b in badges:
        print(f"  {b['verdict']:24s} {b['slug']}")


if __name__ == "__main__":
    main()
