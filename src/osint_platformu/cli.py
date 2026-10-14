"""``osint``: collect public records about a domain, read the report, compare runs, trace a claim to its evidence, validate the platform.

Subcommand and flag tokens are ASCII-transliterated Turkish (``tara`` = scan/collect, ``rapor`` = report, ``fark`` = difference, ``kanit`` = evidence,
``amac`` = purpose, ``hedef`` = target); the output is Turkish.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .engine import ALL_SOURCES, investigate
from .guard import ScopeError, normalize_domain
from .http import HttpClient
from .store import Store

DEFAULT_DB = "osint.db"

SOURCE_TABLE = [
    ("ct", "Sertifika seffafligi (crt.sh, yedek: Cert Spotter)", "domaine verilmis herkese acik sertifikalardaki alan adlari", "kisi bilgisi yok; e-posta adresleri silinir"),
    ("rdap", "RDAP (IANA bootstrap + kayit kurulusu)", "kayit/bitis tarihi, kayit kurulusu, ad sunuculari, DNSSEC", "kayitli kisi/yonetici/teknik iletisim bilgileri ASLA okunmaz"),
    ("dns", "DNS-over-HTTPS (Cloudflare, yedek: Google) + Team Cymru ASN", "A/AAAA/CNAME/MX/NS/TXT/CAA, SPF/DMARC/MTA-STS, adresin ASN'i", "yalnizca kesfedilen adlar; kaba kuvvet ile ad tahmini yok"),
    ("wayback", "Internet Archive CDX dizini", "arsivlenmis URL'ler ve alan adi sunuculari (yalnizca dizin; hicbir sayfa getirilmez)", "yol adlari 'aday' olarak raporlanir, dogrulanmaz"),
    ("web", "hedefin kendi robots.txt, security.txt, sitemap.xml dosyalari", "apex ve www uzerinde birer GET", "sayfa taranmaz; yalnizca security.txt iletisimleri saklanir"),
    ("github", "GitHub kamu API'si (organizasyon + depolar)", "depo sayisi, diller, son aktivite", "--github-org verilmezse atlanir; katilimci/commit yazari/e-posta yok"),
]


def _client(args, store):
    """The HTTP client for a scan; ``main(client=...)`` injects another one (the tests use a client confined to loopback)."""
    if getattr(args, "_client", None) is not None:
        return args._client
    return HttpClient(cache=None if args.onbellek_yok else store, min_interval=0.0)


def _open(args):
    return Store(args.db)


def _resolve_run(store, target, run=None):
    runs = store.runs(target)
    if not runs:
        raise LookupError(f"{target} icin kayitli calisma yok: once 'osint tara {target} --amac ...' calistirin")
    if run is None:
        return runs[-1]["id"], runs
    if run not in [r["id"] for r in runs]:
        raise LookupError(f"{target} icin {run} numarali calisma yok (var olanlar: {', '.join(str(r['id']) for r in runs)})")
    return run, runs


def _snapshot(store, target, run_id, runs):
    from .snapshot import build_snapshot
    meta = next(r for r in runs if r["id"] == run_id)
    return build_snapshot(store, run_id, target, meta["finished_at"] or meta["started_at"], meta["purpose"])


def cmd_tara(args):
    from .insights import findings
    store = _open(args)
    sources = [s.strip() for s in args.kaynak.split(",") if s.strip()] if args.kaynak else None
    options = {"github_org": args.github_org, "github_token": os.environ.get("GITHUB_TOKEN")}
    try:
        target = normalize_domain(args.hedef)
        print(f"Hedef: {target}   amac: {args.amac}")
        print("Yalnizca halka acik kayitlar okunur; hicbir sey taranmaz, gezilmez ya da yoklanmaz (ayrintilar: osint kaynaklar).")
        run_id, statuses = investigate(target, args.amac, store, _client(args, store), endpoints=getattr(args, "_endpoints", None), sources=sources, options=options,
                                       progress=lambda m: print("  " + m))
    except ScopeError as exc:
        print(f"Kapsam disi: {exc}", file=sys.stderr)
        return 2
    runs = store.runs(target)
    snap = _snapshot(store, target, run_id, runs)
    found = findings(snap)
    sev = {s: sum(1 for f in found if f.severity == s) for s in ("medium", "low", "info")}
    print(f"\nCalisma {run_id} tamamlandi: {len(snap.names)} ad, {len(snap.ips)} adres, {len(snap.asns)} ag; bulgu: {sev['medium']} orta, {sev['low']} dusuk, {sev['info']} bilgi.")
    bad = [s for s in statuses if s.state in ("error", "unavailable")]
    if bad:
        print("Dikkat, eksik kaynaklar: " + "; ".join(f"{s.source} ({s.state}: {s.detail})" for s in bad))
    print(f"Rapor icin: osint rapor --hedef {target}   (veritabani: {args.db})")
    return 0


def cmd_rapor(args):
    from .insights import findings
    from .report import render_markdown, to_json
    store = _open(args)
    try:
        target = normalize_domain(args.hedef)
        run_id, runs = _resolve_run(store, target, args.calisma)
    except (ScopeError, LookupError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    snap = _snapshot(store, target, run_id, runs)
    found = findings(snap)
    text = to_json(snap, found) if args.bicim == "json" else render_markdown(snap, found)
    if args.cikti:
        with open(args.cikti, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Rapor yazildi: {args.cikti}")
    else:
        print(text)
    return 0


def cmd_fark(args):
    from .diff import diff_snapshots, render_diff
    from .insights import findings
    store = _open(args)
    try:
        target = normalize_domain(args.hedef)
        runs = store.runs(target)
        if len(runs) < 2 and (args.eski is None or args.yeni is None):
            raise LookupError(f"{target} icin karsilastirilacak en az iki calisma gerekir (var: {len(runs)})")
        new_id = args.yeni if args.yeni is not None else runs[-1]["id"]
        old_id = args.eski if args.eski is not None else runs[-2]["id"]
        _resolve_run(store, target, new_id)
        _resolve_run(store, target, old_id)
    except (ScopeError, LookupError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    old, new = _snapshot(store, target, old_id, runs), _snapshot(store, target, new_id, runs)
    d = diff_snapshots(old, new, findings(old), findings(new))
    print(json.dumps(d, indent=2, ensure_ascii=False) if args.bicim == "json" else render_diff(d))
    return 0


def cmd_graf(args):
    from .plots import plot_graph
    store = _open(args)
    try:
        target = normalize_domain(args.hedef)
        run_id, runs = _resolve_run(store, target, args.calisma)
    except (ScopeError, LookupError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    plot_graph(_snapshot(store, target, run_id, runs), args.png)
    print(f"Grafik yazildi: {args.png}")
    return 0


def cmd_kanit(args):
    from .report import evidence
    store = _open(args)
    try:
        target = normalize_domain(args.hedef)
        run_id, _ = _resolve_run(store, target, args.calisma)
    except (ScopeError, LookupError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    rows = evidence(store, run_id, args.varlik)
    if not rows:
        print(f"'{args.varlik}' ile ilgili kayit bulunamadi.")
        return 1
    for r in rows:
        print(f"{r['subject']}  {r['predicate']}  {json.dumps(r['object'], ensure_ascii=False)}\n    kaynak: {r['source']}   kanit URL: {r['url']}\n    saklanan yanit SHA-256: {r['raw_sha256']}")
    return 0


def cmd_liste(args):
    store = _open(args)
    rows = store.investigations()
    if not rows:
        print("Kayitli arastirma yok.")
        return 0
    for r in rows:
        print(f"{r['target']}  ({r['runs']} calisma, ilk kayit {r['created_at']})  amac: {r['purpose']}")
        for run in store.runs(r["target"]):
            print(f"    calisma {run['id']}: {run['started_at']}  kaynaklar: {', '.join(json.loads(run['sources']))}")
    return 0


def cmd_kaynaklar(args):
    print("Kaynaklar ve sinirlar (hepsi halka acik; hicbiri kisi odakli degil):\n")
    for name, what, reads, limits in SOURCE_TABLE:
        print(f"  {name:8} {what}\n           okur: {reads}\n           sinir: {limits}")
    print("\nHedef yalnizca bir alan adi olabilir: e-posta, kisi adi, IP adresi, URL ve ozel/ozel-kullanim adlari reddedilir.")
    print("Hicbir calisma 'amac' belirtilmeden baslamaz; amac kayda gecer.")
    return 0


def cmd_dogrulama(args):
    from . import checks
    results = checks.run_all()
    for c in results:
        print(f"[{'GECTI' if c.passed else 'KALDI'}] {c.name}\n        {c.detail}")
    failed = [c for c in results if not c.passed]
    print(f"\n{len(results) - len(failed)}/{len(results)} dogrulama gecti.")
    return 0 if not failed else 1


def build_parser():
    p = argparse.ArgumentParser(prog="osint", description="Alan adlari icin pasif, halka acik kayitlara dayali OSINT platformu (kisi aramasi yok).")
    p.add_argument("--surum", action="version", version=f"osint {__version__}")
    p.add_argument("--db", default=DEFAULT_DB, help=f"SQLite veritabani (varsayilan: {DEFAULT_DB})")
    sub = p.add_subparsers(dest="komut", required=True)

    s = sub.add_parser("tara", help="bir alan adi icin halka acik kayitlari topla")
    s.add_argument("hedef", help="alan adi, ornek: example.org")
    s.add_argument("--amac", required=True, help="arastirmanin amaci (kayda gecer, zorunlu)")
    s.add_argument("--kaynak", help=f"virgulle ayrilmis kaynaklar (varsayilan hepsi): {', '.join(ALL_SOURCES)}")
    s.add_argument("--github-org", dest="github_org", help="GitHub organizasyon adi (tahmin edilmez; verilmezse atlanir)")
    s.add_argument("--onbellek-yok", action="store_true", dest="onbellek_yok", help="HTTP onbellegini kullanma")
    s.set_defaults(func=cmd_tara)

    s = sub.add_parser("rapor", help="bir calismanin raporu (Markdown/JSON)")
    s.add_argument("--hedef", required=True)
    s.add_argument("--calisma", type=int, help="calisma numarasi (varsayilan: son)")
    s.add_argument("--bicim", choices=["md", "json"], default="md")
    s.add_argument("--cikti", help="dosyaya yaz")
    s.set_defaults(func=cmd_rapor)

    s = sub.add_parser("fark", help="iki calisma arasindaki degisiklikler")
    s.add_argument("--hedef", required=True)
    s.add_argument("--eski", type=int)
    s.add_argument("--yeni", type=int)
    s.add_argument("--bicim", choices=["md", "json"], default="md")
    s.set_defaults(func=cmd_fark)

    s = sub.add_parser("graf", help="altyapi grafigi (PNG)")
    s.add_argument("--hedef", required=True)
    s.add_argument("--calisma", type=int)
    s.add_argument("--png", required=True)
    s.set_defaults(func=cmd_graf)

    s = sub.add_parser("kanit", help="bir varligin dayandigi kayitlari, kanit URL'sini ve saklanan yanitin ozetini goster")
    s.add_argument("--hedef", required=True)
    s.add_argument("--varlik", required=True, help="aranacak ad / adres / metin")
    s.add_argument("--calisma", type=int)
    s.set_defaults(func=cmd_kanit)

    s = sub.add_parser("liste", help="kayitli arastirmalar ve calismalar")
    s.set_defaults(func=cmd_liste)

    s = sub.add_parser("kaynaklar", help="kaynaklar, ne okuduklari ve sinirlari")
    s.set_defaults(func=cmd_kaynaklar)

    s = sub.add_parser("dogrulama", help="tum dogrulama deneylerini calistir")
    s.set_defaults(func=cmd_dogrulama)
    return p


def main(argv=None, endpoints=None, client=None):
    """Run the command line. ``endpoints`` and ``client`` replace the public services and the HTTP client (for tests and for private mirrors)."""
    args = build_parser().parse_args(argv)
    args._endpoints, args._client = endpoints, client
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
