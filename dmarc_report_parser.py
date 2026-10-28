#!/usr/bin/env python3
"""DMARC report parser.

Legge i report aggregati DMARC (RUA) in formato XML, anche compressi
(.xml, .gz, .zip), e produce un riepilogo a terminale, CSV o JSON.

Solo libreria standard, nessuna dipendenza esterna.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import sys
import zipfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

__version__ = "0.1.0"


@dataclass
class Record:
    org_name: str
    report_id: str
    domain: str
    date_begin: str
    date_end: str
    source_ip: str
    count: int
    disposition: str
    dkim_result: str
    spf_result: str
    header_from: str

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_result == "pass" or self.spf_result == "pass"


def _text(node: ET.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    found = node.find(path)
    return (found.text or default).strip() if found is not None and found.text else default


def _ts(value: str) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError):
        return value


def read_xml_payloads(path: Path) -> list[bytes]:
    """Restituisce i contenuti XML di un file .xml, .gz o .zip."""
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return [gzip.decompress(raw)]
    if suffix == ".zip":
        out = []
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                if name.lower().endswith(".xml"):
                    out.append(zf.read(name))
        return out
    return [raw]


def parse_report(xml_bytes: bytes) -> list[Record]:
    root = ET.fromstring(xml_bytes)
    meta = root.find("report_metadata")
    policy = root.find("policy_published")

    org = _text(meta, "org_name")
    report_id = _text(meta, "report_id")
    begin = _ts(_text(meta, "date_range/begin"))
    end = _ts(_text(meta, "date_range/end"))
    domain = _text(policy, "domain")

    records = []
    for rec in root.findall("record"):
        row = rec.find("row")
        pol = row.find("policy_evaluated") if row is not None else None
        records.append(
            Record(
                org_name=org,
                report_id=report_id,
                domain=domain,
                date_begin=begin,
                date_end=end,
                source_ip=_text(row, "source_ip"),
                count=int(_text(row, "count", "0") or 0),
                disposition=_text(pol, "disposition"),
                dkim_result=_text(pol, "dkim"),
                spf_result=_text(pol, "spf"),
                header_from=_text(rec, "identifiers/header_from"),
            )
        )
    return records


def load_paths(paths: list[Path]) -> list[Record]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(x for x in p.iterdir() if x.suffix.lower() in {".xml", ".gz", ".zip"}))
        else:
            files.append(p)

    records: list[Record] = []
    for f in files:
        try:
            for payload in read_xml_payloads(f):
                records.extend(parse_report(payload))
        except (ET.ParseError, OSError, zipfile.BadZipFile, gzip.BadGzipFile) as exc:
            print(f"Errore su {f}: {exc}", file=sys.stderr)
    return records


def print_summary(records: list[Record]) -> None:
    if not records:
        print("Nessun record trovato.")
        return

    total = sum(r.count for r in records)
    passed = sum(r.count for r in records if r.dmarc_pass)
    print(f"Messaggi totali: {total}")
    print(f"DMARC pass:      {passed} ({passed / total * 100:.1f}%)")
    print(f"DMARC fail:      {total - passed} ({(total - passed) / total * 100:.1f}%)\n")

    by_ip: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in records:
        by_ip[r.source_ip][0 if r.dmarc_pass else 1] += r.count

    print(f"{'IP sorgente':<40} {'pass':>8} {'fail':>8}")
    print("-" * 58)
    for ip, (ok, ko) in sorted(by_ip.items(), key=lambda kv: -(kv[1][0] + kv[1][1])):
        print(f"{ip:<40} {ok:>8} {ko:>8}")


def write_csv(records: list[Record], out) -> None:
    fields = list(asdict(records[0]).keys()) if records else []
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for r in records:
        writer.writerow(asdict(r))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Parser per report aggregati DMARC (RUA).")
    ap.add_argument("paths", nargs="+", type=Path, help="file .xml/.gz/.zip o cartelle")
    ap.add_argument("--format", choices=["summary", "csv", "json"], default="summary")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    records = load_paths(args.paths)

    if args.format == "csv":
        write_csv(records, sys.stdout)
    elif args.format == "json":
        json.dump([asdict(r) for r in records], sys.stdout, indent=2)
        print()
    else:
        print_summary(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
