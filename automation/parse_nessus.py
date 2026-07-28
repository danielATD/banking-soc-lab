#!/usr/bin/env python3
"""
parse_nessus.py — Reporte de gestión de vulnerabilidades desde un export de Nessus.

Toma el CSV exportado por Nessus Essentials y genera un reporte priorizado por
riesgo, dando MÁS peso a los activos del CDE (entorno de datos de tarjeta) — la
priorización por contexto de negocio es justo lo que distingue a un analista de
un simple ejecutor de escáner (y es lenguaje PCI DSS Req. 11.2 / 6.1).

Salida: un resumen por consola + un reporte Markdown listo para el writeup.

Uso:
    python3 parse_nessus.py scan.csv
    python3 parse_nessus.py scan.csv --cde 10.20.0.0/24 --out docs/05-reporte-vuln.md

Nota: no subas el CSV crudo al repo (puede tener detalle sensible). El reporte
Markdown resumido sí es apto para el portafolio.
"""
import csv
import sys
import argparse
import ipaddress
from collections import Counter

SEV_ORDER = ["Critical", "High", "Medium", "Low", "None"]
SEV_WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "None": 0}


def in_cde(ip: str, cde_net) -> bool:
    if not cde_net or not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in cde_net
    except ValueError:
        return False


def load(path: str) -> list:
    with open(path, newline="", errors="ignore") as fh:
        return list(csv.DictReader(fh))


def score(rows: list, cde_net):
    """Añade a cada fila un 'risk_score' ponderado por severidad y por si está en el CDE."""
    scored = []
    for r in rows:
        sev = (r.get("Risk") or r.get("Severity") or "None").strip().title()
        if sev not in SEV_WEIGHT:
            sev = "None"
        host = r.get("Host") or r.get("IP Address") or ""
        base = SEV_WEIGHT[sev]
        cde = in_cde(host, cde_net)
        risk = base * (2 if cde else 1)  # el CDE pesa el doble
        scored.append({
            "host": host,
            "name": r.get("Name", "").strip(),
            "severity": sev,
            "cve": r.get("CVE", "").strip(),
            "cde": cde,
            "risk_score": risk,
        })
    # ignorar informativos
    scored = [s for s in scored if s["severity"] != "None"]
    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)


def render_markdown(scored: list, cde_net) -> str:
    counts = Counter(s["severity"] for s in scored)
    cde_count = sum(1 for s in scored if s["cde"])
    lines = [
        "# Reporte de gestión de vulnerabilidades",
        "",
        f"- **Total de hallazgos (excl. informativos):** {len(scored)}",
        f"- **Por severidad:** " + ", ".join(f"{sev}={counts.get(sev,0)}" for sev in SEV_ORDER[:-1]),
        f"- **En el CDE ({cde_net}):** {cde_count} (priorizados ×2)" if cde_net else "",
        "",
        "## Top 15 priorizados por riesgo",
        "",
        "| # | Riesgo | Sev | CDE | Host | Vulnerabilidad | CVE |",
        "|---|--------|-----|-----|------|----------------|-----|",
    ]
    for i, s in enumerate(scored[:15], 1):
        lines.append(
            f"| {i} | {s['risk_score']} | {s['severity']} | "
            f"{'✅' if s['cde'] else ''} | {s['host']} | {s['name'][:50]} | {s['cve']} |"
        )
    lines += [
        "",
        "## Plan de remediación (completar)",
        "1. Remediar primero los hallazgos del CDE (contexto PCI DSS).",
        "2. Parchear/mitigar → documentar la acción.",
        "3. Re-escanear y adjuntar el antes/después.",
        "",
        "_Generado con parse_nessus.py — proyecto SOC bancario._",
    ]
    return "\n".join(l for l in lines if l is not None)


def main():
    ap = argparse.ArgumentParser(description="Reporte priorizado de vulnerabilidades desde CSV de Nessus.")
    ap.add_argument("csvfile", help="Export CSV de Nessus")
    ap.add_argument("--cde", help="Red del CDE en CIDR (p.ej. 10.20.0.0/24) para ponderar ×2")
    ap.add_argument("--out", help="Ruta del reporte Markdown de salida")
    args = ap.parse_args()

    cde_net = None
    if args.cde:
        try:
            cde_net = ipaddress.ip_network(args.cde, strict=False)
        except ValueError:
            print(f"[!] CIDR inválido: {args.cde}", file=sys.stderr)
            return 1

    try:
        rows = load(args.csvfile)
    except FileNotFoundError:
        print(f"[!] No se encontró: {args.csvfile}", file=sys.stderr)
        return 1

    scored = score(rows, cde_net)
    md = render_markdown(scored, cde_net)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(md)
        print(f"[+] Reporte escrito en {args.out} ({len(scored)} hallazgos)")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
