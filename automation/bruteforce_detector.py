#!/usr/bin/env python3
"""
bruteforce_detector.py — Análisis de logs en Python: detección de fuerza bruta.

Parsea un archivo de log de autenticación Linux (/var/log/auth.log) y detecta
IPs con N o más intentos fallidos dentro de una ventana de tiempo — el patrón
clásico de fuerza bruta SSH (MITRE ATT&CK T1110). Extrae las IPs sospechosas
para alimentar enrich_ioc.py.

Demuestra la habilidad de "análisis de logs" en Python, complementaria al SIEM:
útil para explicar en entrevista cómo se detecta a mano lo que el SIEM automatiza.

Uso:
    python3 bruteforce_detector.py /var/log/auth.log
    python3 bruteforce_detector.py auth.log --threshold 5 --enrich
"""
import re
import sys
import argparse
from collections import defaultdict

# Ejemplo de línea:
# May 10 13:22:41 host sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 55321 ssh2
_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_failures(path: str) -> dict:
    """Devuelve {ip: {'count': n, 'users': set()}} de intentos fallidos."""
    stats = defaultdict(lambda: {"count": 0, "users": set()})
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            m = _FAILED_RE.search(line)
            if m:
                ip = m.group("ip")
                stats[ip]["count"] += 1
                stats[ip]["users"].add(m.group("user"))
    return stats


def detect(path: str, threshold: int) -> list:
    """Lista de IPs que superan el umbral, ordenadas por nº de intentos."""
    stats = parse_failures(path)
    hits = [
        {"ip": ip, "attempts": d["count"], "users_tried": sorted(d["users"])}
        for ip, d in stats.items()
        if d["count"] >= threshold
    ]
    return sorted(hits, key=lambda x: x["attempts"], reverse=True)


def main():
    ap = argparse.ArgumentParser(description="Detecta fuerza bruta SSH en un auth.log (T1110).")
    ap.add_argument("logfile", help="Ruta al archivo de log (p.ej. /var/log/auth.log)")
    ap.add_argument("--threshold", type=int, default=5,
                    help="Intentos fallidos mínimos para marcar una IP (def: 5)")
    ap.add_argument("--enrich", action="store_true",
                    help="Enriquecer cada IP sospechosa con VirusTotal/AbuseIPDB")
    args = ap.parse_args()

    try:
        hits = detect(args.logfile, args.threshold)
    except FileNotFoundError:
        print(f"[!] No se encontró el archivo: {args.logfile}", file=sys.stderr)
        return 1

    if not hits:
        print(f"[+] Sin IPs por encima del umbral ({args.threshold}).")
        return 0

    print(f"[!] {len(hits)} IP(s) sospechosa(s) de fuerza bruta (T1110):\n")
    for h in hits:
        print(f"  {h['ip']:<16} {h['attempts']:>4} intentos  usuarios: {', '.join(h['users_tried'][:5])}")

    if args.enrich:
        try:
            from enrich_ioc import enrich
        except ImportError:
            print("\n[!] enrich_ioc.py no disponible en el PATH.", file=sys.stderr)
            return 0
        print("\n--- Enriquecimiento ---")
        for h in hits:
            res = enrich(h["ip"])
            print(f"  {h['ip']:<16} -> {res.get('verdict', '?').upper()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
