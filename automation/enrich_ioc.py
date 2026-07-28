#!/usr/bin/env python3
"""
enrich_ioc.py — Enriquecimiento de IOCs (IP o hash) con VirusTotal + AbuseIPDB.

Componente central del pipeline SOAR del proyecto SOC bancario. Recibe un
indicador de compromiso (una IP o un hash de archivo), consulta la reputación en
VirusTotal (v3) y —si es IP— en AbuseIPDB, y devuelve un veredicto normalizado.

Uso como CLI:
    python3 enrich_ioc.py 8.8.8.8
    python3 enrich_ioc.py 44d88612fea8a8f36de82e1278abb02f

Uso como librería (lo llama wazuh_soar_handler.py):
    from enrich_ioc import enrich
    veredicto = enrich("8.8.8.8")

Claves de API: se leen de variables de entorno (VT_API_KEY, ABUSEIPDB_API_KEY),
NUNCA hardcodeadas. Copia .env.example a .env y cárgalo (python-dotenv) o
expórtalas en tu shell. Las cuentas gratuitas de ambos servicios bastan para el lab.
"""
import os
import re
import sys
import json
import argparse

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv es opcional; también sirve exportar las variables en el shell

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

TIMEOUT = 15  # segundos por request

# --- Detección del tipo de IOC ------------------------------------------------
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def classify_ioc(value: str) -> str:
    """Devuelve 'ip', 'hash' o 'unknown'."""
    value = value.strip()
    if _IP_RE.match(value):
        return "ip"
    if _HASH_RE.match(value):
        return "hash"
    return "unknown"


# --- VirusTotal ---------------------------------------------------------------
def _vt_lookup(ioc: str, ioc_type: str) -> dict:
    """Consulta VirusTotal v3. Devuelve un dict resumido (o error)."""
    if not VT_API_KEY:
        return {"source": "virustotal", "error": "VT_API_KEY no configurada"}

    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"

    try:
        r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"source": "virustotal", "found": False, "note": "IOC no encontrado en VT"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        return {
            "source": "virustotal",
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except requests.RequestException as e:
        return {"source": "virustotal", "error": str(e)}


# --- AbuseIPDB (solo IPs) -----------------------------------------------------
def _abuseipdb_lookup(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"source": "abuseipdb", "error": "ABUSEIPDB_API_KEY no configurada"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {
            "source": "abuseipdb",
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
        }
    except requests.RequestException as e:
        return {"source": "abuseipdb", "error": str(e)}


# --- Veredicto agregado -------------------------------------------------------
def _verdict(vt: dict, abuse: dict) -> str:
    """Regla simple de negocio: combina señales en malicious/suspicious/clean."""
    vt_mal = vt.get("malicious", 0) or 0
    abuse_score = abuse.get("abuse_confidence", 0) or 0
    if vt_mal >= 3 or abuse_score >= 75:
        return "malicious"
    if vt_mal >= 1 or abuse_score >= 25:
        return "suspicious"
    return "clean"


def enrich(ioc: str) -> dict:
    """Enriquece un IOC y devuelve el veredicto completo (para el SOAR)."""
    ioc = ioc.strip()
    ioc_type = classify_ioc(ioc)
    if ioc_type == "unknown":
        return {"ioc": ioc, "type": "unknown", "error": "No es una IP ni un hash válido"}

    vt = _vt_lookup(ioc, ioc_type)
    abuse = _abuseipdb_lookup(ioc) if ioc_type == "ip" else None

    result = {
        "ioc": ioc,
        "type": ioc_type,
        "virustotal": vt,
        "abuseipdb": abuse,
        "verdict": _verdict(vt, abuse or {}),
    }
    return result


def main():
    parser = argparse.ArgumentParser(description="Enriquece un IOC (IP o hash) con VT + AbuseIPDB.")
    parser.add_argument("ioc", help="IP o hash a enriquecer")
    args = parser.parse_args()
    print(json.dumps(enrich(args.ioc), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
