#!/usr/bin/env python3
"""
wazuh_soar_handler.py — El pipeline SOAR completo, en Python.

Recibe alertas de Wazuh por webhook (directo o vía Shuffle), extrae los IOCs
(IP de origen y/o hash del archivo), los enriquece con enrich_ioc.py y —si el
veredicto es malicioso o sospechoso— abre un caso en TheHive y registra la
notificación al analista.

Es el corazón del componente "automatización (Python es un plus)" del CV:
demuestra que sabés escribir la lógica del SOAR, no solo arrastrar cajas en
una GUI. Puede correr solo (servidor Flask) o ser invocado por Shuffle.

Arranque:
    pip install -r requirements.txt
    export FLASK_ENV=lab
    python3 wazuh_soar_handler.py          # escucha en 127.0.0.1:5000/webhook

Config Wazuh (ossec.conf) para enviar alertas al webhook — ver docs/06-soar-automation.md.

Prueba local sin Wazuh:
    curl -X POST http://127.0.0.1:5000/webhook -H 'Content-Type: application/json' \
         -d @sample_alert.json
"""
import os
import json
import logging
from datetime import datetime, timezone

from flask import Flask, request, jsonify

from enrich_ioc import enrich
import thehive_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("soar")

app = Flask(__name__)

# Umbral: por debajo de este veredicto no se abre caso (evita ruido).
OPEN_CASE_FOR = {"malicious", "suspicious"}

# Mapa veredicto -> severidad de TheHive
SEVERITY = {"malicious": 4, "suspicious": 3, "clean": 1, "unknown": 2}


def extract_iocs(alert: dict) -> list:
    """
    Extrae IOCs de un alert JSON de Wazuh. Wazuh anida los datos en 'data' y
    'agent'; los campos varían según la regla. Buscamos IP de origen y hash.
    """
    iocs = []
    data = alert.get("data", {})

    # IP de origen (varios campos posibles según el decoder)
    for key in ("srcip", "src_ip", "source_ip"):
        ip = data.get(key)
        if ip:
            iocs.append(ip)
            break
    # A veces viene anidado en data.win.eventdata
    win = data.get("win", {}).get("eventdata", {}) if isinstance(data.get("win"), dict) else {}
    for key in ("ipAddress", "sourceIp"):
        if win.get(key):
            iocs.append(win[key])

    # Hash del archivo (Sysmon event 1 / integridad)
    for key in ("md5", "sha1", "sha256", "hash"):
        h = data.get(key)
        if h:
            iocs.append(h)
    if win.get("hashes"):
        # formato "MD5=...,SHA256=..." -> tomamos cada valor
        for part in str(win["hashes"]).split(","):
            if "=" in part:
                iocs.append(part.split("=", 1)[1].strip())

    # dedup preservando orden
    seen, out = set(), []
    for i in iocs:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def handle_alert(alert: dict) -> dict:
    """Procesa una alerta: enriquece IOCs y abre caso si corresponde."""
    rule = alert.get("rule", {})
    rule_desc = rule.get("description", "sin descripción")
    rule_level = rule.get("level", "?")
    agent = alert.get("agent", {}).get("name", "desconocido")

    iocs = extract_iocs(alert)
    log.info("Alerta: '%s' (nivel %s, agente %s) — IOCs: %s",
             rule_desc, rule_level, agent, iocs or "ninguno")

    enrichments, worst = [], "clean"
    order = ["clean", "unknown", "suspicious", "malicious"]
    for ioc in iocs:
        res = enrich(ioc)
        enrichments.append(res)
        v = res.get("verdict", "unknown")
        if order.index(v) > order.index(worst):
            worst = v

    action = "ignored"
    case = None
    if worst in OPEN_CASE_FOR:
        # Construimos la descripción del caso con el enriquecimiento
        desc_lines = [
            f"**Regla Wazuh:** {rule_desc} (nivel {rule_level})",
            f"**Agente:** {agent}",
            f"**Veredicto agregado:** {worst.upper()}",
            "",
            "**Enriquecimiento de IOCs:**",
            "```json",
            json.dumps(enrichments, indent=2, ensure_ascii=False),
            "```",
        ]
        case = thehive_client.create_alert(
            title=f"[{worst.upper()}] {rule_desc}",
            description="\n".join(desc_lines),
            severity=SEVERITY[worst],
            tags=["wazuh", "soar", worst, f"agent:{agent}"],
            source_ref=f"{agent}-{datetime.now(timezone.utc).isoformat()}",
        )
        action = "case_created"
        log.info("Caso creado en TheHive (veredicto %s). Notificar al analista.", worst)

    return {
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "rule": rule_desc,
        "iocs": iocs,
        "verdict": worst,
        "action": action,
        "enrichments": enrichments,
        "thehive": case,
    }


@app.post("/webhook")
def webhook():
    try:
        alert = request.get_json(force=True)
    except Exception as e:
        return jsonify({"error": f"JSON inválido: {e}"}), 400
    if not isinstance(alert, dict):
        return jsonify({"error": "Se esperaba un objeto JSON de alerta"}), 400
    return jsonify(handle_alert(alert)), 200


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "wazuh-soar-handler"}), 200


if __name__ == "__main__":
    host = os.getenv("SOAR_HOST", "127.0.0.1")  # loopback por defecto (invariante: no exponer)
    port = int(os.getenv("SOAR_PORT", "5000"))
    log.info("SOAR handler escuchando en http://%s:%s/webhook", host, port)
    app.run(host=host, port=port)
