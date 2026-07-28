#!/usr/bin/env python3
"""
thehive_client.py — Cliente mínimo para crear casos/alertas en TheHive (REST v1).

Lo usa el pipeline SOAR para abrir un caso cuando una alerta de Wazuh se
enriquece como maliciosa. Sin dependencias externas más allá de requests, para
que sea fácil de auditar y no depender de versiones de thehive4py.

Config por variables de entorno:
    THEHIVE_URL      p.ej. http://127.0.0.1:9000
    THEHIVE_API_KEY  API key de un usuario de servicio de TheHive
"""
import os

import requests

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://127.0.0.1:9000").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
TIMEOUT = 15


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json",
    }


def create_alert(title: str, description: str, severity: int = 2,
                 tags=None, source: str = "wazuh", source_ref: str = "") -> dict:
    """
    Crea una alerta en TheHive.
    severity: 1=Low, 2=Medium, 3=High, 4=Critical.
    Devuelve el JSON de la alerta creada, o {'error': ...}.
    """
    if not THEHIVE_API_KEY:
        return {"error": "THEHIVE_API_KEY no configurada"}

    payload = {
        "type": "internal",
        "source": source,
        "sourceRef": source_ref or title[:32],
        "title": title,
        "description": description,
        "severity": severity,
        "tags": tags or [],
    }
    try:
        r = requests.post(f"{THEHIVE_URL}/api/v1/alert",
                          json=payload, headers=_headers(), timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        return {"error": str(e)}


if __name__ == "__main__":
    # Prueba rápida de conectividad / creación de una alerta de ejemplo.
    demo = create_alert(
        title="[TEST] Alerta de prueba desde el pipeline SOAR",
        description="Alerta de verificación generada por thehive_client.py",
        severity=2,
        tags=["test", "soar", "lab"],
    )
    print(demo)
