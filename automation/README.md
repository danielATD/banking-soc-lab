# automation/ — Componente Python / SOAR del SOC bancario

Scripts en Python que cubren el requisito **"automatización (Python es un plus)"** de la vacante.
Todos leen sus claves desde variables de entorno (`.env`); ninguna queda hardcodeada.

| Script | Qué hace | Requisito que prueba |
|---|---|---|
| `enrich_ioc.py` | Enriquece una IP/hash con VirusTotal + AbuseIPDB → veredicto | Threat intel / automatización |
| `wazuh_soar_handler.py` | Webhook: recibe alertas de Wazuh, enriquece IOCs y abre caso en TheHive | **SOAR end-to-end en Python** |
| `thehive_client.py` | Crea alertas/casos en TheHive vía REST | Gestión de casos / IR |
| `bruteforce_detector.py` | Análisis de `auth.log`: detecta fuerza bruta SSH (T1110) | Análisis de logs |
| `parse_nessus.py` | Reporte de vulnerabilidades priorizado (CDE ×2) desde CSV de Nessus | Gestión de vulnerabilidades |

## Puesta en marcha

```bash
cd automation
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # y rellena tus claves
```

## Pruebas rápidas (sin el lab montado)

```bash
# 1) Enriquecer un IOC (necesita VT_API_KEY / ABUSEIPDB_API_KEY)
python3 enrich_ioc.py 8.8.8.8

# 2) Detectar fuerza bruta en un log de ejemplo
python3 bruteforce_detector.py /var/log/auth.log --threshold 5

# 3) Levantar el SOAR handler y enviarle una alerta de ejemplo
python3 wazuh_soar_handler.py            # en una terminal
curl -X POST http://127.0.0.1:5000/webhook \
     -H 'Content-Type: application/json' -d @sample_alert.json   # en otra
```

## Dónde encaja en el pipeline

```
Wazuh (alerta) ──webhook──► wazuh_soar_handler.py ──► enrich_ioc.py (VT + AbuseIPDB)
                                     │
                                     └──► thehive_client.py (crea caso) ──► notifica analista
```

Para la config de Wazuh (`ossec.conf`) que envía las alertas, ver `docs/06-soar-automation.md`.
