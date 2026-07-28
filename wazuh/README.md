# Decoders y reglas propias de Wazuh

Lo que agregué al Wazuh del lab. Van en el manager, en `/var/ossec/etc/`:

- `decoders/pfsense_decoders.xml` → `/var/ossec/etc/decoders/`
- `rules/local_rules.xml` → `/var/ossec/etc/rules/`

pfSense envía el `filterlog` por syslog **sin el campo hostname** (bug de FreeBSD, pfSense #6975),
así que el decoder `pf` que trae Wazuh de fábrica —que engancha por `program_name`— nunca arrancaba.
El decoder `pfsense-fw` engancha por `prematch` y extrae protocolo/IPs/puertos; las reglas `100100`
(bloqueo) y `100101` (escaneo por correlación) generan las alertas.

Después de copiarlos:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```
