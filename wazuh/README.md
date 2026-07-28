# decoders y reglas propias de wazuh

Estos son los decoders y reglas que agregué al Wazuh del lab. Se instalan en el manager, dentro de `/var/ossec/etc/`:

- `decoders/pfsense_decoders.xml` → `/var/ossec/etc/decoders/`
- `rules/local_rules.xml` → `/var/ossec/etc/rules/`

pfSense envía el `filterlog` por syslog **sin el campo hostname** (bug de FreeBSD, pfSense #6975).
Por eso el decoder `pf` que trae Wazuh de fábrica, que engancha por `program_name`, nunca llegaba a
arrancar. El decoder `pfsense-fw` engancha por `prematch` y extrae protocolo, IPs y puertos; las reglas
`100100` (bloqueo) y `100101` (escaneo por correlación) son las que generan las alertas.

Una vez copiados los archivos:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```
