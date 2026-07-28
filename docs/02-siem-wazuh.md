# Fase 2 — SIEM + EDR + Active Directory (Wazuh + Sysmon + AD)

> Registro técnico vivo de la fase. Qué se hace, dónde se configura y cómo repetirlo.
> Cubre del anuncio Credicorp: **SIEM + EDR**. Inicio: 22 jul 2026.

## Objetivo de la fase
Desplegar **Wazuh** (Manager + Indexer + Dashboard) como SIEM/EDR central en la zona SOC, y hacer
que ingiera telemetría de las 4 zonas: logs de pfSense (firewall), endpoints Windows (AD + Sysmon)
y Linux (CDE), con FIM sobre el CDE y una respuesta activa básica.

## Decisiones de la fase
| Fecha | Decisión | Por qué |
|---|---|---|
| 2026-07-22 | Instalación **A: Ubuntu Server 26.04 LTS + script oficial** (no OVA) | Se aprende el despliegue real (paquetes, servicios systemd, indexer/dashboard) y se puede defender en entrevista. El OVA es "next-next-finish". |
| 2026-07-24 | pfSense manda el syslog **sin hostname** → normalizo con un **decoder propio** (no toco pfSense) | El decoder `pf` de fábrica engancha por `program_name`, que sin hostname queda vacío. Arreglar el origen era instalar syslog-ng en pfSense (más superficie, toca Fase 1); normalizar en el SIEM es lo que hace un SOC cuando no controla el origen. |
| 2026-07-22 | Wazuh en zona **SOC** (host-only `vboxnet0`), IP estática **10.40.0.10** | El SIEM vive en la red de gestión, junto a la estación del analista (10.40.0.2). `.10` = servidor de monitoreo. |
| 2026-07-22 | RAM **8 GB**, disco **50 GB**, 4 vCPU | El Wazuh Indexer (basado en OpenSearch/Java) hace I/O pesado; con 4 GB tiende a quedarse sin memoria. El host tiene 30 GB. |

## Plano de direcciones de la zona SOC (VLAN 40, host-only vboxnet0)
| Host | IP | Rol |
|---|---|---|
| pfSense | 10.40.0.1 | Gateway/firewall de la zona |
| PC de Daniel | 10.40.0.2 | Estación del analista (navega el dashboard) |
| **Wazuh** | **10.40.0.10** | **SIEM/EDR (esta fase)** |

## Componentes de Wazuh (para saber qué se instala)
- **Wazuh Indexer** — motor de búsqueda/almacenamiento (fork de OpenSearch). Guarda las alertas.
- **Wazuh Server (Manager)** — recibe los datos de los agentes y de syslog, aplica las reglas de
  detección y genera alertas.
- **Wazuh Dashboard** — la interfaz web (fork de OpenSearch Dashboards) donde se investiga.
El script `wazuh-install.sh -a` (all-in-one) instala los tres en la misma VM — correcto para un
homelab de un nodo.

## Comando de instalación (verificado 22/07 — Wazuh 4.14, docs oficiales)
```bash
# DENTRO de la VM Ubuntu, ya con IP y actualizada:
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
# Al terminar (~15-20 min) imprime la URL https://<IP>, usuario 'admin' y su contraseña.
# Guardar esa contraseña: sale también en wazuh-install-files.tar (tar -O -xf ... o -p para verla).
```

## Estado / progreso
- [x] Descargar ISO Ubuntu Server 24.04 LTS → `~/Documents/SOC-lab/isos/`
- [x] Crear la VM `Wazuh` (host-only vboxnet0, 8 GB RAM, 4 vCPU, disco 50 GB dinámico)
- [x] Instalar Ubuntu Server 26.04 (23/07): IP estática `10.40.0.10/24` gw `10.40.0.1` DNS 1.1.1.1 ·
      LVM **agrandado a disco completo** (el instalador deja `/` en ~24G por default → Edit
      `ubuntu-lv` al máximo; quedó 48G) · OpenSSH ✅ · sin snaps (superficie mínima) · sin LUKS
      (VM de lab; cifrado es para robo físico)
- [x] Verificación pre-Wazuh: IP ok, `/`=48G, **egreso a internet A TRAVÉS de pfSense**
      (gw 10.40.0.1 → NAT WAN) y DNS resolviendo — el servidor navega por el firewall del banco
- [x] Correr `wazuh-install.sh -a` y acceder al dashboard (23/07, Wazuh 4.14)
- [x] Recibir el syslog de pfSense (514/UDP) en el Manager — bloque `<remote>` + `tcpdump` OK (23/07)
- [x] **Generar alertas** desde los bloqueos de pfSense: decoder propio `pfsense-fw` + reglas
      `100100`/`100101`, verificado con `wazuh-logtest` **y en el dashboard** con un nmap real de Kali
      (evidencia `fase2-04`) (24/07)
- [ ] DC Windows + AD en CORP, agentes, Sysmon, FIM, respuesta activa

## Gotchas vividos (para el writeup)
- **"Skip Unattended Installation"** al crear la VM — sin eso VirtualBox instala solo con valores
  inventados.
- El DHCP de `vboxnet0` reparte `192.168.56.x` (rango default viejo de VBox) — irrelevante: todo
  el SOC va con IP estática. Pendiente cosmético: corregirlo o apagarlo.
- **LVM al 50%**: el guided storage de Ubuntu asigna ~la mitad del disco a `/` — siempre revisar
  el summary y agrandar `ubuntu-lv` ANTES de confirmar el formateo.
- "Remove installation medium": VirtualBox ya había expulsado el ISO solo (verificado con
  `showvminfo`: puerto IDE `Empty, ejected`) — Enter y listo.

## Evidencia de la fase
- `../evidence/fase2-00-kali-reubicada-lado-wan.png` — Kali movida al lado WAN (paso puente previo)
- `../evidence/fase2-01-ubuntu-verificacion-ip-disco-egreso.png` — verificación pre-instalación: IP 10.40.0.10, /=48G, ping por pfSense + DNS OK
- `../evidence/fase2-02-dashboard-wazuh-primer-login.png` — dashboard de Wazuh, primer login
- `../evidence/fase2-03-nmap-atacante-y-syslog-pfsense-tcpdump.png` — nmap de Kali + `tcpdump` viendo el syslog llegar al 514
- `../evidence/fase2-04-alertas-pfsense-en-wazuh.png` — alertas `100100`/`100101` en el dashboard tras un nmap real

## Por qué pfSense no generaba alertas (y cómo lo resolví)

El transporte funcionaba (el `tcpdump` mostraba los datagramas llegando al 514), pero en el dashboard
no aparecía ninguna alerta. "Llega" no es "se procesa". Lo desarmé con `wazuh-logtest`, que muestra
las tres fases por las que pasa un log: **pre-decoding → decoding → reglas**.

1. **Pre-decoding:** Wazuh tomaba `hostname: 'filterlog[84556]:'` y dejaba `program_name` vacío.
2. **Causa raíz:** pfSense manda el `filterlog` por syslog **sin el campo hostname** (bug conocido de
   FreeBSD/pfSense, [#6975](https://redmine.pfsense.org/issues/6975)). El decoder `pf` que trae Wazuh
   de fábrica engancha por `program_name=filterlog` → sin ese campo, nunca arranca.
3. **Prueba:** inyecté la misma línea con un hostname a mano (`... pfSense filterlog: ...`) y ahí sí
   decodificó con `pf` y disparó la regla de fábrica 87701 (nivel 5). Confirmado: el único problema
   era el hostname.

**Decisión:** en vez de tocar pfSense (instalar syslog-ng para reescribir el hostname), lo normalicé
en el SIEM con un decoder propio — lo que hace un SOC cuando no controla el origen. Intento fallido y
su lección: **redefinir el decoder `pf` de fábrica no funciona** (Wazuh mantiene su condición
`program_name`); un decoder custom necesita **nombre propio**.

### Lo que quedó (en `wazuh/`, desplegado en `/var/ossec/etc/`)

- **Decoder `pfsense-fw`** (`decoders/pfsense_decoders.xml`): engancha por `prematch` (`match,block`)
  y extrae `protocol/srcip/dstip/srcport/dstport` con un regex `pcre2` que no depende de dónde
  arranca el mensaje.
- **Reglas** (`rules/local_rules.xml`): `100100` (bloqueo, nivel 5, `pci_dss 1.4`) y `100101`
  (correlación: +15 bloqueos del mismo origen en 60s = posible escaneo, nivel 10).

Verificado con `wazuh-logtest` (Phase 2 con los campos + Phase 3 regla `100100` → *Alert to be
generated*) y en vivo con un `nmap -sS` de Kali: en el dashboard aparecieron los bloqueos `100100` y
la `100101` de escaneo. **Nota de tuning:** la `100100` a nivel 5 dispara una alerta por puerto; en
producción el evento individual iría a nivel bajo y la alerta útil sería la correlación (el escaneo),
para no inundar al analista — por eso Wazuh trae los eventos de firewall a nivel 0 de fábrica.
