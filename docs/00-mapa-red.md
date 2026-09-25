# Mapa de red del lab

Qué red tiene cada zona, qué hay en ella hoy y qué política de firewall la controla.

## Zonas

| Zona | Red | Interfaz en pfSense | Red de VirtualBox | Hoy | Pendiente |
|---|---|---|---|---|---|
| WAN, el "internet" del lab | `10.0.2.0/24` (DHCP) | `em0` | `lab-wan` (NAT Network) | Kali `10.0.2.4` | |
| DMZ, banca en línea | `10.10.0.0/24` | `em1`, `10.10.0.1` | `lab-dmz` (interna) | vacía | portal con WAF en `10.10.0.10` |
| CDE, datos de tarjeta | `10.20.0.0/24` | `em2`, `10.20.0.1` | `lab-cde` (interna) | vacía | servidor Ubuntu con FIM en `10.20.0.10` |
| CORP, oficina | `10.30.0.0/24` | `em3`, `10.30.0.1` | `lab-corp` (interna) | DC `10.30.0.10`, estación `10.30.0.50` | agentes Wazuh y Sysmon |
| SOC, monitoreo | `10.40.0.0/24` | `em4` (LAN), `10.40.0.1` | `vboxnet0` (host-only) | mi PC `10.40.0.2`, Wazuh `10.40.0.10` | |

## Cómo reparto las IPs

- El segundo octeto identifica la zona: 10 DMZ, 20 CDE, 30 CORP, 40 SOC.
- `.1` es siempre pfSense, `.10` en adelante son servidores y `.50` en adelante estaciones.
- Las zonas internas no tienen DHCP, todo va con IP fija. Así hasta el DHCP de un equipo intruso
  cae en el deny por defecto y queda en el log.

## Qué interfaz es cada zona

El orden de las placas no siempre coincide, así que lo verifiqué por MAC el 21 de julio:

| NIC de VirtualBox | MAC | Interfaz | Zona |
|---|---|---|---|
| 1 | `08:00:27:EC:1F:D1` | em0 | WAN |
| 2 | `08:00:27:2A:CE:BE` | em1 | DMZ |
| 3 | `08:00:27:46:AC:4C` | em2 | CDE |
| 4 | `08:00:27:9E:B2:F3` | em3 | CORP |
| 5 | `08:00:27:27:1B:1C` | em4 | SOC |

## Política del firewall

Uso dos alias: `LAB_NETS` (las 4 redes internas) y `EGRESO_WEB` (puertos 53, 80 y 443).

| Zona | Qué puede hacer | Qué se bloquea y registra |
|---|---|---|
| DMZ, CDE y CORP | Salir a internet por 53, 80 y 443 (regla temporal mientras armo el lab) | Todo lo que vaya hacia `LAB_NETS`, es decir, hacia otra zona |
| SOC | Todo, es la zona del analista | Nadie entra al SOC desde otra zona |
| WAN | Nada | Todo lo que entra cae en el deny por defecto |

El orden importa: el bloqueo entre zonas va primero y la salida a internet después, porque en
pfSense gana la primera regla que coincide. Dejé desmarcado el bloqueo de redes privadas en la
WAN a propósito, porque el "internet" del lab es una red privada y si no los escaneos de la Kali
nunca llegarían a generar alertas.

Pendiente: cerrar la salida a internet de las zonas internas cuando termine de montar el lab.
