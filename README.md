# Lab SOC bancario

Un banco en miniatura montado en VirtualBox para practicar del lado defensivo: red segmentada
como pide PCI DSS, todo el log hacia un SIEM y las detecciones escritas por mí, no descargadas.
Cuatro zonas internas, un firewall pfSense, un dominio Windows y una Kali afuera de atacante.

Es un lab de estudio y está en construcción.

## La detección, de punta a punta

Kali escanea el firewall desde afuera:

```bash
sudo nmap -Pn -sS 10.0.2.15     # la cara WAN de pfSense
```

pfSense bloquea y registra cada intento. El log viaja por syslog a Wazuh, donde un decoder mío
lo parsea y dos reglas propias lo convierten en alertas:

![Alertas de escaneo en el dashboard de Wazuh](evidence/fase2-04-alertas-pfsense-en-wazuh.png)

*Reglas `100100` (bloqueo, nivel 5) y `100101` ("posible escaneo de puertos", nivel 10). El `srcip` 10.0.2.4 es la Kali.*

## Arquitectura

Cuatro zonas internas más la WAN. El segundo octeto es el número de VLAN, y pfSense es el `.1` de cada red:

```
"Internet" simulada (lab-wan, NAT)   10.0.2.0/24    Kali, atacante externo (.4)
        |
   [ pfSense ]   fw-banco.banco.lab
        |
        +-- DMZ    10.10.0.0/24   banca en línea (portal + WAF)     [pendiente]
        +-- CDE    10.20.0.0/24   datos de tarjeta / PCI            [pendiente]
        +-- CORP   10.30.0.0/24   Active Directory + estaciones     DC01 .10 · estación .50
        +-- SOC    10.40.0.0/24   gestión y monitoreo               Wazuh .10 · analista .2
```

Cada zona es un dominio de confianza distinto: el CDE solo habla lo explícitamente permitido,
al SOC no entra nadie, y los ataques tienen que cruzar el firewall para dejar rastro. Es el
control de segmentación de PCI DSS Req. 1, y está validado con pruebas más abajo.

## Stack

| Componente | Versión | Rol | Dónde |
|---|---|---|---|
| pfSense | 2.8.1 | Firewall y gateway de cada zona | `.1` de cada red |
| Wazuh | 4.14 | SIEM/EDR (Manager, Indexer, Dashboard) | SOC · 10.40.0.10 |
| Windows Server | 2022 | Domain Controller, bosque `banco.lab` | CORP · 10.30.0.10 |
| Windows 10 Pro | - | Estación de empleado, unida al dominio | CORP · 10.30.0.50 |
| Kali Linux | 2026.2 | Atacante externo | WAN · 10.0.2.4 |
| VirtualBox | - | Hipervisor (host de 30 GB) | - |

Wazuh corre sobre Ubuntu Server con 8 GB de RAM; con menos, el Indexer (Java) se ahoga.

## Detección

| Regla | Qué caza | MITRE ATT&CK | Nivel | Marco |
|---|---|---|---|---|
| `100100` | Cada bloqueo del firewall (origen → destino:puerto) | - | 5 | PCI DSS 1.4 |
| `100101` | 15+ bloqueos del mismo origen en 60 s (escaneo) | T1595 · Active Scanning | 10 | PCI DSS 11.4 |

Las dos cuelgan de un decoder propio, `pfsense-fw`. Hizo falta porque pfSense manda el
`filterlog` por syslog sin hostname (bug conocido de FreeBSD) y el decoder de fábrica nunca
llega a arrancar. Lo resolví del lado del SIEM; el detalle está en
[`docs/02-siem-wazuh.md`](docs/02-siem-wazuh.md). Decoder y reglas: [`wazuh/`](wazuh/).

## Validación de la segmentación

Levanté una VM en la DMZ haciendo de servidor comprometido y probé las tres caras de la
política: lo prohibido (bloqueado y loggeado por mi regla), lo permitido (DNS y HTTPS salen) y
lo no contemplado (muere en el default-deny). Cada resultado con dos evidencias: la terminal
del atacante y el log del firewall.

![Bloqueo inter-zona en el log de pfSense](evidence/fase1-05-log-bloqueo-interzona.png)

## Estado

- Fase 1 (segmentación y firewall): cerrada. Reglas verificadas en el motor `pf`, no solo en la GUI.
- Fase 2 (SIEM y Active Directory): en curso. Wazuh detectando; dominio `banco.lab` con estaciones unidas.
- Después: agentes Wazuh + Sysmon en los Windows, FIM sobre el CDE y una fase cloud en AWS.

## Aviso

El lab es inseguro a propósito (contraseñas débiles, servicios expuestos entre zonas) y vive
aislado en redes internas de VirtualBox. No reutilizar nada de esto en producción.

## Mapa del repo

- [`docs/`](docs/): el detalle técnico por fase.
- [`wazuh/`](wazuh/): decoders y reglas propias.
- [`evidence/`](evidence/): capturas de cada paso.
- [`automation/`](automation/): scripts de la fase SOAR (en preparación).
