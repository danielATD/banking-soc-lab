# Lab SOC bancario

Un banco pequeño armado en VirtualBox para practicar del lado defensivo. La idea es simple:
separar la red por zonas como lo pide PCI DSS, mandar los logs a un SIEM y escribir yo mismo las
detecciones, en vez de quedarme solo con las que trae de fábrica.

Es un lab de estudio y sigue en construcción.

## Lo que funciona hoy

Kali escanea el firewall desde afuera:

```bash
sudo nmap -Pn -sS 10.0.2.15     # la cara WAN de pfSense
```

pfSense bloquea y registra cada intento. Ese log llega por syslog a Wazuh, un decoder que escribí
lo lee y dos reglas propias lo convierten en alertas:

![Alertas de escaneo en el dashboard de Wazuh](evidence/fase2-04-alertas-pfsense-en-wazuh.png)

*Reglas `100100` (bloqueo, nivel 5) y `100101` (posible escaneo de puertos, nivel 10). El `srcip` 10.0.2.4 es la Kali.*

## La red

```
"Internet" del lab (lab-wan, NAT)   10.0.2.0/24    Kali, atacante externo (.4)
        |
   [ pfSense ]   fw-banco.banco.lab
        |
        +-- DMZ    10.10.0.0/24   banca en línea (portal + WAF)     pendiente
        +-- CDE    10.20.0.0/24   datos de tarjeta (PCI)            pendiente
        +-- CORP   10.30.0.0/24   Active Directory y estaciones     DC .10, estación .50
        +-- SOC    10.40.0.0/24   monitoreo                         Wazuh .10, mi PC .2
```

Cada zona es una red interna distinta de VirtualBox (no uso VLANs 802.1Q, el aislamiento lo da
la red interna). Entre zonas todo está bloqueado y registrado, y al SOC no entra nadie desde
otra zona. Lo probé con una Kali dentro de la DMZ: lo prohibido se bloquea con mi regla, DNS y
HTTPS salen, y lo que no está contemplado muere en el deny por defecto.

![Bloqueo entre zonas en el log de pfSense](evidence/fase1-05-log-bloqueo-interzona.png)

## Detecciones

| Regla | Qué detecta | Técnica MITRE ATT&CK | Nivel |
|---|---|---|---|
| `100100` | Cada bloqueo del firewall (origen, destino y puerto) | | 5 |
| `100101` | 15 o más bloqueos del mismo origen en 60 s | T1595, Active Scanning | 10 |

El decoder propio hizo falta porque pfSense manda el `filterlog` sin hostname y el decoder que
trae Wazuh nunca arrancaba. Cómo lo encontré y lo resolví está en
[`docs/02-siem-wazuh.md`](docs/02-siem-wazuh.md). Los archivos están en [`wazuh/`](wazuh/).

## Qué usé

pfSense 2.8.1, Wazuh 4.14 (SIEM, sobre Ubuntu Server con 8 GB de RAM), Windows Server 2022 como
controlador de dominio `banco.lab`, una estación Windows 10 unida al dominio, Kali Linux y
VirtualBox.

## Estado

- Fase 1, segmentación y firewall: terminada.
- Fase 2, SIEM y Active Directory: en curso. Wazuh ya genera alertas del firewall y el dominio
  funciona con una estación unida. Falta instalar los agentes de Wazuh y Sysmon en los Windows.
- Pendiente: la DMZ con el portal y el WAF, el CDE con monitoreo de integridad de archivos.

## Aviso

El lab es inseguro a propósito y vive aislado en redes internas de VirtualBox. No uses nada de
esto en producción.

## Carpetas

- [`docs/`](docs/): notas técnicas de cada fase.
- [`wazuh/`](wazuh/): decoder y reglas propias.
- [`evidence/`](evidence/): capturas de cada paso.
