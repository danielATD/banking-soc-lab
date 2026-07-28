# Fase 1 — Red segmentada + firewall (pfSense)

> **Registro técnico vivo de la fase**: qué se hizo, dónde se configura cada cosa y cómo repetirlo.
> Se actualiza al cierre de cada bloque de trabajo. Al terminar la fase se convierte en el writeup
> final (con las capturas de `../evidence/`). Fechas: 18–22 jul 2026. **FASE CERRADA ✅ (22/07)**.

## Resumen de arquitectura de esta fase

pfSense como router/firewall central del "Banco Demo S.A.": 5 interfaces, una por zona, con
default-deny entre zonas. Las "VLANs" del diseño se implementan como **redes internas separadas de
VirtualBox** (una red = una zona), no como VLANs 802.1Q — mismo efecto de aislamiento, sin switch
gestionado.

| Zona | Red VirtualBox | Subred | pfSense | Rol |
|---|---|---|---|---|
| WAN | NAT | 10.0.2.0/24 (DHCP) | 10.0.2.15 | "Internet" simulado |
| SOC/MGMT (LAN) | vboxnet0 (host-only) | 10.40.0.0/24 | 10.40.0.1 | Gestión; la PC del analista es 10.40.0.2 |
| DMZ (OPT1) | lab-dmz (interna) | 10.10.0.0/24 | 10.10.0.1 | Portal banca en línea + WAF |
| CDE (OPT2) | lab-cde (interna) | 10.20.0.0/24 | 10.20.0.1 | Core banking / datos de tarjeta |
| CORP (OPT3) | lab-corp (interna) | 10.30.0.0/24 | 10.30.0.1 | AD + estación empleado |

Nemotécnico: **segundo octeto = número de VLAN del diseño** (10/20/30/40).

---

## Las DOS capas de configuración (clave para no perderse)

Toda interfaz del lab existe en dos lugares distintos, y se configura en este orden:

**Capa 1 — VirtualBox (el "hardware"):** define qué placas de red (NICs) tiene la VM y a qué red
virtual está enchufado cada cable. Se configura con la VM **apagada**, desde la terminal del host
con `vboxmanage` (o GUI de VirtualBox, que solo muestra 4 adaptadores; CLI llega a 8).

**Capa 2 — pfSense (el sistema operativo):** ve esas NICs como `em0`, `em1`, `em2`… y decide qué
rol cumple cada una (WAN/LAN/OPT), su IP y sus reglas. Se configura en la consola de la VM
(opciones 1 y 2 del menú) o en el GUI web.

### ¿Por qué "em"? ¿Quién decide em0, em1…?
pfSense corre sobre FreeBSD, y FreeBSD nombra las interfaces según el **driver** de la placa.
VirtualBox emula placas Intel 82540EM → driver `em` → interfaces `em0..em4`, numeradas por el
orden del bus PCI (que coincide con el orden NIC 1..5 de VirtualBox). **Nunca confiar en el orden a
ciegas:** se verifica cruzando las **MAC** que muestra pfSense contra `vboxmanage showvminfo`.

### Mapa em ↔ zona de este lab (verificado por MAC el 21/07)
| NIC VBox | MAC | em (pfSense) | Zona |
|---|---|---|---|
| 1 | 08:00:27:EC:1F:D1 | em0 | WAN |
| 2 | 08:00:27:2A:CE:BE | em1 | DMZ |
| 3 | 08:00:27:46:AC:4C | em2 | CDE |
| 4 | 08:00:27:9E:B2:F3 | em3 | CORP |
| 5 | 08:00:27:27:1B:1C | em4 | SOC (LAN) |

---

## Lo que se hizo, paso a paso (y dónde se repite cada cosa)

### 1. Redes virtuales en el host (capa VirtualBox) — terminal del host, VM apagada
```bash
# Permiso de rango para redes host-only (una sola vez; VBox ≥6.1.28 solo permite
# 192.168.56.0/21 por defecto — sin esto, E_ACCESSDENIED):
sudo mkdir -p /etc/vbox && echo "* 10.40.0.0/24" | sudo tee /etc/vbox/networks.conf

# Red del analista (host-only): crea vboxnet0 y le da IP 10.40.0.2 A LA PC:
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 --ip 10.40.0.2 --netmask 255.255.255.0

# Enchufar cada NIC de la VM a su red (las redes internas se crean solas al nombrarlas):
vboxmanage modifyvm pfSense --nic2 intnet --intnet2 lab-dmz
vboxmanage modifyvm pfSense --nic3 intnet --intnet3 lab-cde
vboxmanage modifyvm pfSense --nic4 intnet --intnet4 lab-corp
vboxmanage modifyvm pfSense --nic5 hostonly --hostonlyadapter5 vboxnet0

# Verificar:
vboxmanage showvminfo pfSense | grep "NIC [1-5]"
```

### 2. Asignación de roles (capa pfSense) — consola de la VM, opción `1) Assign Interfaces`
Respuestas usadas: VLANs=`n` · WAN=`em0` · LAN=`em4` · OPT1=`em1` · OPT2=`em2` · OPT3=`em3`.

**Decisión de diseño:** la zona SOC se asignó como **LAN** porque pfSense le da a "LAN" la regla
anti-lockout (garantiza acceso al GUI web) — la confianza le corresponde a la zona de gestión.
Las OPT nacen **sin reglas = todo bloqueado** (default-deny de fábrica).

### 3. IP de la LAN — consola, opción `2) Set interface(s) IP address`
LAN → DHCP=`n` (pfSense ES el router: IP estática) → `10.40.0.1` → bits `24` → gateway vacío
(no tiene "río arriba" en esa red) → DHCP server=`n` (la PC ya tiene IP fija) → revert HTTP=`n`.

### 4. Wizard inicial — GUI web `https://10.40.0.1` (cert autofirmado: aceptar)
- Hostname `fw-banco` · Domain `banco.lab` (dominio inventado; NO usar `.local`, choca con mDNS)
- DNS `1.1.1.1` / `8.8.8.8` · **Override DNS: desmarcado** (que el NAT no los pise)
- NTP default · TZ `America/Panama` (hora uniforme = timelines correlacionables en el SOC)
- WAN: tipo `DHCP` · MAC/MTU/MSS vacíos · **Block RFC1918 y Block bogons: DESMARCADOS** ⚠️
  (en producción van marcados — anti-spoofing; aquí el "internet" entero es red privada 10.0.2.x,
  y con ellos marcados los ataques de Kali desde la WAN morirían antes de generar alertas)
- Contraseña de admin cambiada (nunca dejar la default en un firewall).

### 5. Habilitar las zonas OPT — GUI: `Interfaces → OPT1/OPT2/OPT3`
Para cada una: Enable ✅ · Description (`DMZ`/`CDE`/`CORP` — renombra la interfaz en todo el GUI) ·
`Static IPv4` · IP de la tabla (`10.10.0.1/24`, `10.20.0.1/24`, `10.30.0.1/24`) · gateway `None` ·
Save → Apply.

---

## 📖 Receta: agregar una zona/interfaz NUEVA al lab (el ciclo completo)

1. Apagar pfSense (consola opción 6, o `vboxmanage controlvm pfSense acpipowerbutton`).
2. Host: `vboxmanage modifyvm pfSense --nic6 intnet --intnet6 lab-nueva`
3. Prender la VM. FreeBSD detecta la placa nueva → aparece `em5`.
4. Consola opción 1 (o GUI `Interfaces → Assignments → Add`): asignar `em5` (verificar MAC).
5. GUI `Interfaces → OPT4`: Enable + Description + Static IPv4 + IP `.1` de su /24 + Save/Apply.
6. `Firewall → Rules → pestaña nueva`: sus reglas (sin reglas = aislada). Actualizar este doc y
   el alias `LAB_NETS` si aplica.

---

## Reglas de firewall (hechas 22/07 y VERIFICADAS en el motor pf)

Principios aplicados (cómo evalúa pfSense):
1. Reglas **por interfaz**, aplican al tráfico que **entra** por ella (lo que esa zona intenta hacer).
2. **Top-down, primera coincidencia gana** — el orden es la política.
3. Sin coincidencia → **implicit deny** (bloqueado). Stateful: las respuestas de conexiones
   permitidas vuelven solas.

### Aliases — GUI `Firewall → Aliases`
- **`LAB_NETS`** (pestaña IP, type Network(s)): `10.10.0.0/24` DMZ · `10.20.0.0/24` CDE ·
  `10.30.0.0/24` CORP · `10.40.0.0/24` SOC.
- **`EGRESO_WEB`** (pestaña Ports): `53` DNS · `80` HTTP · `443` HTTPS.

Por qué aliases: las reglas referencian el **nombre**; agregar una zona = editar el alias una vez,
no cada regla. Mantenibilidad + autodocumentación.

### Reglas por zona — GUI `Firewall → Rules → pestañas DMZ / CDE / CORP` (mismas 2, EN ORDEN)
| # | Acción | Proto | Source | Destino | Puerto dest | Log | Descripción |
|---|---|---|---|---|---|---|---|
| 1 | **Block** | Any | `<Zona> subnets` | alias `LAB_NETS` | * | ✅ | Denegar y loggear trafico inter-zona (PCI DSS Req.1 - segmentacion) |
| 2 | **Pass** | TCP/UDP | `<Zona> subnets` | **any** | alias `EGRESO_WEB` | ✅ | Egreso web/DNS temporal para construccion - endurecer al final |

- **El orden ES la política:** el destino `any` de la regla 2 incluye a las otras zonas; el block
  de arriba atrapa el tráfico inter-zona antes (first match wins). Lo que llega vivo a la regla 2
  solo puede ir "hacia afuera".
- **LAN/SOC: defaults, sin tocar** (anti-lockout + allow-all — es la estación del analista).
- Truco GUI (puerto alias): `Destination Port Range` → From **(other)** → tipear el alias (To se
  completa con lo mismo). El error típico es dejar el desplegable en "any" → el puerto queda `*`
  (nos pasó: la primera versión permitía egreso por TODOS los puertos, y la de DMZ era solo TCP).
- El log quedó activo también en las reglas de egreso: más ruido, pero más materia prima para el
  SIEM de la Fase 2. Si molesta, se apaga después (el imprescindible es el log del block).

### Lección vivida: Save ≠ Apply (y "GUI ≠ motor")
**Save** escribe `config.xml`; el motor pf sigue corriendo el ruleset anterior hasta **Apply
Changes** (banner amarillo). Y si al recargar una regla no compila, pf **mantiene el ruleset viejo
completo** (Status → Filter Reload muestra el error). Nos pasó exacto: 6 reglas "visibles" en la
GUI y `pfctl -sr` sin ninguna — el banner pendiente en las capturas lo delató.

### Verificación en el motor — GUI `Diagnostics → Command Prompt`
```sh
pfctl -sr | grep USER_RULE      # toda regla creada por la GUI lleva label "USER_RULE: ..."
pfctl -t LAB_NETS -T show       # contenido cargado de una tabla/alias
```
Resultado (22/07): las 6 reglas cargadas, block ANTES que pass en em1/em2/em3. Cómo las renderiza pf:
- **Redes y aliases = tablas** (`<OPT1__NETWORK>`, `<LAB_NETS>`), no IPs literales en la regla —
  por eso un grep por "10.10" NO las encuentra (solo pesca las antispoof, que sí llevan CIDR).
- **El alias de puertos se expande:** 1 regla de GUI → 6 reglas pf (TCP y UDP × domain/http/https).
- `quick` = gana la primera coincidencia · `keep state` = stateful · `(if-bound)` = el estado
  queda atado a la interfaz donde nació.

## Prueba de validación de la política (22/07) — ✅ FASE 1 CERRADA

**Montaje:** Kali (VM pre-armada, registrada con `Máquina → Agregar` sobre su `.vbox`) conectada
**temporalmente** a `lab-dmz` en el rol de "servidor DMZ comprometido" — las reglas solo se
disparan con tráfico que entra por em1/em2/em3, así que desde la WAN no se pueden probar. IP
estática dentro de Kali (en las zonas no hay DHCP a propósito):
```bash
sudo nmcli con add type ethernet ifname eth0 con-name dmz ipv4.method manual \
  ipv4.addresses 10.10.0.50/24 ipv4.gateway 10.10.0.1 ipv4.dns 1.1.1.1
sudo nmcli con up dmz
```

**Los 5 comandos del veredicto** (cada uno prueba una cara distinta de la política):

| Comando | Resultado | Qué demuestra |
|---|---|---|
| `ping -c 3 10.20.0.1` | ✅ 100% loss | Segmentación DMZ→CDE — bloqueado por la regla propia (tracker `1784751273`) |
| `ping -c 3 10.40.0.2` | ✅ 100% loss | La estación del analista (SOC) inalcanzable desde la DMZ |
| `nslookup example.com` | ✅ resuelve vía 1.1.1.1 | Egreso UDP 53 permitido |
| `curl -I https://example.com` | ✅ HTTP/2 200 | Egreso TCP 443 permitido |
| `ping -c 3 8.8.8.8` | ✅ 100% loss | **Deny implícito**: ICMP no está en el pass (TCP/UDP) → muere solo |

**En el log** (`Status → System Logs → Firewall`, filtrable por interfaz): los ICMP inter-zona
aparecen bloqueados por **la regla propia** (la entrada cita la descripción "Denegar y loggear…" +
tracker), los egresos en verde por la regla de egreso, y el ping a 8.8.8.8 por el
`Default deny rule IPv4`. Tip GUI: la ✖ roja de cada entrada abre "Rule details" con la regla
exacta que matcheó. **Bonus observado:** los broadcasts DHCP de Kali al bootear
(`0.0.0.0:68 → 255.255.255.255:67`) murieron en el default deny — la zona ni siquiera responde
DHCP, coherente con el diseño de IPs estáticas.

## Evidencia de la fase
- `../evidence/fase1-01-pfsense-primer-boot-consola.png` — consola tras instalación, WAN/LAN default
- `../evidence/fase1-02-dashboard-5-zonas-configuradas.png` — dashboard con las 5 interfaces e IPs
- `../evidence/fase1-03-interface-assignments-mapa-em-zonas.png` — mapeo em↔zona con MACs
- `../evidence/fase1-04-reglas-dmz.png` / `-cde.png` / `-corp.png` — tablas de reglas por zona (block+log → egreso restringido)
- `../evidence/fase1-05-log-bloqueo-interzona.png` — log del firewall: bloqueos inter-zona por regla propia + egresos permitidos + default deny (con popup "Rule details")
- `../evidence/fase1-06-kali-bloqueos-interzona.png` — Kali: IP estática y pings a CDE/SOC bloqueados
- `../evidence/fase1-07-kali-egreso-y-deny-implicito.png` — Kali: DNS/HTTPS funcionando, ICMP a internet muerto

## Incidentes de la fase (lo que rompió y cómo se arregló)
- **Kernel 7.0 vs DKMS (18–20/07):** el kernel más nuevo del host rompía el módulo `vboxdrv`;
  quitar headers no bastó — hubo que **fijar GRUB** al kernel 6.17.0-35. Lección: pin del kernel
  del host cuando dependés de módulos DKMS.
- **E_ACCESSDENIED al crear vboxnet0 con IP 10.40.0.2 (21/07):** VirtualBox restringe rangos
  host-only por seguridad (default-deny de rangos); fix = autorizarlo en `/etc/vbox/networks.conf`.
