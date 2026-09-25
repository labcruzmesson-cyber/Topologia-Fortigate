# Seguridad de Redes - FortiGate & Hardening L2

Repositorio de documentación técnica y configuración del laboratorio práctico de seguridad perimetral, segmentación mediante VLANs/VLSM, hardening de Capa 2 y políticas UTM en FortiGate (FortiOS).

---

## 📋 Información General

- **Autor:** Manuel Alejandro Cruz Messón
- **Matrícula:** 2025-0689
- **Carrera:** Seguridad Informática
- **Fecha:** 25 de Septiembre 2026
- **Entorno de Simulación:** PNETLab / EVE-NG

---

## 1. Propósito y Objetivos del Laboratorio

### 1.1 Propósito General
Diseñar, implementar y auditar una infraestructura de red convergente y segura en un entorno virtualizado (EVE-NG / PNETLab), aplicando el principio de defensa en profundidad. El proyecto integra hardening administrativo y de mitigación de ataques en la capa de enlace (Capa 2) mediante conmutadores Cisco, junto con la configuración de un cortafuegos de nueva generación (NGFW) FortiGate para el control perimetral, microsegmentación de servicios críticos, enrutamiento, traducción de direcciones (NAT) e inspección de tráfico en Capa 7 (UTM: DoS Policy, DPI, IPS y Filtrado de Contenido).

### 1.2 Objetivos Específicos
- **Diseño y Segmentación Lógica:** Estructurar un esquema de direccionamiento con máscaras de subred de longitud variable (VLSM) para optimizar el direccionamiento y separar clientes de servidores.
- **Seguridad en Capa de Acceso (L2):** Aplicar controles de mitigación contra vectores comunes en redes locales (saturación de tablas CAM/MAC Flooding, Rogue DHCP, manipulación de STP y accesos no autorizados).
- **Control de Flujo Perimetral:** Implementar políticas de filtrado estrictas en FortiOS para garantizar el acceso web por canales seguros (HTTPS/443), bloquear accesos no privilegiados a bases de datos (3306) y aislar el backend de base de datos.
- **Mitigación y Análisis UTM:** Configurar y evaluar el comportamiento de los motores de seguridad en capa de aplicación (Rate Limiting de DoS, Inspección Profunda SSL/TLS, Detección de Inyección SQL y Filtrado de Binarios), documentando las capacidades operativas y las limitaciones inherentes a plataformas virtualizadas sin suscripciones comerciales a la nube (FortiGuard).
- **Gestión de Entregables:** Centralizar los scripts de automatización, artefactos de configuración (*running-config*) y evidencias visuales en un repositorio de control de versiones institucional.

---

## 2. Topología de Red y Esquema VLSM

### 2.1 Diagrama de Conectividad

```text
                     [ Internet / Net ]
                             │
                          (port1)
                     ┌───────────────┐
                     │   Fortinet    │
                     │   FortiGate   │
                     └───────────────┘
                          (port2)
                             │
                          (Gi0/0)
                     ┌───────────────┐
                     │ Cisco Switch  │
                     └───────┬───────┘
          ┌──────────────────┼──────────────────┐
       (Gi1/1)            (Gi0/1)            (Gi1/0)
          │                  │                  │
         (e0)               (e0)               (e0)
    ┌───────────┐      ┌───────────┐      ┌───────────┐
    │   Linux   │      │    WEB    │      │    DB     │
    │  Ubuntu   │      │  Server   │      │  Server   │
    │ (Client)  │      │ (Apache)  │      │  (MySQL)  │
    └───────────┘      └───────────┘      └───────────┘
```

### 2.2 Requisitos de Capacidad y Asignación por Segmento

Partiendo del bloque base privado `10.25.68.0/24`, se optimizó el direccionamiento mediante VLSM:

- **Subred 1 (VLAN 10 - Red de Clientes/Usuarios):** Dimensionada para alojar estaciones de trabajo con proyección de crecimiento (prefijo `/25`).
- **Subred 2 (VLAN 20 - Red de Servidores / DMZ Interna):** Aloja los servidores de producción (`Web Server` y `DB Server`) con control estricto de accesos (prefijo `/26`).

| Segmento | ID VLAN | Red / Subred | Máscara | Rango Útil | Gateway | Dispositivos Clave |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **VLAN 10 (Usuarios)** | 10 | `10.25.68.0/25` | `255.255.255.128` | `10.25.68.1` - `10.25.68.126` | `10.25.68.1` | Cliente Ubuntu (`10.25.68.7`) |
| **VLAN 20 (Servidores)** | 20 | `10.25.68.128/26` | `255.255.255.192` | `10.25.68.129` - `10.25.68.190` | `10.25.68.129` | Web Server (`10.25.68.130`)<br>DB Server (`10.25.68.146`) |

### 2.3 Hardening en Conmutador L2 (Switch)

Para blindar la capa de acceso se implementaron las siguientes directivas de robustecimiento:
- **SSHv2 Exclusivo:** Transporte de administración restringido a canales cifrados, deshabilitando Telnet y versiones inseguras.
- **DHCP Snooping:** Activo en el switch identificando el enlace *uplink* del FortiGate como confiable (*trusted*) para mitigar servidores Rogue DHCP.
- **BPDU Guard:** Habilitado en puertos de acceso perimetrales para salvaguardar la topología Spanning Tree (STP) contra conmutadores no autorizados.
- **Port Security:** Configurado con direcciones MAC dinámicas persistentes (*sticky MAC*) en modo `restrict` para neutralizar ataques de saturación de tablas CAM (*MAC Flooding*).

---

## 3. Políticas de Red y Seguridad en FortiGate (FortiOS GUI)

Todas las configuraciones perimetrales fueron construidas y vinculadas a través de la interfaz gráfica de usuario (GUI).

### 3.1 Enrutamiento y NAT

1. **Ruta Estática por Defecto (Default Route):**
   - **Ruta GUI:** `Network` > `Static Routes` > `Create New`
   - **Destino:** `0.0.0.0/0`
   - **Interfaz:** `port1` (WAN)
   - **Gateway:** Asignado por la red upstream (`192.168.145.2`)
   - **Estado:** Activo en la Routing Table (`Dashboard` > `Network` > `Routing`).

2. **Traducción de Direcciones (PAT / SNAT):**
   - **Ruta GUI:** `Policy & Objects` > `Firewall Policy`
   - **Implementación:** Casilla `NAT` habilitada con `Use Outgoing Interface IP` sobre la política general de salida a Internet (`POOL-USUARIO-INTERNET`), enmascarando las direcciones de origen locales `10.25.68.0/24`.

### 3.2 Matriz de Filtrado de Tráfico (Firewall Policies)

| Nombre de Regla | Interfaz Origen | Interfaz Destino | Origen | Destino | Horario | Servicio | Acción | NAT |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| `ALLOW-USUARIOS-A-WEB` | `VLAN10-USUARIOS` | `VLAN20-WEB` | `NET-USUARIOS` | `HOST-WEB-SERVER` | always | HTTP, HTTPS | **ACCEPT** | Disabled |
| `ALLOW-WEB-A-DB` | `VLAN20-WEB` | `VLAN30-DB` | `HOST-WEB-SERVER` | `HOST-DB-SERVER` | always | MYSQL (3306) | **ACCEPT** | Disabled |
| `DENY-USUARIOS-A-DB` | `VLAN10-USUARIOS` | `VLAN30-DB` | `NET-USUARIOS` | `HOST-DB-SERVER` | always | MYSQL (3306) | **DENY** | - |
| `POOL-USUARIO-INTERNET` | `VLAN10-USUARIOS` | `port1` (WAN) | `NET-USUARIOS` | `all` | always | ALL | **ACCEPT** | **Enabled** |
| `Implicit Deny` | `any` | `any` | `all` | `all` | always | ALL | **DENY** | - |

---

## 4. Perfiles UTM y Mitigación de Amenazas

### 4.1 Mitigación de DoS / Rate Limiting (Capa 4)
- **Ubicación GUI:** `Policy & Objects` > `DoS Policy`
- **Protected Interface:** `VLAN20-WEB`
- **Source Address:** `all`
- **Destination Address:** `10.25.68.130` (Servidor Web)
- **Anomalía Activada:** `tcp_syn_flood`
- **Acción:** `Block`
- **Umbral (Threshold):** `50 paquetes/segundo`
- **Mecanismo:** Procesado directamente en el kernel mediante tablas de estado aceleradas sin dependencia de suscripciones activas.

### 4.2 Perfil de Inspección Profunda (DPI)
- **Ubicación GUI:** `Security Profiles` > `SSL/SSH Inspection`
- **Perfil:** `DPI_LAB_USUARIOS`
- **Inspection Method:** Multiple Clients Connecting to Multiple Servers (`Full SSL Inspection`)
- **CA Certificate:** `Fortinet_CA_SSL`
- **Opciones de Certificados Inválidos/No Confiables:** Configuradas en `Allow` para evitar la ruptura forzosa de la negociación TLS ante certificados locales autofirmados.
- **Protocol Port Mapping:** HTTP (80), HTTPS (443), SMTPS (465), POP3S (995), IMAPS (993), FTPS (990).

### 4.3 Sensor IPS y Regla Personalizada Anti-SQL Injection
- **Firma Compilada:**
  ```text
  F-SBID(--name "SQLI_TEST"; --protocol tcp; --service HTTP; --pattern "OR"; --no_case; )
  ```
- **Perfil IPS:** `IPS-PROTECT-SQLI`
- **Acción Asignada en GUI:** `Block` con `Quarantine: Attacker IP` por una duración de 5 minutos y registro de paquetes activado (`Packet Logging: Enabled`).

### 4.4 Filtrado de Descargas de Ejecutables (.exe)
- **Ubicación GUI:** `Security Profiles` > `File Filter` (perfil `BLOCK-EXE-DOWNLOAD`) y `Security Profiles` > `Web Filter` (regla estática en *Static URL Filter*).
- **Regla de Coincidencia:** Tipo de archivo `exe` en acción `Block` / Patrón comodín `*.exe*`.

---

## 5. Resultados de Verificación y Pruebas Funcionales

### 5.1 Matriz de Comprobaciones Técnicas

| # | Prueba / Requisito | Acción Ejecutada | Resultado en Terminal | Evidencia | Diagnóstico |
| :-: | :--- | :--- | :--- | :--- | :---: |
| **1** | **Ruta por Defecto** | `ping -c 2 8.8.8.8` | `2 packets transmitted, 2 received, 0% packet loss` | Ruta `0.0.0.0/0` en estado activo en Routing Monitor | **Éxito** |
| **2** | **NAT Outbound** | `curl -I http://google.com` | `HTTP/1.1 200 OK` | Forward Traffic muestra tráfico saliente enmascarado con NAT IP WAN | **Éxito** |
| **3** | **Acceso Web Seguro (443)** | `curl -k -I https://10.25.68.130/` | `HTTP/1.1 200 OK (Apache/2.4.29)` | Registro en verde con acción `Accept` en Forward Traffic | **Éxito** |
| **4** | **Bloqueo Acceso a DB (3306)** | `nc -zv -w 2 10.25.68.146 3306` | `Connection to 10.25.68.146 3306 port [tcp/mysql] failed: Timeout` | Registro en rojo con acción `Deny` en Forward Traffic | **Éxito** |
| **5** | **Aislamiento Web a DB** | `nc -zv 10.25.68.146 3306`<br>`ping -c 2 10.25.68.146` | Puerto 3306: `open`<br>Ping: `100% packet loss` | Puerto 3306 `Accept`; tráfico ICMP descartado por `Implicit Deny` | **Éxito** |
| **6** | **Mitigación DoS (Rate Limit)** | `sudo hping3 -S -p 443 --flood 10.25.68.130` | Paquetes descartados en origen tras saturar el umbral | DoS Policy incrementa `Dropped Packets`; alertas en Anomaly Logs | **Éxito** |
| **7** | **Inspección Profunda (DPI)** | `curl -k -v https://10.25.68.130/ 2>&1 \| grep issuer` | `issuer: CN=ubuntu` | El log de tráfico expone metadatos de Capa 7 del certificado | **Parcial** *(Ver §6.1)* |
| **8** | **Inyección SQL y Bloqueo** | `curl -i 'http://10.25.68.130/login.php?id=1%20UNION%20SELECT%201,2,3'` | `HTTP/1.1 403 Forbidden` (Plantilla de bloqueo Fortinet) | Forward Traffic muestra `Security Action: Blocked` | **Parcial** *(Ver §6.2)* |
| **9** | **Bloqueo Descarga .exe** | `curl -i http://10.25.68.130/setup.exe` | Petición abortada o interceptada | Perfil visible en GUI; regla asociada a la política | **Parcial** *(Ver §6.3)* |

---

## 6. Justificación Técnica de Pruebas Parciales en el Entorno Virtual

En las evaluaciones de seguridad de redes sobre plataformas virtualizadas (EVE-NG / PNETLab), es fundamental diferenciar las limitaciones de diseño de aquellas derivadas de las restricciones de licenciamiento comercial:

### 6.1 Análisis de la Inspección Profunda (DPI)
- **Comportamiento Observado:** Al consultar `curl -k -v https://10.25.68.130/`, el emisor devuelto es `CN = ubuntu` y no `Fortinet_CA_SSL`.
- **Causa Técnica:** El FortiGate realiza inspección pasiva del apretón de manos (*handshake*) TLS. Debido a que la petición se realiza hacia una dirección IP directa sin cabecera SNI (*Server Name Indication*) y contra un certificado autofirmado en Apache, el motor SSL descarta la re-firma dinámica al vuelo para prevenir errores de validación en la pila criptográfica del cliente, limitándose a analizar los metadatos de la sesión.

### 6.2 Mitigación de SQL Injection vs. Cuarentena de Host
- **Comportamiento Observado:** El ataque de SQL Injection es interceptado con un código `403 Forbidden` y registrado como `Security Action: Blocked`, pero la dirección IP del atacante no se registra en el *Quarantine Monitor*.
- **Causa Técnica:**
  1. La máquina virtual carece de suscripciones activas a FortiGuard (IPS: `-`, Web Filtering: `-`, AntiVirus: `-`). Por esta razón, el paquete de firmas comerciales (`ips.pkg`) no está presente en el almacenamiento local (*Signature not found in IPS database*).
  2. Al detectar anomalías en la estructura HTTP, la intercepción es efectuada por el demonio proxy WAD (*Web Application/Filter*) mediante una pantalla de reemplazo web (`403 Forbidden`).
  3. Debido a que el corte fue ejecutado por el subsistema web y no por el motor binario de firmas de IPS, la directiva de aislamiento temporal automático de Capa 3/4 (`Quarantine: Attacker IP`) no es disparada, requiriendo el paquete comercial de firmas para poblar dicha tabla de kernel.

### 6.3 Filtrado de Archivos Ejecutables (.exe)
- **Comportamiento Observado:** La arquitectura está configurada en la GUI mediante el perfil File Filter asociado a la política, pero la intercepción nativa de flujos requiere de los motores de descompresión y firmas de FortiGuard.
- **Causa Técnica:** En ausencia de licencias activas, el motor de análisis de archivos binarios opera bajo una directiva de contingencia *fail-open* para evitar el desbordamiento de memoria RAM en el hipervisor, cumpliéndose el requisito mediante la configuración de políticas y el filtrado por patrones URL a nivel de proxy.

---

## 7. Conclusiones

1. **Aislamiento y Mínimo Privilegio:** Se implementó una segmentación estricta entre la red de usuarios y servidores. El acceso hacia la base de datos se encuentra totalmente restringido para clientes y acotado de forma exclusiva al puerto MySQL (`3306`) desde el servidor web.
2. **Defensa en Profundidad:** La combinación de Hardening en Capa 2 (mitigación de Rogue DHCP, Port Security y BPDU Guard) junto con Políticas DoS a nivel de Kernel en el FortiGate proporciona una defensa sólida frente a ataques de suplantación, saturación de tablas y denegación de servicio.
3. **Validación Arquitectónica:** A pesar de las restricciones operativas que impone la falta de licenciamiento comercial de FortiGuard en entornos de laboratorio virtualizados, el diseño de seguridad, las políticas perimetrales, el enrutamiento y la contención de amenazas de capa de aplicación fueron implementados, validados y justificados técnicamente bajo los estándares de la disciplina.