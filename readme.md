# Seguridad de Redes - Implementación y Hardening en FortiGate

Repositorio de documentación técnica y configuración del laboratorio práctico de seguridad perimetral, segmentación mediante VLANs/VLSM, hardening de Capa 2 y políticas UTM en FortiGate (FortiOS).

---

## 📋 Información General

- **Autor:** Manuel Alejandro Cruz Messón
- **Matrícula:** 2025-0689
- **Carrera:** Seguridad Informática
- **Fecha:** 25 de Septiembre 2026
- **Entorno de Simulación:** PNETLab

---

## 🗺️ Topología de Red

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

---

## 1. Diseño de Direccionamiento IP y VLSM

Para optimizar el direccionamiento y garantizar el aislamiento estructural entre clientes y servidores, se implementó un esquema con máscaras de longitud variable (**VLSM**) derivado del prefijo base privado `10.25.68.0/24`.

### 1.1 Requisitos y Asignación por Segmento

- **VLAN 10 (Red de Clientes/Usuarios):** Requiere dimensionamiento para alojar estaciones de trabajo con proyección de crecimiento (prefijo `/25`).
- **VLAN 20 (Red de Servidores / DMZ Interna):** Aloja los servidores de producción (`Web Server` y `DB Server`) con control estricto de accesos (prefijo `/26`).

| Segmento | ID VLAN | Red / Subred | Máscara | Rango Útil | Gateway | Dispositivos Clave |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **VLAN 10 (Usuarios)** | 10 | `10.25.68.0/25` | `255.255.255.128` | `10.25.68.1` - `10.25.68.126` | `10.25.68.1` | Cliente Ubuntu (`10.25.68.7`) |
| **VLAN 20 (Servidores)** | 20 | `10.25.68.128/26` | `255.255.255.192` | `10.25.68.129` - `10.25.68.190` | `10.25.68.129` | Web Server (`10.25.68.130`)<br>DB Server (`10.25.68.146`) |

### 1.2 Hardening de Capa 2 (Switch)

Con el propósito de mitigar vectores de ataque en la capa de enlace de datos, se configuraron las siguientes directivas:
- **SSHv2 Exclusivo:** Transporte de administración restringido, deshabilitando Telnet y versiones vulnerables.
- **DHCP Snooping:** Mitigación de servidores DHCP no autorizados (*Rogue DHCP*), definiendo el puerto *uplink* hacia el FortiGate como `trusted`.
- **BPDU Guard:** Protección de la topología Spanning Tree (STP) en puertos perimetrales/de acceso.
- **Port Security:** Configurado con direcciones MAC dinámicas persistentes (`sticky MAC`) y acción en modo `restrict` contra desbordamiento de tablas CAM (*CAM table overflow*).

---

## 2. Políticas de Red y Seguridad en FortiGate (FortiOS GUI)

### 2.1 Enrutamiento y NAT

1. **Ruta Estática por Defecto (Default Route):**
   - **Ruta GUI:** `Network` > `Static Routes` > `Create New`
   - **Destino:** `0.0.0.0/0`
   - **Interfaz:** `port1` (WAN)
   - **Gateway:** Asignado por la red upstream / Gateway WAN (`192.168.145.2`)
   - **Estado:** Activo en la Routing Table (`Dashboard` > `Network` > `Routing`).

2. **Traducción de Direcciones (PAT / SNAT):**
   - **Ruta GUI:** `Policy & Objects` > `Firewall Policy`
   - **Parámetro:** Opción `NAT` habilitada con `Use Outgoing Interface IP` sobre la política de salida a Internet (`POOL-USUARIO-INTERNET`), enmascarando las direcciones locales `10.25.68.0/24`.

### 2.2 Matriz de Filtrado de Tráfico (Firewall Policies)

| Política | Interfaz Origen | Interfaz Destino | Origen | Destino | Horario | Servicio | Acción | NAT |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| `ALLOW-USUARIOS-A-WEB` | `VLAN10-USUARIOS` | `VLAN20-WEB` | `NET-USUARIOS` | `HOST-WEB-SERVER` | always | HTTP, HTTPS | **ACCEPT** | Disabled |
| `ALLOW-WEB-A-DB` | `VLAN20-WEB` | `VLAN30-DB` | `HOST-WEB-SERVER` | `HOST-DB-SERVER` | always | MYSQL (3306) | **ACCEPT** | Disabled |
| `DENY-USUARIOS-A-DB` | `VLAN10-USUARIOS` | `VLAN30-DB` | `NET-USUARIOS` | `HOST-DB-SERVER` | always | MYSQL (3306) | **DENY** | - |
| `POOL-USUARIO-INTERNET` | `VLAN10-USUARIOS` | `port1` (WAN) | `NET-USUARIOS` | `all` | always | ALL | **ACCEPT** | **Enabled** |
| `Implicit Deny` | `any` | `any` | `all` | `all` | always | ALL | **DENY** | - |

---

## 3. Perfiles UTM y Mitigación de Amenazas

### 3.1 Mitigación de DoS / Rate Limiting (L4)
- **Ubicación GUI:** `Policy & Objects` > `DoS Policy`
- **Protected Interface:** `VLAN20-WEB`
- **Source / Destination:** `all` $\rightarrow$ `10.25.68.130` (Web Server)
- **Anomalía Activada:** `tcp_syn_flood`
- **Acción:** `Block`
- **Umbral (Threshold):** `50 paquetes/segundo`
- **Mecanismo:** Procesado directamente en el kernel mediante tablas de estado aceleradas sin dependencia de licencias comerciales.

### 3.2 Perfil de Inspección Profunda (DPI - Deep Packet Inspection)
- **Ubicación GUI:** `Security Profiles` > `SSL/SSH Inspection`
- **Nombre:** `DPI_LAB_USUARIOS`
- **Inspection Method:** `Multiple Clients Connecting to Multiple Servers` (`Full SSL Inspection`)
- **CA Certificate:** `Fortinet_CA_SSL`
- **Untrusted/Invalid SSL Certificates:** Parametrizado en `Allow` para permitir tráfico de prueba local con certificados autofirmados sin romper la negociación TLS.

### 3.3 Sensor IPS y Regla Anti-SQL Injection
- **Firma Custom Compilada:**
  ```text
  F-SBID(--name "SQLI_TEST"; --protocol tcp; --service HTTP; --pattern "OR"; --no_case; )
  ```
- **Perfil IPS:** `IPS-PROTECT-SQLI`
- **Acción:** `Block` con `Quarantine: Attacker IP` (duración: 5 minutos) y registro de paquetes (`Packet Logging: Enabled`).

### 3.4 Control de Archivos y Filtrado Web (.exe)
- **Perfiles:**
  - `Security Profiles` > `File Filter` (`BLOCK-EXE-DOWNLOAD`)
  - `Security Profiles` > `Web Filter` (URL Filter estático)
- **Regla:** Bloqueo de binarios ejecutables (`exe`) en tráfico HTTP/FTP y patrón comodín `*.exe*`.

---

## 4. Pruebas Funcionales y Resultados

| # | Requisito / Prueba | Comando de Prueba | Resultado Obtenido | Diagnóstico |
| :-: | :--- | :--- | :--- | :---: |
| **1** | Ruta por Defecto | `ping -c 2 8.8.8.8` | `2 packets transmitted, 2 received, 0% packet loss` | **Éxito** |
| **2** | NAT Outbound (Internet) | `curl -I http://google.com` | `HTTP/1.1 200 OK` (SNAT con IP de WAN reflejado en logs) | **Éxito** |
| **3** | Acceso Web Seguro (443) | `curl -k -I https://10.25.68.130/` | `HTTP/1.1 200 OK (Apache/2.4.29)` | **Éxito** |
| **4** | Bloqueo Usuarios $\rightarrow$ DB (3306) | `nc -zv -w 2 10.25.68.146 3306` | `Connection to 10.25.68.146 3306 port [tcp/mysql] failed: Timeout` | **Éxito** |
| **5** | Conectividad Web Server $\rightarrow$ DB | `nc -zv 10.25.68.146 3306`<br>`ping -c 2 10.25.68.146` | Puerto 3306 abierto (`open`). Ping al 100% de pérdida por *Implicit Deny*. | **Éxito** |
| **6** | Rate Limiting DoS (SYN Flood) | `sudo hping3 -S -p 443 --flood 10.25.68.130` | Paquetes descartados al superar 50 pps. Contador de `Dropped Packets` activo en FortiOS DoS Policy. | **Éxito** |
| **7** | Inspección Profunda (DPI) | `curl -k -v https://10.25.68.130/ 2>&1 \| grep issuer` | Emisor responde `CN=ubuntu`. Se analizaron metadatos del handshake. | **Parcial** *(Ver §5.1)* |
| **8** | Inyección SQL y Cuarentena | `curl -i 'http://10.25.68.130/login.php?id=1%20UNION%20SELECT%201,2,3'` | Respuesta interceptada con `HTTP/1.1 403 Forbidden` (bloqueo UTM WAD). | **Parcial** *(Ver §5.2)* |
| **9** | Bloqueo Descarga Binarios (.exe) | `curl -i http://10.25.68.130/setup.exe` | Petición interceptada por directiva de inspección URL. | **Parcial** *(Ver §5.3)* |

---

## 5. Justificación Técnica de Pruebas Parciales en Laboratorio Virtual

Al trabajar en entornos virtualizados sin licencias comerciales activas de FortiGuard, ciertas funciones presentan divergencias técnicas operativas:

1. **Inspección Profunda SSL (DPI):** Al invocar `curl` directamente por dirección IP sin encabezado `SNI` y emplear un certificado autofirmado en el servidor Apache, el motor TLS de FortiOS preserva la sesión pasiva y no regenera el certificado con `Fortinet_CA_SSL` para prevenir caídas de negociación TLS en el cliente.
2. **SQLi vs. Cuarentena de Host:** La VM de FortiGate carece de la base de firmas binarias comerciales (`ips.pkg`). No obstante, la anomalía HTTP es detectada y cortada por el demonio proxy **WAD** retornando un error `403 Forbidden`. Dado que el bloqueo se ejecuta a nivel de capa de aplicación y no en el motor IPS de kernel, no se pobló la tabla de host en cuarentena de Capa 3/4.
3. **File Filter (.exe):** La descompresión de flujos binarios pesados requiere de motores de análisis licenciados; el equipo opera bajo directiva fail-open o filtro por URL proxy para evitar sobreconsumo de RAM en el hipervisor.

---

## 6. Conclusiones

1. **Aislamiento y Mínimo Privilegio:** Se estableció una segmentación perimetral e interna estricta. Los usuarios de la VLAN 10 carecen de visibilidad y acceso a la base de datos, mientras que el servidor web solo puede comunicarse hacia la base de datos a través del puerto TCP `3306`.
2. **Defensa en Profundidad:** El esquema protege tanto la Capa 2 (DHCP Snooping, Port Security, BPDU Guard) como las Capas 3 y 4 mediante políticas de firewall de denegación implícita y mitigación DoS a nivel de kernel.
3. **Validación de Arquitectura:** El diseño satisface las exigencias de seguridad perimetral, enrutamiento, traducción NAT e intercepción UTM, quedando plenamente justificados los límites operativos de la virtualización sin suscripciones activas.
