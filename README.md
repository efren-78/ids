# Sistema de Detección de Intrusiones (IDS)

Sistema de detección de intrusiones, capaz de analizar flujos de red y detectar anomalías como escaneos de puertos, ataques de SYN flood y ataques de fuerza bruta (SSH, FTP, Telnet, RDP, bases de datos). El proyecto está construido sobre Maven y utiliza un enfoque en tiempo real con captura en vivo mediante procesamiento asíncrono multihilo.

El sistema es desacoplado, lo cual permite agregar nuevos detectores de intrusiones de forma sencilla sin afectar el funcionamiento del sistema.

## Requisitos

* **Java 25** o superior.
* **Maven 3.9.x** o superior.
* **Driver npcap** (instalar con permisos de administrador)

## Compilación y Ejecución

### Compilar el Proyecto

Para compilar el proyecto y generar el archivo JAR ejecutable, ejecuta el siguiente comando en la raíz del proyecto:

```bash
mvn compile
```

O bien, para compilar y empaquetar el proyecto en un único archivo ejecutable (incluyendo todas las dependencias):

```bash
mvn package
```

### Ejecutar la Aplicación

Para ejecutar la aplicación directamente desde la línea de comandos de Maven:

```bash
mvn exec:java
```

> **Nota para PowerShell en Windows:** Si prefieres especificar la clase principal por parámetro, envuelve todo el argumento `-D` entre comillas:
> ```powershell
> mvn exec:java "-Dexec.mainClass=org.example.ids.MainIDS"
> ```

Si has compilado el proyecto previamente, puedes ejecutar el JAR generado de la siguiente manera:

```bash
java -jar target/ids-1.0-SNAPSHOT.jar
```

## Visualización y Dashboard Web

La interfaz de usuario se puede acceder mediante el servidor web local integrado en la dirección `http://localhost:8080`.

### Acceso y Autenticación

El sistema cuenta con protección de acceso basada en sesiones:

1. **Login:** `http://localhost:8080/login`
2. **Dashboard Principal:** `http://localhost:8080/`

**Credenciales por defecto:**
* **Usuario:** `admin`
* **Contraseña:** `admin`

### Configuración del Servidor y Autenticación

Puedes personalizar las propiedades del Dashboard y la seguridad en el archivo `ids.properties`:
* `ids.ui.enabled`: Habilita o deshabilita la interfaz web (`true`/`false`).
* `ids.ui.port`: Puerto del servidor web (por defecto `8080`).
* `ids.auth.enabled`: Habilita o deshabilita el inicio de sesión obligatorio (`true`/`false`).
* `ids.auth.username` / `ids.auth.password`: Credenciales de acceso del usuario administrador.
* `ids.auth.session.timeout.minutes`: Tiempo de expiración de sesión (por defecto `30` minutos).

### Limpiar el Proyecto

Para limpiar el directorio de salida (`target`) y eliminar los archivos compilados:

```bash
mvn clean
```

### Ejecutar Tests

Para ejecutar las pruebas unitarias desarrolladas para el proyecto:

```bash
mvn test
```

## Estructura del Proyecto

```
ids/
├── src/
│   ├── main/
│   │   └── java/
│   │       └── org/example/ids/
│   │           ├── MainIDS.java            # Punto de entrada y orquestador de la aplicación
│   │           ├── DetectionEngine.java    # Motor de detección multihilo
│   │           ├── Event.java              # Modelo de datos para eventos de red
│   │           ├── PacketParser.java       # Decodificador de paquetes y filtro de ruido
│   │           ├── IdsConfig.java          # Carga y gestión de configuración centralizada
│   │           ├── CaptureController.java  # Controlador de captura y ciclo de vida de interfaz de red
│   │           ├── auth/                   # Capa de autenticación
│   │           │   ├── AuthFilter.java     # Filtro HTTP de protección de rutas y sesiones
│   │           │   └── AuthManager.java    # Gestor de sesiones, credenciales y expiración
│   │           ├── detectors/              # Detectores de intrusiones
│   │           │   ├── Detector.java       # Interfaz base de detectores
│   │           │   ├── PortScanDetector.java   # Detección de escaneos de puertos
│   │           │   ├── SynFloodDetector.java   # Detección de ataques SYN Flood
│   │           │   └── BruteForceDetector.java # Detección de ataques de fuerza bruta
│   │           └── ui/                     # Servidor y UI del Dashboard SOC
│   │               ├── AlertHistory.java   # Historial en memoria de alertas emitidas
│   │               └── DashboardServer.java # Servidor HTTP embebido y endpoints REST/SSE
│   ├── test/
│   │   └── java/
│   │       └── org/example/ids/            # Tests unitarios y de integración del sistema
│   └── resources/
│       ├── ids.properties                  # Archivo de propiedades de configuración
│       └── web/                            # Frontend del Dashboard SOC
│           ├── index.html                  # Panel principal SOC en tiempo real
│           ├── login.html                  # Vista de autenticación
│           ├── style.css                   # Estilos del dashboard
│           ├── style-login.css             # Estilos de la vista de login
│           └── app.js                      # Lógica cliente, SSE y control de captura
├── pom.xml                                 # Configuración y dependencias de Maven
└── README.md                               # Documentación del proyecto
```