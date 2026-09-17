package org.example.ids;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

/**
 * Gestor centralizado y resiliente de configuración del IDS.
 *
 * Carga las propiedades desde `ids.properties` en el classpath o desde
 * una ruta externa vía `-Dids.config.file=ruta/al/archivo.properties`.
 * Proporciona valores por defecto seguros (*fail-safe*) si el archivo no existe
 * o contiene entradas malformadas.
 */
public class IdsConfig {

    private static final Logger logger = LoggerFactory.getLogger(IdsConfig.class);
    private static final String DEFAULT_PROPERTIES_RESOURCE = "ids.properties";
    private static final String CONFIG_FILE_SYSTEM_PROPERTY = "ids.config.file";

    private static volatile IdsConfig instance;

    private final Properties properties = new Properties();

    public static IdsConfig getInstance() {
        if (instance == null) {
            synchronized (IdsConfig.class) {
                if (instance == null) {
                    instance = new IdsConfig();
                }
            }
        }
        return instance;
    }

    public IdsConfig() {
        loadConfig();
    }

    public IdsConfig(Properties customProperties) {
        if (customProperties != null) {
            this.properties.putAll(customProperties);
        }
    }

    private void loadConfig() {
        // 1. Intentar cargar desde ruta externa si fue especificada
        String externalPath = System.getProperty(CONFIG_FILE_SYSTEM_PROPERTY);
        if (externalPath != null && !externalPath.isBlank()) {
            File externalFile = new File(externalPath);
            if (externalFile.exists() && externalFile.canRead()) {
                try (InputStream fis = new FileInputStream(externalFile)) {
                    properties.load(fis);
                    logger.info("Configuración cargada exitosamente desde archivo externo: {}", externalPath);
                    return;
                } catch (Exception e) {
                    logger.warn("No se pudo leer el archivo externo {}. Intentando classpath: {}", externalPath, e.getMessage());
                }
            } else {
                logger.warn("Archivo externo especificado '{}' no existe o no se puede leer.", externalPath);
            }
        }

        // 2. Cargar desde el classpath
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(DEFAULT_PROPERTIES_RESOURCE)) {
            if (is != null) {
                properties.load(is);
                logger.info("Configuración cargada exitosamente desde classpath: {}", DEFAULT_PROPERTIES_RESOURCE);
            } else {
                logger.warn("Archivo '{}' no encontrado en classpath. Se utilizarán valores por defecto en memoria.", DEFAULT_PROPERTIES_RESOURCE);
            }
        } catch (Exception e) {
            logger.error("Error al cargar '{}' desde classpath: {}. Usando valores por defecto.", DEFAULT_PROPERTIES_RESOURCE, e.getMessage());
        }
    }

    public int getInt(String key, int defaultValue) {
        String val = properties.getProperty(key);
        if (val == null || val.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            logger.warn("Valor numérico inválido para '{}': '{}'. Usando valor por defecto: {}", key, val, defaultValue);
            return defaultValue;
        }
    }

    public long getLong(String key, long defaultValue) {
        String val = properties.getProperty(key);
        if (val == null || val.isBlank()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(val.trim());
        } catch (NumberFormatException e) {
            logger.warn("Valor numérico inválido para '{}': '{}'. Usando valor por defecto: {}", key, val, defaultValue);
            return defaultValue;
        }
    }

    public boolean getBoolean(String key, boolean defaultValue) {
        String val = properties.getProperty(key);
        if (val == null || val.isBlank()) {
            return defaultValue;
        }
        return Boolean.parseBoolean(val.trim());
    }

    public String getString(String key, String defaultValue) {
        String val = properties.getProperty(key);
        if (val == null || val.isBlank()) {
            return defaultValue;
        }
        return val.trim();
    }

    // --- Helpers tipados de configuración de Captura ---
    public int getCaptureSnaplen() {
        return getInt("ids.capture.snaplen", 65536);
    }

    public int getCaptureTimeoutMs() {
        return getInt("ids.capture.timeout.ms", 10);
    }

    public String getCaptureFilter() {
        return getString("ids.capture.filter", "ip or ip6");
    }

    public boolean isCapturePromiscuous() {
        return getBoolean("ids.capture.promiscuous", true);
    }

    // --- Helpers de Motor, Workers y Purga ---
    public int getEnginePurgeIntervalSeconds() {
        return getInt("ids.engine.purge.interval.seconds", 30);
    }

    public int getEngineWorkerCount() {
        int configured = getInt("ids.engine.worker.count", 0);
        if (configured <= 0) {
            // Auto-detectar número de cores disponibles (mínimo 2)
            return Math.max(2, Runtime.getRuntime().availableProcessors());
        }
        return configured;
    }

    public int getEngineQueueCapacity() {
        return getInt("ids.engine.queue.capacity", 10000);
    }

    // --- Helpers de Port Scan ---
    public long getPortScanWindowMs() {
        return getLong("ids.detector.portscan.window.ms", 10000L);
    }

    public int getPortScanThreshold() {
        return getInt("ids.detector.portscan.threshold", 15);
    }

    public long getPortScanMaxCapacity() {
        return getLong("ids.detector.portscan.max.capacity", 50000L);
    }

    // --- Helpers de SYN Flood ---
    public long getSynFloodWindowMs() {
        return getLong("ids.detector.synflood.window.ms", 5000L);
    }

    public int getSynFloodThreshold() {
        return getInt("ids.detector.synflood.threshold", 50);
    }

    public long getSynFloodMaxCapacity() {
        return getLong("ids.detector.synflood.max.capacity", 50000L);
    }

    // --- Helpers de Fuerza Bruta ---
    public long getBruteForceWindowMs() {
        return getLong("ids.detector.bruteforce.window.ms", 10000L);
    }

    public int getBruteForceThreshold() {
        return getInt("ids.detector.bruteforce.threshold", 20);
    }

    public long getBruteForceMaxCapacity() {
        return getLong("ids.detector.bruteforce.max.capacity", 50000L);
    }

    public java.util.Set<Integer> getBruteForceTargetPorts() {
        String portsStr = getString("ids.detector.bruteforce.ports", "21,22,23,3389,3306,5432");
        java.util.Set<Integer> ports = new java.util.HashSet<>();
        if (portsStr != null && !portsStr.isBlank()) {
            for (String p : portsStr.split(",")) {
                try {
                    ports.add(Integer.parseInt(p.trim()));
                } catch (NumberFormatException ignored) {
                }
            }
        }
        if (ports.isEmpty()) {
            ports.addAll(java.util.List.of(21, 22, 23, 3389, 3306, 5432));
        }
        return ports;
    }

    // --- Helpers de Servidor UI ---
    public boolean isUiEnabled() {
        return getBoolean("ids.ui.enabled", true);
    }

    public int getUiPort() {
        return getInt("ids.ui.port", 8080);
    }

    // --- Helpers de Autenticación del Dashboard ---
    public boolean isAuthEnabled() {
        return getBoolean("ids.auth.enabled", true);
    }

    public String getAuthUsername() {
        return getString("ids.auth.username", "admin");
    }

    public String getAuthPassword() {
        return getString("ids.auth.password", "admin");
    }

    public int getAuthSessionTimeoutMinutes() {
        return getInt("ids.auth.session.timeout.minutes", 30);
    }
}


