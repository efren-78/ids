package org.example.ids.detectors;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import org.example.ids.Event;
import org.example.ids.IdsConfig;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Detecta escaneo de puertos (Port Scanning).
 *
 * Algoritmo: Rastrea intentos de conexión (en TCP: paquetes SYN sin ACK, o sondas UDP)
 * desde una misma IP origen hacia múltiples puertos distintos en una misma IP destino
 * dentro de una ventana de tiempo.
 *
 * Filtra el tráfico establecido y aísla la detección por par atacante -> víctima
 * para evitar falsos positivos provocados por la navegación web cotidiana o consultas DNS.
 */
public class PortScanDetector implements Detector {

    private static final long DEFAULT_WINDOW_MS = 10_000;
    private static final int DEFAULT_PORT_THRESHOLD = 15;
    private static final long DEFAULT_MAX_CAPACITY = 50_000;

    private final int portThreshold;
    private final Cache<String, Set<Integer>> connections;

    public PortScanDetector() {
        this(IdsConfig.getInstance());
    }

    public PortScanDetector(IdsConfig config) {
        this(
            config != null ? config.getPortScanMaxCapacity() : DEFAULT_MAX_CAPACITY,
            config != null ? config.getPortScanWindowMs() : DEFAULT_WINDOW_MS,
            config != null ? config.getPortScanThreshold() : DEFAULT_PORT_THRESHOLD
        );
    }

    public PortScanDetector(long maxCapacity, long windowMs, int portThreshold) {
        this.portThreshold = portThreshold;
        this.connections = Caffeine.newBuilder()
                .maximumSize(maxCapacity)
                .expireAfterWrite(windowMs, TimeUnit.MILLISECONDS)
                .recordStats()
                .build();
    }

    /**
     * Analiza un evento y lo clasifica como PORT_SCAN si la IP origen ha intentado
     * conectar a un número excesivo de puertos distintos en una misma IP destino.
     */
    @Override
    public void analyze(Event event) {
        if (event == null || event.getSrcIp() == null || event.getSrcIp().isBlank()
                || event.getDstIp() == null || event.getDstIp().isBlank()) {
            return;
        }

        // Para TCP: solo analizar intentos de inicio de conexión (SYN activo y ACK inactivo)
        // Esto descarta tráfico establecido, paquetes de datos normales y respuestas
        if ("TCP".equalsIgnoreCase(event.getProtocol())) {
            if (!event.isSyn() || event.isAck()) {
                return;
            }
        }

        // Clave única por par Atacante -> Víctima para evitar falsos positivos con tráfico web normal
        String flowKey = event.getSrcIp() + "->" + event.getDstIp();

        Set<Integer> ports = connections.get(flowKey, k -> ConcurrentHashMap.newKeySet());
        if (ports != null) {
            ports.add(event.getDstPort());

            if (ports.size() >= portThreshold) {
                event.setEventType(Event.EventType.PORT_SCAN);
                event.setNumberOfPorts(ports.size());
            }
        }
    }

    /**
     * Purga registros expirados delegando la limpieza ultra-eficiente a Caffeine.
     */
    @Override
    public void purgeExpired() {
        connections.cleanUp();
    }

    /**
     * Retorna las estadísticas de rendimiento y desalojos de la caché.
     */
    public CacheStats getStats() {
        return connections.stats();
    }

    /**
     * Retorna el número estimado de pares IP registrados actualmente en memoria.
     */
    public long estimatedSize() {
        return connections.estimatedSize();
    }
}
