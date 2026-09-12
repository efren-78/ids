package org.example.ids;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Detecta escaneo de puertos (port scanning).
 *
 * Utiliza Caffeine Cache con algoritmo W-TinyLFU para limitar el uso de memoria
 * y descartar automáticamente registros de conexiones expiradas.
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
     * Analiza un evento y lo marca como PORT_SCAN si la IP origen
     * ha contactado demasiados puertos distintos en la ventana actual.
     */
    @Override
    public void analyze(Event event) {
        if (event == null || event.getSrcIp() == null || event.getSrcIp().isBlank()) {
            return;
        }

        Set<Integer> ports = connections.get(event.getSrcIp(), k -> ConcurrentHashMap.newKeySet());
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
     * Retorna el número estimado de IPs registradas actualmente en memoria.
     */
    public long estimatedSize() {
        return connections.estimatedSize();
    }
}


