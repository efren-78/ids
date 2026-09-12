package org.example.ids;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Detecta ataques SYN flood.
 *
 * Utiliza Caffeine Cache con algoritmo W-TinyLFU para limitar el uso de memoria
 * y descartar automáticamente contadores de SYN expirados tras la ventana de tiempo.
 */
public class SynFloodDetector implements Detector {

    private static final long DEFAULT_WINDOW_MS = 5_000;
    private static final int DEFAULT_SYN_THRESHOLD = 50;
    private static final long DEFAULT_MAX_CAPACITY = 50_000;

    private final int synThreshold;
    private final Cache<String, AtomicInteger> synCounts;

    public SynFloodDetector() {
        this(DEFAULT_MAX_CAPACITY, DEFAULT_WINDOW_MS, DEFAULT_SYN_THRESHOLD);
    }

    public SynFloodDetector(long maxCapacity, long windowMs, int synThreshold) {
        this.synThreshold = synThreshold;
        this.synCounts = Caffeine.newBuilder()
                .maximumSize(maxCapacity)
                .expireAfterWrite(windowMs, TimeUnit.MILLISECONDS)
                .recordStats()
                .build();
    }

    /**
     * Analiza un evento y lo marca como SYN_FLOOD si la IP destino
     * ha recibido demasiados SYN sin ACK en la ventana actual.
     * Solo procesa paquetes TCP con SYN=true y ACK=false.
     */
    @Override
    public void analyze(Event event) {
        if (event == null || event.getDstIp() == null || event.getDstIp().isBlank()) {
            return;
        }

        // Solo nos interesan paquetes TCP SYN sin ACK (inicio de conexión)
        if (!"TCP".equalsIgnoreCase(event.getProtocol()) || !event.isSyn() || event.isAck()) {
            return;
        }

        AtomicInteger counter = synCounts.get(event.getDstIp(), k -> new AtomicInteger(0));
        if (counter != null) {
            int count = counter.incrementAndGet();

            if (count >= synThreshold) {
                event.setEventType(Event.EventType.SYN_FLOOD);
            }
        }
    }

    /**
     * Purga registros expirados delegando la limpieza ultra-eficiente a Caffeine.
     */
    @Override
    public void purgeExpired() {
        synCounts.cleanUp();
    }

    /**
     * Retorna las estadísticas de rendimiento y desalojos de la caché.
     */
    public CacheStats getStats() {
        return synCounts.stats();
    }

    /**
     * Retorna el número estimado de IPs registradas actualmente en memoria.
     */
    public long estimatedSize() {
        return synCounts.estimatedSize();
    }
}


