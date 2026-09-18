package org.example.ids.detectors;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import org.example.ids.Event;
import org.example.ids.IdsConfig;

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Detecta conexiones anómalas o tráfico hacia puertos comúnmente utilizados por
 * malware, troyanos, backdoors y canales de comando y control (C2).
 *
 * Puertos monitoreados por defecto:
 * - 4444: Metasploit / Meterpreter default reverse shell
 * - 1337: Backdoors y reverse shells comunes
 * - 31337: Back Orifice
 * - 6667: Canales IRC clásicos para Botnets C2
 * - 5555: Explotación Android ADB / botnets IoT
 * - 8088 / 9001: Proxies y C2 sobre Tor
 * - 27374: SubSeven
 */
public class SuspiciousPortDetector implements Detector {

    private static final long DEFAULT_WINDOW_MS = 10_000;
    private static final int DEFAULT_THRESHOLD = 1;
    private static final long DEFAULT_MAX_CAPACITY = 50_000;
    private static final Set<Integer> DEFAULT_SUSPICIOUS_PORTS = Set.of(
            4444, 1337, 31337, 6667, 5555, 8088, 9001, 27374
    );

    private final int threshold;
    private final Set<Integer> suspiciousPorts;
    private final Cache<String, AtomicInteger> connectionCache;

    public SuspiciousPortDetector() {
        this(IdsConfig.getInstance());
    }

    public SuspiciousPortDetector(IdsConfig config) {
        this(
            config != null ? config.getSuspiciousPortMaxCapacity() : DEFAULT_MAX_CAPACITY,
            config != null ? config.getSuspiciousPortWindowMs() : DEFAULT_WINDOW_MS,
            config != null ? config.getSuspiciousPortThreshold() : DEFAULT_THRESHOLD,
            config != null ? config.getSuspiciousPorts() : DEFAULT_SUSPICIOUS_PORTS
        );
    }

    public SuspiciousPortDetector(long maxCapacity, long windowMs, int threshold, Set<Integer> suspiciousPorts) {
        this.threshold = Math.max(1, threshold);
        this.suspiciousPorts = (suspiciousPorts != null && !suspiciousPorts.isEmpty())
                ? suspiciousPorts
                : DEFAULT_SUSPICIOUS_PORTS;
        this.connectionCache = Caffeine.newBuilder()
                .maximumSize(maxCapacity)
                .expireAfterWrite(windowMs, TimeUnit.MILLISECONDS)
                .recordStats()
                .build();
    }

    @Override
    public void analyze(Event event) {
        if (event == null || event.getSrcIp() == null || event.getDstIp() == null) {
            return;
        }

        int dstPort = event.getDstPort();

        // Verificar si el puerto destino (servicio objetivo/C2) está en la lista negra
        if (!suspiciousPorts.contains(dstPort)) {
            return;
        }

        String flowKey = event.getSrcIp() + "->" + event.getDstIp() + ":" + dstPort;

        AtomicInteger counter = connectionCache.get(flowKey, k -> new AtomicInteger(0));
        if (counter != null) {
            int attempts = counter.incrementAndGet();

            if (attempts >= threshold) {
                event.setEventType(Event.EventType.SUSPICIOUS_CONNECTION);
            }
        }
    }

    @Override
    public void purgeExpired() {
        connectionCache.cleanUp();
    }

    public CacheStats getStats() {
        return connectionCache.stats();
    }

    public long estimatedSize() {
        return connectionCache.estimatedSize();
    }

    public Set<Integer> getSuspiciousPorts() {
        return suspiciousPorts;
    }
}
