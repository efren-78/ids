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
 * Detecta ataques de fuerza bruta (Brute Force).
 *
 * Algoritmo: Rastrea intentos repetitivos de conexión TCP (SYN activo, ACK inactivo)
 * desde una misma IP origen hacia un servicio o puerto sensible específico (SSH, FTP, RDP, MySQL, etc.)
 * en la misma IP destino dentro de una ventana de tiempo.
 * Si se supera el umbral de intentos hacia ese servicio, se clasifica como BRUTE_FORCE.
 */
public class BruteForceDetector implements Detector {

    private static final long DEFAULT_WINDOW_MS = 10_000;
    private static final int DEFAULT_THRESHOLD = 20;
    private static final long DEFAULT_MAX_CAPACITY = 50_000;
    private static final Set<Integer> DEFAULT_TARGET_PORTS = Set.of(21, 22, 23, 3389, 3306, 5432);

    private final int threshold;
    private final Set<Integer> targetPorts;
    private final Cache<String, AtomicInteger> connectionAttempts;

    public BruteForceDetector() {
        this(IdsConfig.getInstance());
    }

    public BruteForceDetector(IdsConfig config) {
        this(
            config != null ? config.getBruteForceMaxCapacity() : DEFAULT_MAX_CAPACITY,
            config != null ? config.getBruteForceWindowMs() : DEFAULT_WINDOW_MS,
            config != null ? config.getBruteForceThreshold() : DEFAULT_THRESHOLD,
            config != null ? config.getBruteForceTargetPorts() : DEFAULT_TARGET_PORTS
        );
    }

    public BruteForceDetector(long maxCapacity, long windowMs, int threshold, Set<Integer> targetPorts) {
        this.threshold = threshold;
        this.targetPorts = (targetPorts != null && !targetPorts.isEmpty()) ? targetPorts : DEFAULT_TARGET_PORTS;
        this.connectionAttempts = Caffeine.newBuilder()
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

        // Solo nos interesan intentos de inicio de conexión TCP (SYN activo y ACK inactivo)
        if (!"TCP".equalsIgnoreCase(event.getProtocol()) || !event.isSyn() || event.isAck()) {
            return;
        }

        // Verificar si el puerto destino es uno de los servicios monitoreados para fuerza bruta
        if (!targetPorts.contains(event.getDstPort())) {
            return;
        }

        // Clave única por flujo atacante -> servicio específico objetivo
        String flowKey = event.getSrcIp() + "->" + event.getDstIp() + ":" + event.getDstPort();

        AtomicInteger counter = connectionAttempts.get(flowKey, k -> new AtomicInteger(0));
        if (counter != null) {
            int attempts = counter.incrementAndGet();

            if (attempts >= threshold) {
                event.setEventType(Event.EventType.BRUTE_FORCE);
            }
        }
    }

    @Override
    public void purgeExpired() {
        connectionAttempts.cleanUp();
    }

    public CacheStats getStats() {
        return connectionAttempts.stats();
    }

    public long estimatedSize() {
        return connectionAttempts.estimatedSize();
    }

    public Set<Integer> getTargetPorts() {
        return targetPorts;
    }
}
