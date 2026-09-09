package org.example.ids;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detecta escaneo de puertos (port scanning).
 *
 * Algoritmo: rastrea cuántos puertos destino distintos contacta una misma
 * IP origen dentro de una ventana de tiempo. Si se excede el umbral,
 * el evento se clasifica como PORT_SCAN.
 */
public class PortScanDetector {

    // --- Configuración ---
    private static final long WINDOW_MS = 10_000;   // ventana de 10 segundos
    private static final int PORT_THRESHOLD = 15;    // 15 puertos distintos para disparar alerta

    // --- Estado interno ---
    private final Map<String, ConnectionRecord> connections = new ConcurrentHashMap<>();

    /**
     * Registro de conexiones por IP origen: puertos destino contactados
     * y el inicio de la ventana de tiempo actual.
     */
    private static class ConnectionRecord {
        volatile long windowStart;
        final Set<Integer> ports = ConcurrentHashMap.newKeySet();

        ConnectionRecord(long now) {
            this.windowStart = now;
        }

        void reset(long now) {
            this.windowStart = now;
            this.ports.clear();
        }
    }

    /**
     * Analiza un evento y lo marca como PORT_SCAN si la IP origen
     * ha contactado demasiados puertos distintos en la ventana actual.
     */
    public void analyze(Event event) {
        long now = event.timestamp.getTime();

        ConnectionRecord record = connections.computeIfAbsent(
                event.srcIp, k -> new ConnectionRecord(now));

        // Si la ventana expiró, reiniciar el registro
        if (now - record.windowStart > WINDOW_MS) {
            record.reset(now);
        }

        record.ports.add(event.dstPort);

        if (record.ports.size() >= PORT_THRESHOLD) {
            event.event_type = Event.EventType.PORT_SCAN;
            event.number_of_ports = record.ports.size();
        }
    }

    /**
     * Purga registros cuya ventana ya expiró para liberar memoria.
     */
    public void purgeExpired() {
        long now = System.currentTimeMillis();
        connections.entrySet().removeIf(
                entry -> now - entry.getValue().windowStart > WINDOW_MS * 2);
    }
}
