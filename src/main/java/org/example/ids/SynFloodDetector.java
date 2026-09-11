package org.example.ids;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Detecta ataques SYN flood.
 *
 * Algoritmo: cuenta paquetes TCP con flag SYN activo y ACK inactivo
 * dirigidos a una misma IP destino dentro de una ventana de tiempo.
 * Si se excede el umbral, el evento se clasifica como SYN_FLOOD.
 */
public class SynFloodDetector implements Detector {

    // --- Configuración ---
    private static final long WINDOW_MS = 5_000;    // ventana de 5 segundos
    private static final int SYN_THRESHOLD = 50;     // 50 SYNs para disparar alerta

    // --- Estado interno ---
    private final Map<String, SynRecord> synCounts = new ConcurrentHashMap<>();

    /**
     * Registro de SYNs recibidos por IP destino:
     * contador atómico y el inicio de la ventana.
     */
    private static class SynRecord {
        volatile long windowStart;
        final AtomicInteger count = new AtomicInteger(0);

        SynRecord(long now) {
            this.windowStart = now;
        }

        void reset(long now) {
            this.windowStart = now;
            this.count.set(0);
        }
    }

    /**
     * Analiza un evento y lo marca como SYN_FLOOD si la IP destino
     * ha recibido demasiados SYN sin ACK en la ventana actual.
     * Solo procesa paquetes TCP con SYN=true y ACK=false.
     */
    public void analyze(Event event) {
        // Solo nos interesan paquetes TCP SYN sin ACK (inicio de conexión)
        if (!"TCP".equals(event.getProtocol()) || !event.isSyn() || event.isAck()) {
            return;
        }

        long now = event.getTimestamp().toEpochMilli();

        SynRecord record = synCounts.computeIfAbsent(
                event.getDstIp(), k -> new SynRecord(now));

        // Si la ventana expiró, reiniciar el registro
        if (now - record.windowStart > WINDOW_MS) {
            record.reset(now);
        }

        int count = record.count.incrementAndGet();

        if (count >= SYN_THRESHOLD) {
            event.setEventType(Event.EventType.SYN_FLOOD);
        }
    }

    /**
     * Purga registros cuya ventana ya expiró para liberar memoria.
     */
    public void purgeExpired() {
        long now = System.currentTimeMillis();
        synCounts.entrySet().removeIf(
                entry -> now - entry.getValue().windowStart > WINDOW_MS * 2);
    }
}
