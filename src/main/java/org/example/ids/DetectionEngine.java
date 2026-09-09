package org.example.ids;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Motor de detección de intrusiones.
 *
 * Coordina los detectores individuales (PortScan, SynFlood) y gestiona
 * la limpieza periódica de datos expirados en las ventanas de tiempo.
 * Cada evento pasa por todos los detectores; el primero que detecte
 * una anomalía clasifica el evento.
 */
public class DetectionEngine {

    private final PortScanDetector portScanDetector = new PortScanDetector();
    private final SynFloodDetector synFloodDetector = new SynFloodDetector();

    // Hilo daemon que purga datos expirados periódicamente
    private final ScheduledExecutorService cleaner =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "ids-cleaner");
                t.setDaemon(true);
                return t;
            });

    public DetectionEngine() {
        // Purgar ventanas expiradas cada 30 segundos
        cleaner.scheduleAtFixedRate(this::purgeAll, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * Analiza un evento pasándolo por todos los detectores.
     * El primer detector que encuentre una anomalía clasifica el evento.
     * Si ninguno detecta nada, el evento conserva su tipo NORMAL.
     */
    public void analyze(Event event) {
        // Port scan: ¿esta IP está tocando demasiados puertos?
        portScanDetector.analyze(event);
        if (event.event_type != Event.EventType.NORMAL) {
            return; // ya clasificado, no seguir analizando
        }

        // SYN flood: ¿esta IP destino recibe demasiados SYN?
        synFloodDetector.analyze(event);
    }

    /**
     * Purga datos expirados de todos los detectores.
     */
    private void purgeAll() {
        portScanDetector.purgeExpired();
        synFloodDetector.purgeExpired();
    }

    /**
     * Apaga el hilo de limpieza. Llamar al cerrar el IDS.
     */
    public void shutdown() {
        cleaner.shutdownNow();
    }
}
