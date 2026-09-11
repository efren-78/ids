package org.example.ids;

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Motor de detección de intrusiones.
 *
 * Coordina los detectores registrados y gestiona
 * la limpieza periódica de datos expirados en las ventanas de tiempo.
 * Cada evento pasa por todos los detectores; el primero que detecte
 * una anomalía clasifica el evento y se detiene la cadena.
 */
public class DetectionEngine {

    private final List<Detector> detectors = new ArrayList<>();

    // Hilo daemon que purga datos expirados periódicamente
    private final ScheduledExecutorService cleaner =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "ids-cleaner");
                t.setDaemon(true);
                return t;
            });

    public DetectionEngine() {
        // Registrar detectores por defecto
        detectors.add(new PortScanDetector());
        detectors.add(new SynFloodDetector());

        // Purgar ventanas expiradas cada 30 segundos
        cleaner.scheduleAtFixedRate(this::purgeAll, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * Registra un nuevo detector en el motor.
     * Los detectores se ejecutan en el orden en que se agregan.
     *
     * @param detector el detector a registrar
     */
    public void addDetector(Detector detector) {
        detectors.add(detector);
    }

    /**
     * Analiza un evento pasándolo por todos los detectores.
     * El primer detector que encuentre una anomalía clasifica el evento.
     * Si ninguno detecta nada, el evento conserva su tipo NORMAL.
     */
    public void analyze(Event event) {
        for (Detector detector : detectors) {
            detector.analyze(event);
            if (event.getEventType() != Event.EventType.NORMAL) {
                return; // ya clasificado, no seguir analizando
            }
        }
    }

    /**
     * Purga datos expirados de todos los detectores.
     */
    private void purgeAll() {
        detectors.forEach(Detector::purgeExpired);
    }

    /**
     * Apaga el hilo de limpieza. Llamar al cerrar el IDS.
     */
    public void shutdown() {
        cleaner.shutdownNow();
    }
}

