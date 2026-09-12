package org.example.ids;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private static final Logger logger = LoggerFactory.getLogger(DetectionEngine.class);

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

        // Purgar ventanas expiradas cada 30 segundos con manejo seguro
        cleaner.scheduleAtFixedRate(this::safePurgeAll, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * Registra un nuevo detector en el motor.
     * Los detectores se ejecutan en el orden en que se agregan.
     *
     * @param detector el detector a registrar
     */
    public void addDetector(Detector detector) {
        if (detector != null) {
            detectors.add(detector);
        }
    }

    /**
     * Analiza un evento pasándolo por todos los detectores.
     * Implementa aislamiento de fallos (Fault Isolation): si un detector falla,
     * se registra el error y se continúa con los siguientes detectores.
     * El primer detector que encuentre una anomalía clasifica el evento.
     * Si ninguno detecta nada, el evento conserva su tipo NORMAL.
     */
    public void analyze(Event event) {
        if (event == null) {
            return;
        }

        for (Detector detector : detectors) {
            try {
                detector.analyze(event);
                if (event.getEventType() != Event.EventType.NORMAL) {
                    return; // ya clasificado, no seguir analizando
                }
            } catch (Exception e) {
                logger.error("Fallo no controlado en detector {}: {}",
                        detector.getClass().getSimpleName(), e.getMessage(), e);
            }
        }
    }

    /**
     * Purga datos expirados de todos los detectores de forma segura.
     * Evita que una excepción no capturada cancele silenciosamente el ScheduledExecutorService.
     */
    public void safePurgeAll() {
        try {
            for (Detector detector : detectors) {
                try {
                    detector.purgeExpired();
                } catch (Exception e) {
                    logger.error("Error al purgar estado en detector {}: {}",
                            detector.getClass().getSimpleName(), e.getMessage(), e);
                }
            }
        } catch (Throwable t) {
            logger.error("Error crítico inesperado en el ciclo periódico de purga", t);
        }
    }

    /**
     * Apaga el hilo de limpieza. Llamar al cerrar el IDS.
     */
    public void shutdown() {
        cleaner.shutdownNow();
    }
}


