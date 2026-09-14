package org.example.ids;

import org.example.ids.detectors.BruteForceDetector;
import org.example.ids.detectors.Detector;
import org.example.ids.detectors.PortScanDetector;
import org.example.ids.detectors.SynFloodDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Motor de detección de intrusiones con arquitectura Publisher-Worker desacoplada.
 *
 * Distribuye el tráfico entrante hacia colas independientes (ArrayBlockingQueue)
 * particionadas mediante Flow Hashing (hash de IP) para evitar condiciones de carrera
 * entre hilos de trabajo y amortiguar ráfagas masivas de red.
 */
public class DetectionEngine {

    private static final Logger logger = LoggerFactory.getLogger(DetectionEngine.class);

    private final List<Detector> detectors = new ArrayList<>();
    private final Worker[] workers;
    private final int queueCapacity;

    private final AtomicLong processedEventsCounter = new AtomicLong(0);
    private final AtomicLong droppedEventsCounter = new AtomicLong(0);

    // Hilo daemon que purga datos expirados periódicamente
    private final ScheduledExecutorService cleaner =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "ids-cleaner");
                t.setDaemon(true);
                return t;
            });

    public DetectionEngine() {
        this(IdsConfig.getInstance());
    }

    public DetectionEngine(IdsConfig config) {
        IdsConfig cfg = (config != null) ? config : IdsConfig.getInstance();

        // Registrar detectores modulares por defecto con configuración externa
        detectors.add(new PortScanDetector(cfg));
        detectors.add(new SynFloodDetector(cfg));
        detectors.add(new BruteForceDetector(cfg));

        int workerCount = cfg.getEngineWorkerCount();
        this.queueCapacity = cfg.getEngineQueueCapacity();
        this.workers = new Worker[workerCount];

        logger.info("Inicializando DetectionEngine con {} workers (cola por worker: {})", workerCount, queueCapacity);

        for (int i = 0; i < workerCount; i++) {
            workers[i] = new Worker(i, queueCapacity);
            workers[i].start();
        }

        // Purgar ventanas expiradas según el intervalo configurado con manejo seguro
        int purgeSeconds = cfg.getEnginePurgeIntervalSeconds();
        cleaner.scheduleAtFixedRate(this::safePurgeAll, purgeSeconds, purgeSeconds, TimeUnit.SECONDS);
    }

    /**
     * Encola un evento de forma no bloqueante hacia el worker correspondiente
     * según el hash de la IP (Flow Hashing).
     *
     * @param event el evento de red capturado
     * @return true si fue encolado exitosamente, false si la cola del worker estaba llena (descarte).
     */
    public boolean submit(Event event) {
        if (event == null) {
            return false;
        }

        String partitionKey = getPartitionKey(event);
        int workerIndex = Math.abs(partitionKey.hashCode()) % workers.length;

        boolean enqueued = workers[workerIndex].offer(event);
        if (!enqueued) {
            droppedEventsCounter.incrementAndGet();
            logger.warn("Cola de worker {} saturada. Descartando evento de IP: {}", workerIndex, partitionKey);
            return false;
        }
        return true;
    }

    private String getPartitionKey(Event event) {
        if (event.getSrcIp() != null && !event.getSrcIp().isBlank()) {
            return event.getSrcIp();
        }
        if (event.getDstIp() != null && !event.getDstIp().isBlank()) {
            return event.getDstIp();
        }
        return "default";
    }

    /**
     * Registra un nuevo detector en el motor.
     *
     * @param detector el detector a registrar
     */
    public void addDetector(Detector detector) {
        if (detector != null) {
            detectors.add(detector);
        }
    }

    /**
     * Analiza un evento de forma síncrona pasándolo por todos los detectores.
     * Implementa aislamiento de fallos (Fault Isolation): si un detector falla,
     * se registra el error y se continúa con los siguientes detectores.
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

    // --- Métricas y Observabilidad ---
    public long getProcessedCount() {
        return processedEventsCounter.get();
    }

    public long getDroppedCount() {
        return droppedEventsCounter.get();
    }

    public int getWorkerCount() {
        return workers.length;
    }

    public int getQueueCapacity() {
        return queueCapacity;
    }

    public int getQueueSize(int workerIndex) {
        if (workerIndex >= 0 && workerIndex < workers.length) {
            return workers[workerIndex].getQueueSize();
        }
        return 0;
    }

    public int getTotalPendingEvents() {
        int total = 0;
        for (Worker worker : workers) {
            total += worker.getQueueSize();
        }
        return total;
    }

    /**
     * Apaga los workers y el hilo de limpieza de forma limpia.
     */
    public void shutdown() {
        for (Worker worker : workers) {
            if (worker != null) {
                worker.stop();
            }
        }
        cleaner.shutdownNow();
    }

    /**
     * Hilo de trabajo que procesa su propia cola acotada de eventos.
     */
    private final class Worker implements Runnable {
        private final int id;
        private final ArrayBlockingQueue<Event> queue;
        private final Thread thread;
        private volatile boolean running = true;

        Worker(int id, int capacity) {
            this.id = id;
            this.queue = new ArrayBlockingQueue<>(capacity);
            this.thread = new Thread(this, "ids-worker-" + id);
            this.thread.setDaemon(true);
        }

        void start() {
            this.thread.start();
        }

        boolean offer(Event event) {
            return queue.offer(event);
        }

        int getQueueSize() {
            return queue.size();
        }

        void stop() {
            this.running = false;
            this.thread.interrupt();
        }

        @Override
        public void run() {
            while (running) {
                try {
                    Event event = queue.poll(500, TimeUnit.MILLISECONDS);
                    if (event != null) {
                        analyze(event);
                        processedEventsCounter.incrementAndGet();

                        if (event.getEventType() != Event.EventType.NORMAL) {
                            logger.warn("ALERTA: {}", event);
                        } else if (logger.isDebugEnabled()) {
                            logger.debug("Evento: {}", event);
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Throwable t) {
                    logger.error("Error no controlado en worker {}: {}", id, t.getMessage(), t);
                }
            }
        }
    }
}



