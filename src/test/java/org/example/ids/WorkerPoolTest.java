package org.example.ids;

import org.example.ids.detectors.Detector;
import org.junit.jupiter.api.Test;

import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class WorkerPoolTest {

    @Test
    void eventsAreDispatchedToWorkersAsynchronously() throws InterruptedException {
        Properties props = new Properties();
        props.setProperty("ids.engine.worker.count", "4");
        props.setProperty("ids.engine.queue.capacity", "500");
        IdsConfig config = new IdsConfig(props);

        DetectionEngine engine = new DetectionEngine(config);

        int totalEvents = 100;
        CountDownLatch latch = new CountDownLatch(totalEvents);

        // Añadir detector de prueba con latch
        engine.addDetector(new Detector() {
            @Override
            public void analyze(Event event) {
                latch.countDown();
            }

            @Override
            public void purgeExpired() {}
        });

        for (int i = 0; i < totalEvents; i++) {
            Event event = new Event();
            event.setSrcIp("192.168.1." + i);
            event.setDstIp("10.0.0.1");
            event.setProtocol("TCP");
            boolean submitted = engine.submit(event);
            assertTrue(submitted);
        }

        // Esperar a que los workers procesen los eventos en paralelo
        boolean finished = latch.await(5, TimeUnit.SECONDS);
        assertTrue(finished, "Todos los eventos debieron ser procesados por los workers");
        assertEquals(totalEvents, engine.getProcessedCount());
        assertEquals(0, engine.getDroppedCount());

        engine.shutdown();
    }

    @Test
    void flowHashingRoutesSameIpToSameWorker() {
        Properties props = new Properties();
        props.setProperty("ids.engine.worker.count", "4");
        props.setProperty("ids.engine.queue.capacity", "500");
        IdsConfig config = new IdsConfig(props);

        DetectionEngine engine = new DetectionEngine(config);

        String ip = "192.168.1.150";
        int expectedWorker = Math.abs(ip.hashCode()) % 4;

        // Enviar 10 eventos de la misma IP
        for (int i = 0; i < 10; i++) {
            Event event = new Event();
            event.setSrcIp(ip);
            event.setDstIp("10.0.0.1");
            engine.submit(event);
        }

        // Verificar que los eventos están encolados / pasaron por el worker correspondiente
        assertTrue(engine.getWorkerCount() == 4);

        engine.shutdown();
    }

    @Test
    void queueBackpressureHandlesOverflowWithoutThrowing() {
        Properties props = new Properties();
        props.setProperty("ids.engine.worker.count", "1");
        props.setProperty("ids.engine.queue.capacity", "5"); // Cola muy pequeña
        IdsConfig config = new IdsConfig(props);

        DetectionEngine engine = new DetectionEngine(config);

        // Añadir detector lento para bloquear el worker
        CountDownLatch pauseWorkerLatch = new CountDownLatch(1);
        engine.addDetector(new Detector() {
            @Override
            public void analyze(Event event) {
                try {
                    pauseWorkerLatch.await(2, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {}
            }

            @Override
            public void purgeExpired() {}
        });

        // Llenar la cola rápidamente
        int submittedSuccessfully = 0;
        int dropped = 0;
        for (int i = 0; i < 20; i++) {
            Event event = new Event();
            event.setSrcIp("10.0.0.1"); // Misma IP -> mismo worker
            if (engine.submit(event)) {
                submittedSuccessfully++;
            } else {
                dropped++;
            }
        }

        assertTrue(dropped > 0, "Al saturarse la cola de 5 elementos, debieron descartarse eventos");
        assertTrue(engine.getDroppedCount() > 0, "El contador de eventos descartados debió incrementarse");

        pauseWorkerLatch.countDown();
        engine.shutdown();
    }

    @Test
    void gracefulShutdownStopsAllWorkers() {
        DetectionEngine engine = new DetectionEngine();
        assertEquals(Runtime.getRuntime().availableProcessors() > 0, engine.getWorkerCount() >= 2);

        assertDoesNotThrow(engine::shutdown);
    }
}
