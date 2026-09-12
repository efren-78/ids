package org.example.ids;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class ResilienceTest {

    private DetectionEngine engine;

    @BeforeEach
    void setUp() {
        engine = new DetectionEngine();
    }

    @AfterEach
    void tearDown() {
        engine.shutdown();
    }

    @Test
    void faultyDetectorDoesNotPreventSubsequentDetectorsFromRunning() {
        // Detector defectuoso que lanza RuntimeException
        Detector brokenDetector = new Detector() {
            @Override
            public void analyze(Event event) {
                throw new RuntimeException("Simulated detector crash");
            }

            @Override
            public void purgeExpired() {
                throw new RuntimeException("Simulated purge crash");
            }
        };

        // Detector posterior que verifica que el flujo continuó
        AtomicBoolean secondDetectorRan = new AtomicBoolean(false);
        Detector healthyDetector = new Detector() {
            @Override
            public void analyze(Event event) {
                secondDetectorRan.set(true);
            }

            @Override
            public void purgeExpired() {
            }
        };

        engine.addDetector(brokenDetector);
        engine.addDetector(healthyDetector);

        Event event = new Event();
        event.setSrcIp("192.168.1.100");
        event.setDstIp("192.168.1.1");
        event.setProtocol("TCP");

        // No debe lanzar excepción
        assertDoesNotThrow(() -> engine.analyze(event));
        assertTrue(secondDetectorRan.get(), "El detector saludable debió ejecutarse a pesar del fallo del detector anterior");
    }

    @Test
    void faultyDetectorInPurgeDoesNotCrashSafePurgeAll() {
        Detector brokenDetector = new Detector() {
            @Override
            public void analyze(Event event) {}

            @Override
            public void purgeExpired() {
                throw new RuntimeException("Simulated purge crash");
            }
        };

        AtomicBoolean healthyPurged = new AtomicBoolean(false);
        Detector healthyDetector = new Detector() {
            @Override
            public void analyze(Event event) {}

            @Override
            public void purgeExpired() {
                healthyPurged.set(true);
            }
        };

        engine.addDetector(brokenDetector);
        engine.addDetector(healthyDetector);

        assertDoesNotThrow(() -> engine.safePurgeAll());
        assertTrue(healthyPurged.get(), "El detector saludable debió purgarse a pesar del fallo del detector anterior");
    }

    @Test
    void analyzeNullEventDoesNotThrow() {
        assertDoesNotThrow(() -> engine.analyze(null));
    }

    @Test
    void mainIdsDataProcessHandlesNullPacketGracefully() {
        MainIDS mainIDS = new MainIDS();
        Event result = mainIDS.dataProcess(null, Instant.now());
        assertNull(result, "Un paquete nulo debe retornar null sin lanzar excepciones");
    }

    @Test
    void detectorsHandleNullAndEmptyFieldsGracefully() {
        PortScanDetector portScanDetector = new PortScanDetector();
        SynFloodDetector synFloodDetector = new SynFloodDetector();

        Event nullEvent = null;
        assertDoesNotThrow(() -> portScanDetector.analyze(nullEvent));
        assertDoesNotThrow(() -> synFloodDetector.analyze(nullEvent));

        Event emptyEvent = new Event();
        emptyEvent.setSrcIp(null);
        emptyEvent.setDstIp(null);
        emptyEvent.setProtocol(null);

        assertDoesNotThrow(() -> portScanDetector.analyze(emptyEvent));
        assertDoesNotThrow(() -> synFloodDetector.analyze(emptyEvent));

        assertDoesNotThrow(portScanDetector::purgeExpired);
        assertDoesNotThrow(synFloodDetector::purgeExpired);
    }
}
