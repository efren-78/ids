package org.example.ids;

import org.example.ids.detectors.BruteForceDetector;
import org.example.ids.detectors.Detector;
import org.example.ids.detectors.PortScanDetector;
import org.example.ids.detectors.SuspiciousPortDetector;
import org.example.ids.detectors.SynFloodDetector;
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
        BruteForceDetector bruteForceDetector = new BruteForceDetector();
        org.example.ids.detectors.SuspiciousPortDetector suspiciousPortDetector = new org.example.ids.detectors.SuspiciousPortDetector();

        Event nullEvent = null;
        assertDoesNotThrow(() -> portScanDetector.analyze(nullEvent));
        assertDoesNotThrow(() -> synFloodDetector.analyze(nullEvent));
        assertDoesNotThrow(() -> bruteForceDetector.analyze(nullEvent));
        assertDoesNotThrow(() -> suspiciousPortDetector.analyze(nullEvent));

        Event emptyEvent = new Event();
        emptyEvent.setSrcIp(null);
        emptyEvent.setDstIp(null);
        emptyEvent.setProtocol(null);

        assertDoesNotThrow(() -> portScanDetector.analyze(emptyEvent));
        assertDoesNotThrow(() -> synFloodDetector.analyze(emptyEvent));
        assertDoesNotThrow(() -> bruteForceDetector.analyze(emptyEvent));
        assertDoesNotThrow(() -> suspiciousPortDetector.analyze(emptyEvent));

        assertDoesNotThrow(portScanDetector::purgeExpired);
        assertDoesNotThrow(synFloodDetector::purgeExpired);
        assertDoesNotThrow(bruteForceDetector::purgeExpired);
        assertDoesNotThrow(suspiciousPortDetector::purgeExpired);
    }

    @Test
    void caffeineCacheRespectsMaxCapacityAndEvictsExcessEntries() {
        // Creamos detectores con capacidad acotada a solo 10 entradas para el test
        int maxCapacity = 10;
        PortScanDetector portScanDetector = new PortScanDetector(maxCapacity, 10_000, 15);
        SynFloodDetector synFloodDetector = new SynFloodDetector(maxCapacity, 5_000, 50);

        // Enviamos 100 IPs distintas simulando un ataque de IP Spoofing masivo
        for (int i = 1; i <= 100; i++) {
            Event eventPortScan = new Event();
            eventPortScan.setSrcIp("10.0.0." + i);
            eventPortScan.setDstIp("192.168.1.1");
            eventPortScan.setProtocol("TCP");
            eventPortScan.setSyn(true);
            eventPortScan.setAck(false);
            eventPortScan.setDstPort(80);
            portScanDetector.analyze(eventPortScan);

            Event eventSyn = new Event();
            eventSyn.setDstIp("192.168.1." + i);
            eventSyn.setProtocol("TCP");
            eventSyn.setSyn(true);
            eventSyn.setAck(false);
            synFloodDetector.analyze(eventSyn);
        }

        // Forzar ciclo de limpieza de Caffeine
        portScanDetector.purgeExpired();
        synFloodDetector.purgeExpired();

        // La cantidad en memoria no debe desbordarse infinitamente (debe mantenerse cerca de maxCapacity)
        assertTrue(portScanDetector.estimatedSize() <= maxCapacity,
                "PortScanDetector no debe exceder la capacidad máxima de memoria");
        assertTrue(synFloodDetector.estimatedSize() <= maxCapacity,
                "SynFloodDetector no debe exceder la capacidad máxima de memoria");

        // Verificar que las estadísticas registraron desalojos
        assertTrue(portScanDetector.getStats().evictionCount() > 0,
                "PortScanDetector debió desalojar entradas excedentes");
        assertTrue(synFloodDetector.getStats().evictionCount() > 0,
                "SynFloodDetector debió desalojar entradas excedentes");
    }
}

