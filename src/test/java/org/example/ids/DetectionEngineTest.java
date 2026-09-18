package org.example.ids;

import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DetectionEngineTest {

    private DetectionEngine engine;

    @BeforeEach
    void setUp() {
        engine = new DetectionEngine();
    }

    @AfterEach
    void tearDown() {
        engine.shutdown();
    }

    // Test donde no clasifica un evento normal
    @Test
    void eventoNormalPasaSinClasificar() {
        Event event = new Event();
        event.setTimestamp(Instant.now());
        event.setSrcIp("192.168.1.10");
        event.setDstIp("192.168.1.20");
        event.setSrcPort(12345);
        event.setDstPort(80);
        event.setProtocol("TCP");
        event.setSyn(false);
        event.setAck(true);

        engine.analyze(event);

        assertEquals(Event.EventType.NORMAL, event.getEventType());
    }

    // Test donde detecta un escaneo de puertos sospechoso
    @Test
    void detectaPortScanCorrectamente() {
        Event ultimoEvento = null;
        for (int i = 1; i <= 15; i++) {
            ultimoEvento = new Event();
            ultimoEvento.setTimestamp(Instant.now());
            ultimoEvento.setSrcIp("10.0.0.9");
            ultimoEvento.setDstIp("192.168.1.1");
            ultimoEvento.setSrcPort(20000);
            ultimoEvento.setDstPort(i);
            ultimoEvento.setProtocol("TCP");

            engine.analyze(ultimoEvento);
        }

        assertEquals(Event.EventType.PORT_SCAN, ultimoEvento.getEventType());
    }

    // Test donde detecta un SYN flood sospechoso
    @Test
    void detectaSynFloodCorrectamente() {
        Event ultimoEvento = null;
        for (int i = 1; i <= 50; i++) {
            ultimoEvento = new Event();
            ultimoEvento.setTimestamp(Instant.now());
            ultimoEvento.setSrcIp("10.0.0.8");
            ultimoEvento.setDstIp("192.168.1.200");
            ultimoEvento.setSrcPort(30000);
            ultimoEvento.setDstPort(443);
            ultimoEvento.setProtocol("TCP");
            ultimoEvento.setSyn(true);
            ultimoEvento.setAck(false);

            engine.analyze(ultimoEvento);
        }

        assertEquals(Event.EventType.SYN_FLOOD, ultimoEvento.getEventType());
    }

    // Test donde detecta un ataque de fuerza bruta sospechoso
    @Test
    void detectaBruteForceCorrectamente() {
        Event ultimoEvento = null;
        for (int i = 1; i <= 20; i++) {
            ultimoEvento = new Event();
            ultimoEvento.setTimestamp(Instant.now());
            ultimoEvento.setSrcIp("10.0.0.7");
            ultimoEvento.setDstIp("192.168.1.50");
            ultimoEvento.setSrcPort(40000);
            ultimoEvento.setDstPort(22); // SSH
            ultimoEvento.setProtocol("TCP");
            ultimoEvento.setSyn(true);
            ultimoEvento.setAck(false);

            engine.analyze(ultimoEvento);
        }

        assertEquals(Event.EventType.BRUTE_FORCE, ultimoEvento.getEventType());
    }

    // Test donde detecta conexión a puerto sospechoso (Metasploit / C2)
    @Test
    void detectaSuspiciousPortCorrectamente() {
        Event event = new Event();
        event.setTimestamp(Instant.now());
        event.setSrcIp("10.0.0.6");
        event.setDstIp("192.168.1.50");
        event.setSrcPort(45000);
        event.setDstPort(4444); // Metasploit
        event.setProtocol("TCP");
        event.setSyn(true);
        event.setAck(false);

        engine.analyze(event);

        assertEquals(Event.EventType.SUSPICIOUS_CONNECTION, event.getEventType());
    }
}

