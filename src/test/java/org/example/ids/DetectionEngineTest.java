package org.example.ids;

import java.sql.Timestamp;

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

    //Test donde no clasifica un evento normal
    @Test
    void eventoNormalPasaSinClasificar() {
        Event event = new Event();
        event.timestamp = new Timestamp(System.currentTimeMillis());
        event.srcIp = "192.168.1.10";
        event.dstIp = "192.168.1.20";
        event.srcPort = 12345;
        event.dstPort = 80;
        event.protocol = "TCP";
        event.syn = false;
        event.ack = true;

        engine.analyze(event);

        assertEquals(Event.EventType.NORMAL, event.event_type);
    }

    //Test donde detecta un escaneo de puertos sospechoso
    @Test
    void detectaPortScanCorrectamente() {
        Event ultimoEvento = null;
        for (int i = 1; i <= 15; i++) {
            ultimoEvento = new Event();
            ultimoEvento.timestamp = new Timestamp(System.currentTimeMillis());
            ultimoEvento.srcIp = "10.0.0.9";
            ultimoEvento.dstIp = "192.168.1.1";
            ultimoEvento.srcPort = 20000;
            ultimoEvento.dstPort = i;
            ultimoEvento.protocol = "TCP";

            engine.analyze(ultimoEvento);
        }

        assertEquals(Event.EventType.PORT_SCAN, ultimoEvento.event_type);
    }

    //Test donde detecta un SYN flood sospechoso
    @Test
    void detectaSynFloodCorrectamente() {
        Event ultimoEvento = null;
        for (int i = 1; i <= 50; i++) {
            ultimoEvento = new Event();
            ultimoEvento.timestamp = new Timestamp(System.currentTimeMillis());
            ultimoEvento.srcIp = "10.0.0.8";
            ultimoEvento.dstIp = "192.168.1.200";
            ultimoEvento.srcPort = 30000;
            ultimoEvento.dstPort = 443;
            ultimoEvento.protocol = "TCP";
            ultimoEvento.syn = true;
            ultimoEvento.ack = false;

            engine.analyze(ultimoEvento);
        }

        assertEquals(Event.EventType.SYN_FLOOD, ultimoEvento.event_type);
    }
}
