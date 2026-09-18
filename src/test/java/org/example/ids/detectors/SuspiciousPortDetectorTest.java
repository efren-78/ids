package org.example.ids.detectors;

import org.example.ids.Event;
import org.example.ids.IdsConfig;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SuspiciousPortDetectorTest {

    private Event crearEvento(String srcIp, String dstIp, int srcPort, int dstPort, String protocol) {
        Event event = new Event();
        event.setTimestamp(Instant.now());
        event.setSrcIp(srcIp);
        event.setDstIp(dstIp);
        event.setSrcPort(srcPort);
        event.setDstPort(dstPort);
        event.setProtocol(protocol);
        event.setSyn(true);
        event.setAck(false);
        return event;
    }

    @Test
    void detectaConexionAPuertoMetasploit4444Inmediatamente() {
        SuspiciousPortDetector detector = new SuspiciousPortDetector();
        Event event = crearEvento("192.168.1.100", "198.51.100.23", 50123, 4444, "TCP");

        detector.analyze(event);

        assertEquals(Event.EventType.SUSPICIOUS_CONNECTION, event.getEventType());
    }

    @Test
    void detectaConexionAPuertoBackdoor1337() {
        SuspiciousPortDetector detector = new SuspiciousPortDetector();
        Event event = crearEvento("10.0.0.5", "10.0.0.1", 45000, 1337, "TCP");

        detector.analyze(event);

        assertEquals(Event.EventType.SUSPICIOUS_CONNECTION, event.getEventType());
    }

    @Test
    void detectaTraficoUdpHaciaPuertoSospechoso() {
        SuspiciousPortDetector detector = new SuspiciousPortDetector();
        Event event = crearEvento("10.0.0.50", "10.0.0.1", 33000, 31337, "UDP");

        detector.analyze(event);

        assertEquals(Event.EventType.SUSPICIOUS_CONNECTION, event.getEventType());
    }

    @Test
    void detectaTraficoHaciaPuertoTorC2() {
        SuspiciousPortDetector detector = new SuspiciousPortDetector();
        // Conexión hacia un nodo/C2 Tor conocido (puerto destino 9001)
        Event event = crearEvento("192.168.1.20", "203.0.113.5", 49500, 9001, "TCP");

        detector.analyze(event);

        assertEquals(Event.EventType.SUSPICIOUS_CONNECTION, event.getEventType());
    }

    @Test
    void ignoraPuertosLegitimosNormales() {
        SuspiciousPortDetector detector = new SuspiciousPortDetector();
        Event eventHttp = crearEvento("192.168.1.50", "93.184.216.34", 51000, 80, "TCP");
        Event eventHttps = crearEvento("192.168.1.50", "93.184.216.34", 51001, 443, "TCP");
        Event eventDns = crearEvento("192.168.1.50", "8.8.8.8", 51002, 53, "UDP");

        detector.analyze(eventHttp);
        detector.analyze(eventHttps);
        detector.analyze(eventDns);

        assertEquals(Event.EventType.NORMAL, eventHttp.getEventType());
        assertEquals(Event.EventType.NORMAL, eventHttps.getEventType());
        assertEquals(Event.EventType.NORMAL, eventDns.getEventType());
    }

    @Test
    void respetaConfiguracionDeUmbralMayorAUno() {
        Properties props = new Properties();
        props.setProperty("ids.detector.suspiciousport.threshold", "3");
        props.setProperty("ids.detector.suspiciousport.ports", "4444");

        IdsConfig config = new IdsConfig(props);
        SuspiciousPortDetector detector = new SuspiciousPortDetector(config);

        Event e1 = crearEvento("10.0.0.1", "10.0.0.2", 40000, 4444, "TCP");
        Event e2 = crearEvento("10.0.0.1", "10.0.0.2", 40001, 4444, "TCP");
        Event e3 = crearEvento("10.0.0.1", "10.0.0.2", 40002, 4444, "TCP");

        detector.analyze(e1);
        assertEquals(Event.EventType.NORMAL, e1.getEventType());

        detector.analyze(e2);
        assertEquals(Event.EventType.NORMAL, e2.getEventType());

        detector.analyze(e3);
        assertEquals(Event.EventType.SUSPICIOUS_CONNECTION, e3.getEventType());
    }

    @Test
    void manejaEventosNulosYSinIpSinExcepciones() {
        SuspiciousPortDetector detector = new SuspiciousPortDetector();

        assertDoesNotThrow(() -> detector.analyze(null));

        Event empty = new Event();
        assertDoesNotThrow(() -> detector.analyze(empty));
        assertEquals(Event.EventType.NORMAL, empty.getEventType());

        assertDoesNotThrow(detector::purgeExpired);
    }
}
