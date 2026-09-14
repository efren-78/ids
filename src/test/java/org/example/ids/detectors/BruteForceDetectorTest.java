package org.example.ids.detectors;

import org.example.ids.Event;
import org.example.ids.IdsConfig;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class BruteForceDetectorTest {

    private Event crearIntentoTcp(String srcIp, String dstIp, int dstPort, boolean syn, boolean ack) {
        Event event = new Event();
        event.setTimestamp(Instant.now());
        event.setSrcIp(srcIp);
        event.setDstIp(dstIp);
        event.setSrcPort(45000);
        event.setDstPort(dstPort);
        event.setProtocol("TCP");
        event.setSyn(syn);
        event.setAck(ack);
        return event;
    }

    @Test
    void detectaFuerzaBrutaAlExcederUmbralEnPuertoSensible() {
        // ARRANGE: umbral por defecto = 20 intentos
        BruteForceDetector detector = new BruteForceDetector();
        String atacante = "10.0.0.99";
        String servidor = "192.168.1.10";
        int puertoSsh = 22;

        Event ultimoEvento = null;
        // ACT: 20 intentos de conexión SYN a SSH
        for (int i = 1; i <= 20; i++) {
            ultimoEvento = crearIntentoTcp(atacante, servidor, puertoSsh, true, false);
            detector.analyze(ultimoEvento);
        }

        // ASSERT
        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.BRUTE_FORCE, ultimoEvento.getEventType());
    }

    @Test
    void noDetectaFuerzaBrutaPorDebajoDelUmbral() {
        BruteForceDetector detector = new BruteForceDetector();
        String atacante = "10.0.0.99";
        String servidor = "192.168.1.10";
        int puertoFtp = 21;

        Event ultimoEvento = null;
        // 19 intentos (umbral es 20)
        for (int i = 1; i <= 19; i++) {
            ultimoEvento = crearIntentoTcp(atacante, servidor, puertoFtp, true, false);
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType());
    }

    @Test
    void ignoraPuertosNoSensibles() {
        BruteForceDetector detector = new BruteForceDetector();
        String atacante = "10.0.0.99";
        String servidor = "192.168.1.10";
        int puertoWeb = 8080; // No está en la lista de puertos sensibles de fuerza bruta por defecto

        Event ultimoEvento = null;
        // 30 intentos a puerto 8080
        for (int i = 1; i <= 30; i++) {
            ultimoEvento = crearIntentoTcp(atacante, servidor, puertoWeb, true, false);
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType());
    }

    @Test
    void traficoNoSynNoIncrementaFuerzaBruta() {
        BruteForceDetector detector = new BruteForceDetector();
        String atacante = "10.0.0.99";
        String servidor = "192.168.1.10";
        int puertoRdp = 3389;

        Event ultimoEvento = null;
        // 30 paquetes SYN-ACK (handshake establecido o respuesta)
        for (int i = 1; i <= 30; i++) {
            ultimoEvento = crearIntentoTcp(atacante, servidor, puertoRdp, true, true);
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType());
    }

    @Test
    void respetaConfiguracionCustomDePuertosYUmbrales() {
        Properties props = new Properties();
        props.setProperty("ids.detector.bruteforce.threshold", "3");
        props.setProperty("ids.detector.bruteforce.ports", "8080,9000");

        IdsConfig config = new IdsConfig(props);
        BruteForceDetector detector = new BruteForceDetector(config);

        Event ultimoEvento = null;
        for (int i = 1; i <= 3; i++) {
            ultimoEvento = crearIntentoTcp("10.0.0.5", "192.168.1.1", 8080, true, false);
            detector.analyze(ultimoEvento);
        }

        assertEquals(Event.EventType.BRUTE_FORCE, ultimoEvento.getEventType());
    }
}
