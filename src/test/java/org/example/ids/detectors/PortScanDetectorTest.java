package org.example.ids.detectors;

import org.example.ids.Event;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class PortScanDetectorTest {

    private Event crearEventoTcpSyn(String srcIp, String dstIp, int dstPort) {
        Event event = new Event();
        event.setTimestamp(Instant.now());
        event.setSrcIp(srcIp);
        event.setDstIp(dstIp);
        event.setSrcPort(45000);
        event.setDstPort(dstPort);
        event.setProtocol("TCP");
        event.setSyn(true);
        event.setAck(false);
        return event;
    }

    @Test
    void detectaPortScanCuandoSeExcedeUmbralEnMismoDestino() {
        PortScanDetector detector = new PortScanDetector();
        String atacante = "10.0.0.1";
        String victima = "192.168.1.100";

        Event ultimoEvento = null;
        for (int i = 1; i <= 15; i++) {
            ultimoEvento = crearEventoTcpSyn(atacante, victima, i);
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.PORT_SCAN, ultimoEvento.getEventType());
        assertEquals(15, ultimoEvento.getNumberOfPorts());
    }

    @Test
    void noDetectaPortScanPorDebajoDelUmbral() {
        PortScanDetector detector = new PortScanDetector();
        String atacante = "10.0.0.2";
        String victima = "192.168.1.100";

        Event ultimoEvento = null;
        for (int i = 1; i <= 14; i++) {
            ultimoEvento = crearEventoTcpSyn(atacante, victima, i);
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType());
    }

    @Test
    void traficoEstablecidoNoEsPortScan() {
        PortScanDetector detector = new PortScanDetector();
        String srcIp = "192.168.1.50";
        String dstIp = "192.168.1.1";

        // Paquetes TCP ACK establecidos (navegación o transferencia normal de datos)
        Event ultimoEvento = null;
        for (int i = 1; i <= 20; i++) {
            ultimoEvento = new Event();
            ultimoEvento.setSrcIp(srcIp);
            ultimoEvento.setDstIp(dstIp);
            ultimoEvento.setDstPort(i);
            ultimoEvento.setProtocol("TCP");
            ultimoEvento.setSyn(false);
            ultimoEvento.setAck(true);
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType(), "Tráfico establecido no debe clasificarse como port scan");
    }

    @Test
    void navegacionA15SitiosDiferentesNoDisparaAlerta() {
        PortScanDetector detector = new PortScanDetector();
        String miPc = "192.168.1.50";

        // Mi PC abriendo conexiones legítimas a 15 servidores web distintos (cada uno en puerto 443 o 80)
        Event ultimoEvento = null;
        for (int i = 1; i <= 15; i++) {
            ultimoEvento = crearEventoTcpSyn(miPc, "93.184.216." + i, 443);
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType(), "Conexiones a destinos diferentes no deben acumularse como port scan");
    }

    @Test
    void consultasDnsMultiplesNoDisparanAlerta() {
        PortScanDetector detector = new PortScanDetector();
        String miPc = "192.168.1.50";
        String dnsServer = "192.168.1.1";

        // 30 consultas DNS al mismo puerto 53
        Event ultimoEvento = null;
        for (int i = 1; i <= 30; i++) {
            ultimoEvento = new Event();
            ultimoEvento.setSrcIp(miPc);
            ultimoEvento.setDstIp(dnsServer);
            ultimoEvento.setSrcPort(50000 + i);
            ultimoEvento.setDstPort(53); // Siempre puerto 53
            ultimoEvento.setProtocol("UDP");
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType(), "Consultas repetidas al puerto 53 no deben disparar port scan");
    }

    @Test
    void detectaEscaneoUdpAMultiplesPuertosEnMismoDestino() {
        PortScanDetector detector = new PortScanDetector();
        String atacante = "10.0.0.5";
        String victima = "192.168.1.10";

        Event ultimoEvento = null;
        for (int i = 1; i <= 15; i++) {
            ultimoEvento = new Event();
            ultimoEvento.setSrcIp(atacante);
            ultimoEvento.setDstIp(victima);
            ultimoEvento.setSrcPort(40000);
            ultimoEvento.setDstPort(i * 10);
            ultimoEvento.setProtocol("UDP");
            detector.analyze(ultimoEvento);
        }

        assertNotNull(ultimoEvento);
        assertEquals(Event.EventType.PORT_SCAN, ultimoEvento.getEventType());
    }
}
