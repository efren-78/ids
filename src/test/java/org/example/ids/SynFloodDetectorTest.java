package org.example.ids;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class SynFloodDetectorTest {

    // Helper para crear un evento TCP con flags configurables
    private Event crearEventoTcp(String dstIp, boolean syn, boolean ack) {
        Event event = new Event();
        event.setTimestamp(Instant.now());
        event.setSrcIp("10.0.0.99");
        event.setDstIp(dstIp);
        event.setSrcPort(45000);
        event.setDstPort(80);
        event.setProtocol("TCP");
        event.setSyn(syn);
        event.setAck(ack);
        return event;
    }

    @Test
    void detectaSynFloodCuandoSeExcedeUmbral() {
        // 1. ARRANGE (umbral = 50 paquetes SYN sin ACK a la misma IP destino)
        SynFloodDetector detector = new SynFloodDetector();
        String ipDestino = "192.168.1.50";

        // 2. ACT — enviar 50 paquetes SYN (sin ACK)
        Event ultimoEvento = null;
        for (int i = 1; i <= 50; i++) {
            ultimoEvento = crearEventoTcp(ipDestino, true, false);
            detector.analyze(ultimoEvento);
        }

        // 3. ASSERT — se debe clasificar como SYN_FLOOD
        assertEquals(Event.EventType.SYN_FLOOD, ultimoEvento.getEventType());
    }

    @Test
    void noDetectaSynFloodPorDebajoDelUmbral() {
        // 1. ARRANGE
        SynFloodDetector detector = new SynFloodDetector();
        String ipDestino = "192.168.1.50";

        // 2. ACT — enviar 49 paquetes SYN (por debajo de 50)
        Event ultimoEvento = null;
        for (int i = 1; i <= 49; i++) {
            ultimoEvento = crearEventoTcp(ipDestino, true, false);
            detector.analyze(ultimoEvento);
        }

        // 3. ASSERT — debe permanecer NORMAL
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType());
    }

    @Test
    void traficoNormalSynAckNoDisparaAlerta() {
        // 1. ARRANGE
        SynFloodDetector detector = new SynFloodDetector();
        String ipDestino = "192.168.1.50";

        // 2. ACT — enviar 60 paquetes con SYN y ACK activos (handshake normal)
        Event ultimoEvento = null;
        for (int i = 1; i <= 60; i++) {
            ultimoEvento = crearEventoTcp(ipDestino, true, true);
            detector.analyze(ultimoEvento);
        }

        // 3. ASSERT — no debe disparar alerta de SYN flood
        assertEquals(Event.EventType.NORMAL, ultimoEvento.getEventType());
    }
}
