package org.example.ids;

import org.junit.jupiter.api.Test;
import java.sql.Timestamp;
import static org.junit.jupiter.api.Assertions.*;

class PortScanDetectorTest {

    // Helper para crear un evento con un puerto destino específico
    private Event crearEvento(String srcIp, int dstPort) {
        Event event = new Event();
        event.timestamp = new Timestamp(System.currentTimeMillis());
        event.srcIp = srcIp;
        event.dstIp = "192.168.1.100";
        event.srcPort = 12345;
        event.dstPort = dstPort;
        event.protocol = "TCP";
        return event;
    }

    @Test
    void detectaPortScanCuandoSeExcedeUmbral() {
        // 1. ARRANGE — preparar los objetos
        PortScanDetector detector = new PortScanDetector();
        String ipAtacante = "10.0.0.1";

        // 2. ACT — enviar 15 eventos con puertos distintos (umbral = 15)
        Event ultimoEvento = null;
        for (int i = 1; i <= 15; i++) {
            ultimoEvento = crearEvento(ipAtacante, i);
            detector.analyze(ultimoEvento);
        }

        // 3. ASSERT — el último evento debe ser clasificado como PORT_SCAN
        assertEquals(Event.EventType.PORT_SCAN, ultimoEvento.event_type);
    }

    @Test
    void noDetectaPortScanPorDebajoDelUmbral() {
        // 1. ARRANGE
        PortScanDetector detector = new PortScanDetector();
        String ipNormal = "10.0.0.2";

        // 2. ACT — enviar solo 14 eventos (por debajo del umbral de 15)
        Event ultimoEvento = null;
        for (int i = 1; i <= 14; i++) {
            ultimoEvento = crearEvento(ipNormal, i);
            detector.analyze(ultimoEvento);
        }

        // 3. ASSERT — debe seguir como NORMAL
        assertEquals(Event.EventType.NORMAL, ultimoEvento.event_type);
    }

    @Test
    void mismosPuertosNoDisparanAlerta() {
        // 1. ARRANGE
        PortScanDetector detector = new PortScanDetector();
        String ipRepetitiva = "10.0.0.3";

        // 2. ACT — enviar 20 eventos pero todos al mismo puerto
        Event ultimoEvento = null;
        for (int i = 0; i < 20; i++) {
            ultimoEvento = crearEvento(ipRepetitiva, 80); // siempre puerto 80
            detector.analyze(ultimoEvento);
        }

        // 3. ASSERT — no es port scan porque es un solo puerto
        assertEquals(Event.EventType.NORMAL, ultimoEvento.event_type);
    }

    @Test
    void diferentesIPsNoSeAcumulan() {
        // 1. ARRANGE
        PortScanDetector detector = new PortScanDetector();

        // 2. ACT — 15 puertos distintos pero desde IPs diferentes
        Event ultimoEvento = null;
        for (int i = 1; i <= 15; i++) {
            ultimoEvento = crearEvento("10.0.0." + i, i); // cada evento de IP distinta
            detector.analyze(ultimoEvento);
        }

        // 3. ASSERT — ninguna IP individual supera el umbral
        assertEquals(Event.EventType.NORMAL, ultimoEvento.event_type);
    }
}
