package org.example.ids;

import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class IdsConfigTest {

    @Test
    void loadsDefaultsFromPropertiesFile() {
        IdsConfig config = IdsConfig.getInstance();

        assertNotNull(config);
        assertEquals(65536, config.getCaptureSnaplen());
        assertEquals(10, config.getCaptureTimeoutMs());
        assertEquals("ip or ip6", config.getCaptureFilter());
        assertTrue(config.isCapturePromiscuous());

        assertEquals(30, config.getEnginePurgeIntervalSeconds());

        assertEquals(10000L, config.getPortScanWindowMs());
        assertEquals(15, config.getPortScanThreshold());
        assertEquals(50000L, config.getPortScanMaxCapacity());

        assertEquals(5000L, config.getSynFloodWindowMs());
        assertEquals(50, config.getSynFloodThreshold());
        assertEquals(50000L, config.getSynFloodMaxCapacity());
    }

    @Test
    void returnsFallbackForMissingKeys() {
        IdsConfig config = new IdsConfig(new Properties());

        assertEquals(1234, config.getInt("non.existing.int", 1234));
        assertEquals(9999L, config.getLong("non.existing.long", 9999L));
        assertEquals("default-text", config.getString("non.existing.str", "default-text"));
        assertFalse(config.getBoolean("non.existing.bool", false));
    }

    @Test
    void recoversGracefullyFromMalformedValues() {
        Properties malformedProps = new Properties();
        malformedProps.setProperty("ids.detector.portscan.threshold", "not-a-number");
        malformedProps.setProperty("ids.detector.synflood.window.ms", "invalid-long");

        IdsConfig config = new IdsConfig(malformedProps);

        // Debe retornar el valor de fallback sin lanzar NumberFormatException
        assertEquals(15, config.getPortScanThreshold());
        assertEquals(5000L, config.getSynFloodWindowMs());
    }

    @Test
    void detectorsRespectCustomConfig() {
        Properties customProps = new Properties();
        customProps.setProperty("ids.detector.portscan.threshold", "5");
        customProps.setProperty("ids.detector.synflood.threshold", "3");

        IdsConfig customConfig = new IdsConfig(customProps);

        PortScanDetector portScanDetector = new PortScanDetector(customConfig);
        SynFloodDetector synFloodDetector = new SynFloodDetector(customConfig);

        // Probar que el detector de escaneo de puertos ahora dispara con solo 5 puertos
        Event lastPortScanEvent = null;
        for (int i = 1; i <= 5; i++) {
            lastPortScanEvent = new Event();
            lastPortScanEvent.setSrcIp("10.10.10.10");
            lastPortScanEvent.setDstPort(80 + i);
            portScanDetector.analyze(lastPortScanEvent);
        }
        assertEquals(Event.EventType.PORT_SCAN, lastPortScanEvent.getEventType());

        // Probar que el detector de SYN Flood ahora dispara con solo 3 paquetes
        Event lastSynEvent = null;
        for (int i = 1; i <= 3; i++) {
            lastSynEvent = new Event();
            lastSynEvent.setDstIp("192.168.1.99");
            lastSynEvent.setProtocol("TCP");
            lastSynEvent.setSyn(true);
            lastSynEvent.setAck(false);
            synFloodDetector.analyze(lastSynEvent);
        }
        assertEquals(Event.EventType.SYN_FLOOD, lastSynEvent.getEventType());
    }
}
