package org.example.ids;

import org.example.ids.ui.AlertHistory;
import org.example.ids.ui.DashboardServer;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

public class MainIDS {

    private static final Logger logger = LoggerFactory.getLogger(MainIDS.class);

    private final IdsConfig config;
    private final DetectionEngine detectionEngine;
    private final AlertHistory alertHistory;
    private final CaptureController captureController;
    private DashboardServer dashboardServer;

    public MainIDS() {
        this(IdsConfig.getInstance());
    }

    public MainIDS(IdsConfig config) {
        this.config = (config != null) ? config : IdsConfig.getInstance();
        this.detectionEngine = new DetectionEngine(this.config);
        this.alertHistory = new AlertHistory();
        this.detectionEngine.setAlertListener(alertHistory::addAlert);
        this.captureController = new CaptureController(this.config, this.detectionEngine, this);

        if (this.config.isUiEnabled()) {
            this.dashboardServer = new DashboardServer(this.config.getUiPort(), this.detectionEngine, this.alertHistory, this.captureController);
        }
    }

    public CaptureController getCaptureController() {
        return captureController;
    }

    public static void main(String[] args) {
        MainIDS main = new MainIDS();
        main.run();
    }

    public void run() {
        // --- SHUTDOWN HOOK: cierre limpio al presionar Ctrl+C ---
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Deteniendo captura y apagando servicios...");
            if (dashboardServer != null) {
                dashboardServer.stop();
            }
            captureController.stop();
            detectionEngine.shutdown();
            logger.info("Cerrado correctamente.");
        }));

        if (dashboardServer != null) {
            try {
                dashboardServer.start();
            } catch (Exception e) {
                logger.error("No se pudo iniciar el Dashboard Web: {}", e.getMessage(), e);
            }
        }

        // Iniciar captura a través del CaptureController
        captureController.start();

        // Mantener el hilo principal vivo mientras la captura o el dashboard estén activos
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            logger.info("Captura interrumpida.");
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Convierte un paquete capturado en un Event de forma segura y defensiva.
     * Retorna null si el paquete es irrelevante, corrupto o ruido de red.
     */
    public Event dataProcess(Packet packet, Instant ts) {
        if (packet == null) {
            return null;
        }

        try {
            boolean esIpv4 = packet.contains(IpV4Packet.class);
            boolean esIpv6 = packet.contains(IpV6Packet.class);

            if (!esIpv4 && !esIpv6) {
                return null;
            }

            Event event = new Event();
            event.setTimestamp(ts != null ? ts : Instant.now());

            // --- Extracción segura de IPs: IPv4 e IPv6 ---
            if (esIpv4) {
                if (!extractIpv4(packet.get(IpV4Packet.class), event)) {
                    return null;
                }
            } else {
                if (!extractIpv6(packet.get(IpV6Packet.class), event)) {
                    return null;
                }
            }

            // --- Extracción segura de protocolo y puertos ---
            if (packet.contains(TcpPacket.class)) {
                if (!extractTcp(packet.get(TcpPacket.class), event)) {
                    return null;
                }
            } else if (packet.contains(UdpPacket.class)) {
                if (!extractUdp(packet.get(UdpPacket.class), event)) {
                    return null;
                }
            } else {
                return null; // ni TCP ni UDP
            }

            // --- Filtro de ruido: multicast y broadcast IPv4 e IPv6 ---
            if (esRuidoDeRed(event.getDstIp(), esIpv6)) {
                return null;
            }

            return event;
        } catch (Exception e) {
            logger.debug("Descartando paquete malformado: {}", e.getMessage());
            return null;
        }
    }

    private boolean extractIpv4(IpV4Packet ip, Event event) {
        if (ip == null || ip.getHeader() == null) {
            return false;
        }
        var src = ip.getHeader().getSrcAddr();
        var dst = ip.getHeader().getDstAddr();
        if (src == null || dst == null) {
            return false;
        }

        event.setSrcIp(src.getHostAddress());
        event.setDstIp(dst.getHostAddress());
        return true;
    }

    private boolean extractIpv6(IpV6Packet ip, Event event) {
        if (ip == null || ip.getHeader() == null) {
            return false;
        }
        var src = ip.getHeader().getSrcAddr();
        var dst = ip.getHeader().getDstAddr();
        if (src == null || dst == null) {
            return false;
        }

        event.setSrcIp(src.getHostAddress());
        event.setDstIp(dst.getHostAddress());
        return true;
    }

    private boolean extractTcp(TcpPacket tcp, Event event) {
        if (tcp == null || tcp.getHeader() == null) {
            return false;
        }
        var srcPort = tcp.getHeader().getSrcPort();
        var dstPort = tcp.getHeader().getDstPort();
        if (srcPort == null || dstPort == null) {
            return false;
        }

        event.setProtocol("TCP");
        event.setSrcPort(srcPort.valueAsInt());
        event.setDstPort(dstPort.valueAsInt());
        event.setSyn(tcp.getHeader().getSyn());
        event.setAck(tcp.getHeader().getAck());
        event.setRst(tcp.getHeader().getRst());
        event.setFin(tcp.getHeader().getFin());
        return true;
    }

    private boolean extractUdp(UdpPacket udp, Event event) {
        if (udp == null || udp.getHeader() == null) {
            return false;
        }
        var srcPort = udp.getHeader().getSrcPort();
        var dstPort = udp.getHeader().getDstPort();
        if (srcPort == null || dstPort == null) {
            return false;
        }

        event.setProtocol("UDP");
        event.setSrcPort(srcPort.valueAsInt());
        event.setDstPort(dstPort.valueAsInt());
        return true;
    }

    // Detecta correctamente multicast/broadcast en IPv4 e IPv6 de forma tolerante a errores
    private boolean esRuidoDeRed(String dstIp, boolean esIpv6) {
        if (dstIp == null || dstIp.isBlank()) {
            return true;
        }

        if (esIpv6) {
            // Multicast IPv6: ff00::/8
            return dstIp.toLowerCase().startsWith("ff");
        } else {
            // Multicast IPv4: 224.0.0.0 - 239.255.255.255 (primer octeto 224-239)
            String[] octetos = dstIp.split("\\.");
            if (octetos.length == 4) {
                try {
                    int primerOcteto = Integer.parseInt(octetos[0]);
                    if (primerOcteto >= 224 && primerOcteto <= 239) {
                        return true;
                    }
                } catch (NumberFormatException ignored) {
                }
            }
            // Broadcast limitado
            return dstIp.equals("255.255.255.255");
        }
    }
}
