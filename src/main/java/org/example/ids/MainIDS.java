package org.example.ids;

import java.time.Instant;
import java.util.List;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainIDS {

    private static final Logger logger = LoggerFactory.getLogger(MainIDS.class);

    // Handle a nivel de clase para poder cerrarlo desde el shutdown hook
    private PcapHandle handle;
    private final DetectionEngine detectionEngine = new DetectionEngine();

    public static void main(String[] args) {
        MainIDS main = new MainIDS();
        main.run();
    }

    public void run() {
        eventsCapture();
    }

    public void eventsCapture() {
        try {
            logger.info("Buscando interfaces de red...");
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

            // Si no hay interfaces, no podemos continuar
            if (interfaces == null || interfaces.isEmpty()) {
                logger.error("No se detectó ninguna interfaz de red disponible.");
                return;
            }

            // Seleccionar dispositivo con IP de red local; fallback al primero
            PcapNetworkInterface dispositivo = null;
            for (PcapNetworkInterface nif : interfaces) {
                if (nif == null || nif.getAddresses() == null) {
                    continue;
                }
                for (PcapAddress addr : nif.getAddresses()) {
                    if (addr != null && addr.getAddress() != null && addr.getAddress().isSiteLocalAddress()) {
                        dispositivo = nif;
                        break;
                    }
                }
                if (dispositivo != null) {
                    break;
                }
            }

            if (dispositivo == null) {
                dispositivo = interfaces.get(0);
            }

            logger.info("Dispositivo seleccionado: {} ({})", dispositivo.getName(), dispositivo.getDescription());

            int snaplen = 65536; // tamaño máximo de captura
            int timeout = 10;    // tiempo máximo de espera en ms
            handle = dispositivo.openLive(
                    snaplen,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    timeout);

            handle.setFilter("ip or ip6", BpfProgram.BpfCompileMode.OPTIMIZE);

            // --- SHUTDOWN HOOK: cierre limpio al presionar Ctrl+C ---
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Deteniendo captura y apagando servicios...");
                detectionEngine.shutdown();
                if (handle != null && handle.isOpen()) {
                    try {
                        handle.breakLoop();
                    } catch (NotOpenException ignored) {
                    } finally {
                        handle.close();
                        logger.info("Cerrado correctamente.");
                    }
                }
            }));

            // --- PACKET LISTENER: conecta captura con procesamiento y detección blindado ---
            PacketListener listener = packet -> {
                try {
                    if (packet == null) {
                        return;
                    }

                    Instant ts = Instant.now();
                    Event event = dataProcess(packet, ts);
                    if (event != null) {
                        // Pasar el evento por el motor de detección
                        detectionEngine.analyze(event);

                        // Imprimir alertas de forma destacada o trazas según severidad
                        if (event.getEventType() != Event.EventType.NORMAL) {
                            logger.warn("ALERTA: {}", event);
                        } else if (logger.isDebugEnabled()) {
                            logger.debug("Evento: {}", event);
                        }
                    }
                } catch (Throwable t) {
                    // Blindaje total: ningún fallo en el procesamiento de un paquete derriba la captura
                    logger.error("Error inesperado al procesar paquete capturado: {}", t.getMessage(), t);
                }
            };

            logger.info("Iniciando captura de paquetes (Ctrl+C para detener)...");
            handle.loop(-1, listener);

        } catch (PcapNativeException e) {
            logger.error("Error de Npcap (¿permisos de administrador?): {}", e.getMessage(), e);
        } catch (NotOpenException e) {
            logger.error("El handle fue cerrado inesperadamente: {}", e.getMessage(), e);
        } catch (InterruptedException e) {
            logger.info("Captura interrumpida.");
            Thread.currentThread().interrupt();
        } catch (Throwable t) {
            logger.error("Error no controlado en la captura de eventos: {}", t.getMessage(), t);
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
