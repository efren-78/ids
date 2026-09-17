package org.example.ids;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * Parser de paquetes de red capturados.
 * Convierte paquetes de bajo nivel (pcap4j) en objetos de dominio {@link Event},
 * aplicando filtrado de ruido de red (multicast, broadcast) y validaciones defensivas.
 */
public class PacketParser {

    private static final Logger logger = LoggerFactory.getLogger(PacketParser.class);

    /**
     * Convierte un paquete capturado en un {@link Event} de forma segura y defensiva.
     *
     * @param packet Paquete de red capturado.
     * @param ts Timestamp de captura (o null para usar Instant.now()).
     * @return Objeto Event resultante o null si el paquete es irrelevante, corrupto o ruido.
     */
    public Event parse(Packet packet, Instant ts) {
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
    boolean esRuidoDeRed(String dstIp, boolean esIpv6) {
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
