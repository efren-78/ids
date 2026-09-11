package org.example.ids;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import java.util.List;
import java.time.Instant;

public class MainIDS {

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
            System.out.println("Buscando interfaces de red con Npcap...");
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

            // Si no hay interfaces, no podemos continuar
            if (interfaces.isEmpty()) {
                System.out.println("No se detectó ninguna interfaz.");
                return;
            }

            // Seleccionar dispositivo con IP de red local; fallback al primero
            PcapNetworkInterface dispositivo = null;
            for (PcapNetworkInterface nif : interfaces) {
                for (PcapAddress addr : nif.getAddresses()) {
                    if (addr.getAddress() != null && addr.getAddress().isSiteLocalAddress()) {
                        dispositivo = nif;
                        break;
                    }
                }
                if (dispositivo != null)
                    break;
            }

            if (dispositivo == null) {
                dispositivo = interfaces.get(0);
            }

            System.out.println("Dispositivo seleccionado: " + dispositivo.getDescription());

            int snaplen = 65536; // tamaño máximo de captura
            int timeout = 10; // tiempo máximo de espera
            handle = dispositivo.openLive(
                    snaplen,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    timeout);

            handle.setFilter("ip or ip6", BpfProgram.BpfCompileMode.OPTIMIZE);

            // --- SHUTDOWN HOOK: cierre limpio al presionar Ctrl+C ---
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nDeteniendo captura...");
                detectionEngine.shutdown();
                if (handle != null && handle.isOpen()) {
                    try {
                        handle.breakLoop();
                    } catch (NotOpenException e) {
                        // ya estaba cerrado, no hay nada que hacer
                    } finally {
                        handle.close();
                        System.out.println("Handle cerrado correctamente.");
                    }
                }
            }));

            // --- PACKET LISTENER: conecta captura con procesamiento y detección ---
            PacketListener listener = packet -> {
                Instant ts = Instant.now();
                Event event = dataProcess(packet, ts);
                if (event != null) {
                    // Pasar el evento por el motor de detección
                    detectionEngine.analyze(event);

                    // Imprimir alertas de forma destacada
                    if (event.getEventType() != Event.EventType.NORMAL) {
                        System.out.println("⚠ ALERTA: " + event);
                    } else {
                        System.out.println(event);
                    }
                }
            };

            System.out.println("Capturando paquetes (Ctrl+C para detener)...");
            handle.loop(-1, listener);

        } catch (PcapNativeException e) {
            System.err.println("Error de Npcap (¿permisos de administrador?): " + e.getMessage());
        } catch (NotOpenException e) {
            System.err.println("El handle fue cerrado inesperadamente: " + e.getMessage());
        } catch (InterruptedException e) {
            System.out.println("Captura interrumpida.");
            Thread.currentThread().interrupt();
        }
    }

    // Convierte un paquete capturado en un Event; retorna null si se debe ignorar
    public Event dataProcess(Packet packet, Instant ts) {
        if (packet == null)
            return null;

        boolean esIpv4 = packet.contains(IpV4Packet.class);
        boolean esIpv6 = packet.contains(IpV6Packet.class);

        if (!esIpv4 && !esIpv6)
            return null;

        Event event = new Event();
        event.setTimestamp(ts);

        // --- Extracción de IPs: IPv4 e IPv6 ---
        if (esIpv4) {
            IpV4Packet ip = packet.get(IpV4Packet.class);
            event.setSrcIp(ip.getHeader().getSrcAddr().getHostAddress());
            event.setDstIp(ip.getHeader().getDstAddr().getHostAddress());
        } else {
            IpV6Packet ip = packet.get(IpV6Packet.class);
            event.setSrcIp(ip.getHeader().getSrcAddr().getHostAddress());
            event.setDstIp(ip.getHeader().getDstAddr().getHostAddress());
        }

        // --- Extracción de protocolo y puertos ---
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            event.setProtocol("TCP");
            event.setSrcPort(tcp.getHeader().getSrcPort().valueAsInt());
            event.setDstPort(tcp.getHeader().getDstPort().valueAsInt());
            event.setSyn(tcp.getHeader().getSyn());
            event.setAck(tcp.getHeader().getAck());
            event.setRst(tcp.getHeader().getRst());
            event.setFin(tcp.getHeader().getFin());
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            event.setProtocol("UDP");
            event.setSrcPort(udp.getHeader().getSrcPort().valueAsInt());
            event.setDstPort(udp.getHeader().getDstPort().valueAsInt());
        } else {
            return null; // ni TCP ni UDP; descartamos ICMP, etc. por ahora
        }

        // --- Filtro de ruido: multicast y broadcast IPv4 e IPv6 ---
        if (esRuidoDeRed(event.getDstIp(), esIpv6))
            return null;

        return event;
    }

    // Detecta correctamente multicast/broadcast en IPv4 e IPv6
    private boolean esRuidoDeRed(String dstIp, boolean esIpv6) {
        if (dstIp == null)
            return true;

        if (esIpv6) {
            // Multicast IPv6: ff00::/8
            return dstIp.toLowerCase().startsWith("ff");
        } else {
            // Multicast IPv4: 224.0.0.0 - 239.255.255.255 (primer octeto 224-239)
            String[] octetos = dstIp.split("\\.");
            if (octetos.length == 4) {
                try {
                    int primerOcteto = Integer.parseInt(octetos[0]);
                    if (primerOcteto >= 224 && primerOcteto <= 239)
                        return true;
                } catch (NumberFormatException ignored) {
                }
            }
            // Broadcast limitado
            if (dstIp.equals("255.255.255.255"))
                return true;

            return false;
        }
    }
}