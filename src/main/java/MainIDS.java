import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import java.util.List;
import java.sql.Timestamp;

public class MainIDS {
    public static void main(String[] args) {
        MainIDS main = new MainIDS();
        main.events_capture();
    }

    public void events_capture() {
        try {
            System.out.println("Buscando interfaces de red con Npcap...");
            List<PcapNetworkInterface> listas = Pcaps.findAllDevs();

            // Checa si hay alguna interfaz
            if (listas.isEmpty()) {
                System.out.println("No se detectó ninguna interfaz.");
                return;
            }

            // Buscamos un dispositivo activo que no sea loopback si es posible
            PcapNetworkInterface dispositivo = null;
            for (PcapNetworkInterface nif : listas) {
                List<PcapAddress> direcciones = nif.getAddresses();
                for (PcapAddress addr : direcciones) {
                    if (addr.getAddress() != null && addr.getAddress().isSiteLocalAddress()) {
                        dispositivo = nif;
                        break;
                    }
                }
                if (dispositivo != null) {
                    break;
                }
            }

            // Fallback al primer dispositivo encontrado si no hay uno con IP LAN privada
            if (dispositivo == null) {
                dispositivo = listas.get(0);
            }

            System.out.println("Dispositivo seleccionado para captura: " + dispositivo.getDescription());

            // Abrir la interfaz para captura en vivo
            int snaplen = 65536; // Capturar paquete completo
            int timeout = 10;    // Timeout en ms
            PcapHandle handle = dispositivo.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

            // Filtrar solo tráfico IPv4 o IPv6
            handle.setFilter("ip or ip6", BpfProgram.BpfCompileMode.OPTIMIZE);

            System.out.println("Iniciando captura de paquetes (Ctrl+C para detener)...");

            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    Timestamp ts = handle.getTimestamp();
                    String srcIp = "Desconocida";
                    String dstIp = "Desconocida";
                    String protocol = "IP";
                    int srcPort = -1;
                    int dstPort = -1;

                    if (packet.contains(IpV4Packet.class)) {
                        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
                        srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
                        dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
                    } else if (packet.contains(IpV6Packet.class)) {
                        IpV6Packet ipV6 = packet.get(IpV6Packet.class);
                        srcIp = ipV6.getHeader().getSrcAddr().getHostAddress();
                        dstIp = ipV6.getHeader().getDstAddr().getHostAddress();
                    }

                    if (packet.contains(TcpPacket.class)) {
                        TcpPacket tcp = packet.get(TcpPacket.class);
                        srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                        dstPort = tcp.getHeader().getDstPort().valueAsInt();
                        protocol = "TCP";
                    } else if (packet.contains(UdpPacket.class)) {
                        UdpPacket udp = packet.get(UdpPacket.class);
                        srcPort = udp.getHeader().getSrcPort().valueAsInt();
                        dstPort = udp.getHeader().getDstPort().valueAsInt();
                        protocol = "UDP";
                    }

                    // Imprimimos el evento si pudimos extraer la dirección IP
                    if (!srcIp.equals("Desconocida")) {
                        System.out.printf("[%s] [%s] %s:%d -> %s:%d (Acceso al puerto: %d)%n",
                            ts != null ? ts.toString() : "N/A", protocol, srcIp, srcPort, dstIp, dstPort, dstPort);
                    }
                }
            };

            // Iniciar la captura en bucle infinito
            handle.loop(-1, listener);

            // Cerrar el handle al terminar (aunque loop(-1) corre indefinidamente)
            handle.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void data_process() {
    }

    public static void data_send() {
    }
}