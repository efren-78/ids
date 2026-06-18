import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import java.util.List;

public class MainIDS {
    public static void main(String[] args) {
        try {
            System.out.println("Buscando interfaces de red con Npcap...");
            List<PcapNetworkInterface> listas = Pcaps.findAllDevs();

            if (listas.isEmpty()) {
                System.out.println("No se detectó ninguna interfaz. Recuerda ejecutar como Administrador.");
                return;
            }

            for (PcapNetworkInterface dispositivo : listas) {
                System.out.println("Dispositivo encontrado: " + dispositivo.getDescription());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}