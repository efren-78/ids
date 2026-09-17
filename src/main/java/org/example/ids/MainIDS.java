package org.example.ids;

import org.example.ids.ui.AlertHistory;
import org.example.ids.ui.DashboardServer;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

public class MainIDS {

    private static final Logger logger = LoggerFactory.getLogger(MainIDS.class);

    private final IdsConfig config;
    private final DetectionEngine detectionEngine;
    private final AlertHistory alertHistory;
    private final PacketParser packetParser;
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
        this.packetParser = new PacketParser();
        this.captureController = new CaptureController(this.config, this.detectionEngine, this.packetParser);

        if (this.config.isUiEnabled()) {
            this.dashboardServer = new DashboardServer(this.config.getUiPort(), this.detectionEngine, this.alertHistory, this.captureController, this.config);
        }
    }

    public CaptureController getCaptureController() {
        return captureController;
    }

    public PacketParser getPacketParser() {
        return packetParser;
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
     * Convierte un paquete capturado en un Event delegando en PacketParser.
     */
    public Event dataProcess(Packet packet, Instant ts) {
        return packetParser.parse(packet, ts);
    }
}
