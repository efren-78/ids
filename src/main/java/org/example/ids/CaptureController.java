package org.example.ids;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

/**
 * Controlador del ciclo de vida de la captura de paquetes.
 * Permite iniciar, detener y reiniciar la captura desde el Dashboard Web.
 */
public class CaptureController {

    private static final Logger logger = LoggerFactory.getLogger(CaptureController.class);

    public enum State { STOPPED, RUNNING, STARTING, STOPPING }

    private final IdsConfig config;
    private final DetectionEngine detectionEngine;
    private final MainIDS mainIDS;

    private volatile State state = State.STOPPED;
    private volatile PcapHandle handle;
    private volatile Thread captureThread;

    public CaptureController(IdsConfig config, DetectionEngine detectionEngine, MainIDS mainIDS) {
        this.config = config;
        this.detectionEngine = detectionEngine;
        this.mainIDS = mainIDS;
    }

    public synchronized State getState() {
        return state;
    }

    /**
     * Inicia la captura en un hilo dedicado. No-op si ya está corriendo.
     */
    public synchronized boolean start() {
        if (state == State.RUNNING || state == State.STARTING) {
            logger.info("La captura ya está activa o iniciándose.");
            return false;
        }

        state = State.STARTING;
        captureThread = new Thread(() -> {
            try {
                runCapture();
            } catch (Throwable t) {
                logger.error("Error fatal en hilo de captura: {}", t.getMessage(), t);
            } finally {
                state = State.STOPPED;
                logger.info("Hilo de captura finalizado.");
            }
        }, "ids-capture-thread");
        captureThread.setDaemon(true);
        captureThread.start();
        return true;
    }

    /**
     * Detiene la captura en curso de forma limpia.
     */
    public synchronized boolean stop() {
        if (state != State.RUNNING && state != State.STARTING) {
            logger.info("La captura no está activa.");
            return false;
        }

        state = State.STOPPING;
        logger.info("Deteniendo captura...");

        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException ignored) {
            }
        }
        return true;
    }

    /**
     * Reinicia la captura: detiene y vuelve a iniciar.
     */
    public boolean restart() {
        stop();

        // Esperar a que el hilo de captura termine (máx 3 segundos)
        Thread ct = captureThread;
        if (ct != null) {
            try {
                ct.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        return start();
    }

    private void runCapture() {
        try {
            logger.info("Buscando interfaces de red...");
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

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

            int snaplen = config.getCaptureSnaplen();
            int timeout = config.getCaptureTimeoutMs();
            PcapNetworkInterface.PromiscuousMode mode = config.isCapturePromiscuous()
                    ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
                    : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;

            handle = dispositivo.openLive(snaplen, mode, timeout);
            handle.setFilter(config.getCaptureFilter(), BpfProgram.BpfCompileMode.OPTIMIZE);

            state = State.RUNNING;

            PacketListener listener = packet -> {
                try {
                    if (packet == null) {
                        return;
                    }
                    Instant ts = Instant.now();
                    Event event = mainIDS.dataProcess(packet, ts);
                    if (event != null) {
                        detectionEngine.submit(event);
                    }
                } catch (Throwable t) {
                    logger.error("Error inesperado al procesar paquete capturado: {}", t.getMessage(), t);
                }
            };

            logger.info("Captura iniciada. Monitoreando tráfico...");
            handle.loop(-1, listener);

        } catch (PcapNativeException e) {
            logger.error("Error de Npcap (¿permisos de administrador?): {}", e.getMessage(), e);
        } catch (NotOpenException e) {
            logger.error("El handle fue cerrado inesperadamente: {}", e.getMessage(), e);
        } catch (InterruptedException e) {
            logger.info("Captura interrumpida.");
            Thread.currentThread().interrupt();
        } catch (Throwable t) {
            logger.error("Error no controlado en la captura: {}", t.getMessage(), t);
        } finally {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
            handle = null;
        }
    }
}
