package org.example.ids.ui;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.example.ids.CaptureController;
import org.example.ids.DetectionEngine;
import org.example.ids.Event;
import org.example.ids.IdsConfig;
import org.example.ids.auth.AuthFilter;
import org.example.ids.auth.AuthManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

/**
 * Servidor Web embebido ultraligero para el Dashboard de Monitoreo SOC del IDS.
 *
 * Utiliza com.sun.net.httpserver nativo de Java.
 */
public class DashboardServer {

    private static final Logger logger = LoggerFactory.getLogger(DashboardServer.class);

    private final int port;
    private final DetectionEngine detectionEngine;
    private final AlertHistory alertHistory;
    private final CaptureController captureController;
    private final AuthManager authManager;
    private HttpServer server;

    private final List<OutputStream> sseClients = new CopyOnWriteArrayList<>();

    /**
     * Constructor completo con CaptureController para control de monitoreo.
     */
    public DashboardServer(int port, DetectionEngine detectionEngine, AlertHistory alertHistory,
                           CaptureController captureController, IdsConfig config) {
        this.port = port;
        this.detectionEngine = detectionEngine;
        this.alertHistory = alertHistory;
        this.captureController = captureController;
        this.authManager = new AuthManager((config != null) ? config : IdsConfig.getInstance());

        if (this.alertHistory != null) {
            this.alertHistory.addListener(this::broadcastAlertToSse);
        }
    }

    /**
     * Constructor de compatibilidad (usado en tests y llamadas sin config explícito).
     */
    public DashboardServer(int port, DetectionEngine detectionEngine, AlertHistory alertHistory,
                           CaptureController captureController) {
        this(port, detectionEngine, alertHistory, captureController, null);
    }

    /**
     * Constructor de compatibilidad mínimo (usado en tests).
     */
    public DashboardServer(int port, DetectionEngine detectionEngine, AlertHistory alertHistory) {
        this(port, detectionEngine, alertHistory, null, null);
    }

    public AuthManager getAuthManager() {
        return authManager;
    }

    public synchronized void start() throws IOException {
        if (server != null) {
            return;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "ids-web-server");
            t.setDaemon(true);
            return t;
        }));

        AuthFilter authFilter = new AuthFilter(authManager);

        // --- Rutas PÚBLICAS (sin autenticación) ---
        server.createContext("/login", new StaticFileHandler("web/login.html", "text/html; charset=UTF-8"));
        server.createContext("/style-login.css", new StaticFileHandler("web/style-login.css", "text/css; charset=UTF-8"));
        server.createContext("/api/login", new LoginHandler());

        // --- Rutas PROTEGIDAS (requieren sesión válida) ---
        HttpContext ctxRoot = server.createContext("/", new StaticFileHandler("web/index.html", "text/html; charset=UTF-8"));
        ctxRoot.getFilters().add(authFilter);

        HttpContext ctxCss = server.createContext("/style.css", new StaticFileHandler("web/style.css", "text/css; charset=UTF-8"));
        ctxCss.getFilters().add(authFilter);

        HttpContext ctxJs = server.createContext("/app.js", new StaticFileHandler("web/app.js", "application/javascript; charset=UTF-8"));
        ctxJs.getFilters().add(authFilter);

        // Endpoints API protegidos
        HttpContext ctxStats = server.createContext("/api/stats", new StatsHandler());
        ctxStats.getFilters().add(authFilter);

        HttpContext ctxAlerts = server.createContext("/api/alerts", new AlertsHandler());
        ctxAlerts.getFilters().add(authFilter);

        HttpContext ctxStream = server.createContext("/api/stream", new SseStreamHandler());
        ctxStream.getFilters().add(authFilter);

        HttpContext ctxSimulate = server.createContext("/api/simulate", new SimulateHandler());
        ctxSimulate.getFilters().add(authFilter);

        HttpContext ctxMonitor = server.createContext("/api/monitor", new MonitorHandler());
        ctxMonitor.getFilters().add(authFilter);

        HttpContext ctxLogout = server.createContext("/api/logout", new LogoutHandler());
        ctxLogout.getFilters().add(authFilter);

        server.start();
        logger.info("=================================================================");
        logger.info("IDS DASHBOARD ACTIVO: Accede en http://localhost:{}", port);
        if (authManager.isAuthEnabled()) {
            logger.info("Autenticación activa. Accede con las credenciales configuradas.");
        }
        logger.info("=================================================================");
    }

    public synchronized void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
            logger.info("Servidor Dashboard detenido.");
        }
    }

    private void broadcastAlertToSse(Event alert) {
        String json = "data: {\"type\":\"ALERT\",\"event\":" + eventToJson(alert) + "}\n\n";
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

        List<OutputStream> deadClients = new ArrayList<>();
        for (OutputStream os : sseClients) {
            try {
                os.write(bytes);
                os.flush();
            } catch (IOException e) {
                deadClients.add(os);
            }
        }
        sseClients.removeAll(deadClients);
    }

    private String eventToJson(Event e) {
        return String.format(
                "{\"timestamp\":\"%s\",\"protocol\":\"%s\",\"srcIp\":\"%s\",\"srcPort\":%d,\"dstIp\":\"%s\",\"dstPort\":%d,\"eventType\":\"%s\",\"numberOfPorts\":%d,\"syn\":%b,\"ack\":%b,\"fin\":%b,\"rst\":%b}",
                e.getTimestamp(), e.getProtocol(), e.getSrcIp(), e.getSrcPort(),
                e.getDstIp(), e.getDstPort(), e.getEventType(), e.getNumberOfPorts(),
                e.isSyn(), e.isAck(), e.isFin(), e.isRst()
        );
    }

    // --- Handlers ---
    private class StaticFileHandler implements HttpHandler {
        private final String resourcePath;
        private final String contentType;

        StaticFileHandler(String resourcePath, String contentType) {
            this.resourcePath = resourcePath;
            this.contentType = contentType;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
                if (is == null) {
                    sendResponse(exchange, 404, "text/plain", "Recurso no encontrado: " + resourcePath);
                    return;
                }

                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] data = new byte[4096];
                int nRead;
                while ((nRead = is.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }

                byte[] responseBytes = buffer.toByteArray();
                exchange.getResponseHeaders().set("Content-Type", contentType);
                exchange.sendResponseHeaders(200, responseBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                }
            }
        }
    }

    private class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "text/plain", "Método no permitido");
                return;
            }

            // Leer body del request
            String body;
            try (InputStream is = exchange.getRequestBody()) {
                body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            // Parsear username y password del body (formato: username=X&password=Y)
            String username = null;
            String password = null;

            for (String param : body.split("&")) {
                String[] kv = param.split("=", 2);
                if (kv.length == 2) {
                    String key = java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    if ("username".equals(key)) {
                        username = value;
                    } else if ("password".equals(key)) {
                        password = value;
                    }
                }
            }

            if (authManager.authenticate(username, password)) {
                String token = authManager.createSession();

                exchange.getResponseHeaders().set("Set-Cookie",
                        "IDS_SESSION=" + token + "; Path=/; HttpOnly; SameSite=Strict");
                sendResponse(exchange, 200, "application/json; charset=UTF-8",
                        "{\"status\":\"OK\",\"message\":\"Autenticación exitosa\"}");
                logger.info("Login exitoso para usuario: {}", username);
            } else {
                sendResponse(exchange, 401, "application/json; charset=UTF-8",
                        "{\"status\":\"UNAUTHORIZED\",\"message\":\"Credenciales incorrectas\"}");
                logger.warn("Intento de login fallido para usuario: {}", username);
            }
        }
    }

    private class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "text/plain", "Método no permitido");
                return;
            }

            String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
            String token = AuthManager.extractSessionToken(cookieHeader);

            if (token != null) {
                authManager.invalidateSession(token);
            }

            // Limpiar cookie
            exchange.getResponseHeaders().set("Set-Cookie",
                    "IDS_SESSION=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
            sendResponse(exchange, 200, "application/json; charset=UTF-8",
                    "{\"status\":\"OK\",\"message\":\"Sesión cerrada\"}");
        }
    }

    private class StatsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            int workerCount = (detectionEngine != null) ? detectionEngine.getWorkerCount() : 0;
            int queueCapacity = (detectionEngine != null) ? detectionEngine.getQueueCapacity() : 0;
            long processed = (detectionEngine != null) ? detectionEngine.getProcessedCount() : 0;
            long dropped = (detectionEngine != null) ? detectionEngine.getDroppedCount() : 0;
            int alertCount = (alertHistory != null) ? alertHistory.getAlertCount() : 0;

            StringBuilder queueSizes = new StringBuilder("[");
            if (detectionEngine != null) {
                for (int i = 0; i < workerCount; i++) {
                    if (i > 0) queueSizes.append(",");
                    queueSizes.append(detectionEngine.getQueueSize(i));
                }
            }
            queueSizes.append("]");

            String json = String.format(
                    "{\"workerCount\":%d,\"queueCapacity\":%d,\"processedCount\":%d,\"droppedCount\":%d,\"alertCount\":%d,\"queueSizes\":%s}",
                    workerCount, queueCapacity, processed, dropped, alertCount, queueSizes
            );

            sendResponse(exchange, 200, "application/json; charset=UTF-8", json);
        }
    }

    private class AlertsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if ("DELETE".equals(method)) {
                if (alertHistory != null) {
                    String query = exchange.getRequestURI().getQuery();
                    if (query != null && query.contains("action=clear")) {
                        alertHistory.clear();
                    } else if (query != null && query.contains("ts=")) {
                        String ts = query.split("ts=")[1].split("&")[0];
                        alertHistory.removeAlert(ts, null, -1);
                    } else {
                        alertHistory.clear();
                    }
                }
                sendResponse(exchange, 200, "application/json; charset=UTF-8", "{\"status\":\"OK\"}");
                return;
            }

            List<Event> alerts = (alertHistory != null) ? alertHistory.getRecentAlerts() : List.of();
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < alerts.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(eventToJson(alerts.get(i)));
            }
            sb.append("]");

            sendResponse(exchange, 200, "application/json; charset=UTF-8", sb.toString());
        }
    }

    private class SseStreamHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream; charset=UTF-8");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");

            exchange.sendResponseHeaders(200, 0);
            OutputStream os = exchange.getResponseBody();
            sseClients.add(os);

            // Mensaje inicial de bienvenida
            String welcome = "data: {\"type\":\"CONNECTED\"}\n\n";
            os.write(welcome.getBytes(StandardCharsets.UTF_8));
            os.flush();
        }
    }

    private class SimulateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "text/plain", "Método no permitido");
                return;
            }

            String query = exchange.getRequestURI().getQuery();
            String type = "portscan";
            if (query != null && query.contains("type=")) {
                type = query.split("type=")[1].split("&")[0].toLowerCase();
            }

            if (detectionEngine != null) {
                switch (type) {
                    case "portscan":
                        // Simular 15 puertos destino diferentes desde la misma IP
                        for (int p = 1; p <= 15; p++) {
                            Event e = new Event();
                            e.setTimestamp(Instant.now());
                            e.setSrcIp("10.0.0.99");
                            e.setDstIp("192.168.1.10");
                            e.setSrcPort(34567);
                            e.setDstPort(p * 100);
                            e.setProtocol("TCP");
                            detectionEngine.submit(e);
                        }
                        break;
                    case "synflood":
                        // Simular 50 paquetes SYN
                        for (int i = 1; i <= 50; i++) {
                            Event e = new Event();
                            e.setTimestamp(Instant.now());
                            e.setSrcIp("10.0.0." + (i % 5 + 1));
                            e.setDstIp("192.168.1.50");
                            e.setSrcPort(40000 + i);
                            e.setDstPort(443);
                            e.setProtocol("TCP");
                            e.setSyn(true);
                            e.setAck(false);
                            detectionEngine.submit(e);
                        }
                        break;
                    case "bruteforce":
                        // Simular 20 intentos de conexión a SSH (puerto 22)
                        for (int i = 1; i <= 20; i++) {
                            Event e = new Event();
                            e.setTimestamp(Instant.now());
                            e.setSrcIp("10.0.0.88");
                            e.setDstIp("192.168.1.20");
                            e.setSrcPort(50000 + i);
                            e.setDstPort(22); // SSH
                            e.setProtocol("TCP");
                            e.setSyn(true);
                            e.setAck(false);
                            detectionEngine.submit(e);
                        }
                        break;
                }
            }

            sendResponse(exchange, 200, "application/json", "{\"status\":\"OK\",\"simulated\":\"" + type + "\"}");
        }
    }

    private class MonitorHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();

            if ("GET".equals(method)) {
                // Devolver estado actual del monitoreo
                String state = (captureController != null) ? captureController.getState().name() : "UNAVAILABLE";
                sendResponse(exchange, 200, "application/json; charset=UTF-8",
                        "{\"state\":\"" + state + "\"}");
                return;
            }

            if (!"POST".equals(method)) {
                sendResponse(exchange, 405, "text/plain", "Método no permitido");
                return;
            }

            if (captureController == null) {
                sendResponse(exchange, 503, "application/json",
                        "{\"status\":\"ERROR\",\"message\":\"CaptureController no disponible\"}");
                return;
            }

            String query = exchange.getRequestURI().getQuery();
            String action = "status";
            if (query != null && query.contains("action=")) {
                action = query.split("action=")[1].split("&")[0].toLowerCase();
            }

            boolean result;
            switch (action) {
                case "start":
                    result = captureController.start();
                    break;
                case "stop":
                    result = captureController.stop();
                    break;
                case "restart":
                    result = captureController.restart();
                    break;
                default:
                    sendResponse(exchange, 400, "application/json",
                            "{\"status\":\"ERROR\",\"message\":\"Acción no válida: " + action + "\"}");
                    return;
            }

            String state = captureController.getState().name();
            sendResponse(exchange, 200, "application/json; charset=UTF-8",
                    "{\"status\":\"OK\",\"action\":\"" + action + "\",\"result\":" + result + ",\"state\":\"" + state + "\"}");
        }
    }

    private void sendResponse(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
