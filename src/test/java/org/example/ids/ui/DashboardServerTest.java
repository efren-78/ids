package org.example.ids.ui;

import org.example.ids.DetectionEngine;
import org.example.ids.Event;
import org.example.ids.IdsConfig;
import org.example.ids.auth.AuthManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class DashboardServerTest {

    private DetectionEngine engine;
    private AlertHistory alertHistory;
    private DashboardServer server;
    private int port;
    private HttpClient client;
    private String sessionCookie;

    @BeforeEach
    void setUp() throws IOException, InterruptedException {
        Properties props = new Properties();
        props.setProperty("ids.engine.worker.count", "2");
        props.setProperty("ids.engine.queue.capacity", "50");
        props.setProperty("ids.auth.enabled", "true");
        props.setProperty("ids.auth.username", "testuser");
        props.setProperty("ids.auth.password", "testpass");
        props.setProperty("ids.auth.session.timeout.minutes", "30");
        IdsConfig config = new IdsConfig(props);

        engine = new DetectionEngine(config);
        alertHistory = new AlertHistory(50);
        engine.setAlertListener(alertHistory::addAlert);

        // Usar puerto de prueba no estándar para evitar conflictos
        port = 18088;
        server = new DashboardServer(port, engine, alertHistory, null, config);
        server.start();

        client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        // Obtener cookie de sesión autenticada para los tests protegidos
        sessionCookie = loginAndGetCookie("testuser", "testpass");
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop();
        }
        if (engine != null) {
            engine.shutdown();
        }
    }

    private String loginAndGetCookie(String username, String password) throws IOException, InterruptedException {
        String body = "username=" + username + "&password=" + password;
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        // Extraer Set-Cookie header
        String setCookie = resp.headers().firstValue("Set-cookie").orElse(
                resp.headers().firstValue("set-cookie").orElse(null)
        );
        assertNotNull(setCookie, "El servidor debe retornar Set-Cookie con el token de sesión");
        assertTrue(setCookie.contains("IDS_SESSION="));

        // Extraer solo la parte del cookie para usarla en requests posteriores
        return setCookie.split(";")[0];
    }

    // --- Tests de autenticación ---

    @Test
    void rutaProtegidaSinSesionRetorna302Redirect() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/"))
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(302, resp.statusCode());
        assertTrue(resp.headers().firstValue("Location").orElse("").contains("/login"));
    }

    @Test
    void apiProtegidaSinSesionRetorna401() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/stats"))
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(401, resp.statusCode());
        assertTrue(resp.body().contains("UNAUTHORIZED"));
    }

    @Test
    void loginPageAccesibleSinAutenticacion() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/login"))
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, resp.statusCode());
        assertTrue(resp.headers().firstValue("Content-Type").orElse("").contains("text/html"));
    }

    @Test
    void loginFallidoRetorna401() throws IOException, InterruptedException {
        String body = "username=hacker&password=wrong";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(401, resp.statusCode());
        assertTrue(resp.body().contains("UNAUTHORIZED"));
    }

    // --- Tests del dashboard autenticado ---

    @Test
    void testServeIndexHtml() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/"))
                .header("Cookie", sessionCookie)
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, resp.statusCode());
        assertTrue(resp.headers().firstValue("Content-Type").orElse("").contains("text/html"));
        assertTrue(resp.body().contains("COMMAND CENTER"));
    }

    @Test
    void testServeCssAndJs() throws IOException, InterruptedException {
        HttpRequest cssReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/style.css"))
                .header("Cookie", sessionCookie)
                .GET()
                .build();
        HttpResponse<String> cssResp = client.send(cssReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, cssResp.statusCode());
        assertTrue(cssResp.headers().firstValue("Content-Type").orElse("").contains("text/css"));

        HttpRequest jsReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/app.js"))
                .header("Cookie", sessionCookie)
                .GET()
                .build();
        HttpResponse<String> jsResp = client.send(jsReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, jsResp.statusCode());
        assertTrue(jsResp.headers().firstValue("Content-Type").orElse("").contains("javascript"));
    }

    @Test
    void testApiStats() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/stats"))
                .header("Cookie", sessionCookie)
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, resp.statusCode());
        assertTrue(resp.headers().firstValue("Content-Type").orElse("").contains("application/json"));
        assertTrue(resp.body().contains("\"workerCount\":2"));
        assertTrue(resp.body().contains("\"queueCapacity\":50"));
    }

    @Test
    void testApiAlertsAndHistory() throws IOException, InterruptedException {
        Event alert = new Event();
        alert.setTimestamp(Instant.now());
        alert.setSrcIp("192.168.1.100");
        alert.setDstIp("10.0.0.1");
        alert.setDstPort(80);
        alert.setProtocol("TCP");
        alert.setEventType(Event.EventType.PORT_SCAN);
        alert.setNumberOfPorts(15);

        alertHistory.addAlert(alert);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/alerts"))
                .header("Cookie", sessionCookie)
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("PORT_SCAN"));
        assertTrue(resp.body().contains("192.168.1.100"));
    }

    @Test
    void testApiSimulate() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/simulate?type=bruteforce"))
                .header("Cookie", sessionCookie)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("\"status\":\"OK\""));
        assertTrue(resp.body().contains("bruteforce"));
    }

    @Test
    void testLogout() throws IOException, InterruptedException {
        // Verificar que la sesión funciona antes del logout
        HttpRequest statsReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/stats"))
                .header("Cookie", sessionCookie)
                .GET()
                .build();
        assertEquals(200, client.send(statsReq, HttpResponse.BodyHandlers.ofString()).statusCode());

        // Ejecutar logout
        HttpRequest logoutReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/logout"))
                .header("Cookie", sessionCookie)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> logoutResp = client.send(logoutReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, logoutResp.statusCode());

        // Verificar que la sesión ya no es válida después del logout
        HttpResponse<String> afterLogout = client.send(statsReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, afterLogout.statusCode());
    }
}
