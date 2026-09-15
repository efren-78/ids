package org.example.ids.ui;

import org.example.ids.DetectionEngine;
import org.example.ids.Event;
import org.example.ids.IdsConfig;
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

    @BeforeEach
    void setUp() throws IOException {
        Properties props = new Properties();
        props.setProperty("ids.engine.worker.count", "2");
        props.setProperty("ids.engine.queue.capacity", "50");
        IdsConfig config = new IdsConfig(props);

        engine = new DetectionEngine(config);
        alertHistory = new AlertHistory(50);
        engine.setAlertListener(alertHistory::addAlert);

        // Usar puerto de prueba no estándar para evitar conflictos
        port = 18088;
        server = new DashboardServer(port, engine, alertHistory);
        server.start();

        client = HttpClient.newHttpClient();
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

    @Test
    void testServeIndexHtml() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/"))
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
                .GET()
                .build();
        HttpResponse<String> cssResp = client.send(cssReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, cssResp.statusCode());
        assertTrue(cssResp.headers().firstValue("Content-Type").orElse("").contains("text/css"));

        HttpRequest jsReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/app.js"))
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
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("\"status\":\"OK\""));
        assertTrue(resp.body().contains("bruteforce"));
    }
}
