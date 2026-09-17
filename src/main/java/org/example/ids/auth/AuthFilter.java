package org.example.ids.auth;

import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Filtro HTTP que intercepta todas las solicitudes protegidas del Dashboard.
 *
 * Si la autenticación está habilitada, verifica la presencia y validez de
 * la cookie de sesión {@code IDS_SESSION}. Las solicitudes sin sesión válida
 * son redirigidas a la página de login (HTML) o rechazadas con 401 (API).
 *
 * Rutas exentas (accesibles sin sesión): login page, CSS del login, endpoint de login.
 */
public class AuthFilter extends Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthFilter.class);

    private static final Set<String> PUBLIC_PATHS = Set.of(
            "/login",
            "/style-login.css",
            "/api/login"
    );

    private final AuthManager authManager;

    public AuthFilter(AuthManager authManager) {
        this.authManager = authManager;
    }

    @Override
    public String description() {
        return "Filtro de autenticación del Dashboard IDS";
    }

    @Override
    public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
        // Si la autenticación está deshabilitada, dejar pasar todo
        if (!authManager.isAuthEnabled()) {
            chain.doFilter(exchange);
            return;
        }

        String path = exchange.getRequestURI().getPath();

        // Rutas públicas: no requieren autenticación
        if (isPublicPath(path)) {
            chain.doFilter(exchange);
            return;
        }

        // Extraer y validar cookie de sesión
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        String sessionToken = AuthManager.extractSessionToken(cookieHeader);

        if (sessionToken != null && authManager.isValidSession(sessionToken)) {
            // Sesión válida: continuar al handler original
            chain.doFilter(exchange);
        } else {
            // Sesión inválida o ausente
            handleUnauthorized(exchange, path);
        }
    }

    private boolean isPublicPath(String path) {
        if (path == null) {
            return false;
        }
        return PUBLIC_PATHS.contains(path);
    }

    private void handleUnauthorized(HttpExchange exchange, String path) throws IOException {
        if (isApiPath(path)) {
            // Endpoints API: responder con 401 JSON
            String body = "{\"status\":\"UNAUTHORIZED\",\"message\":\"Sesión no válida o expirada\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(401, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } else {
            // Páginas HTML: redirigir al login
            exchange.getResponseHeaders().set("Location", "/login");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        }

        logger.debug("Acceso no autorizado a '{}'. Redirigiendo/rechazando.", path);
    }

    private boolean isApiPath(String path) {
        return path != null && path.startsWith("/api/");
    }
}
