package org.example.ids.auth;

import org.example.ids.IdsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Gestor centralizado de autenticación y sesiones del Dashboard IDS.
 *
 * Administra sesiones basadas en tokens opacos (cookies) con expiración configurable.
 * Las credenciales se obtienen desde {@link IdsConfig} y las sesiones activas
 * se almacenan en memoria con soporte concurrente.
 */
public class AuthManager {

    private static final Logger logger = LoggerFactory.getLogger(AuthManager.class);
    private static final int TOKEN_BYTE_LENGTH = 32;

    private final String validUsername;
    private final String validPassword;
    private final long sessionTimeoutMs;
    private final boolean authEnabled;

    private final SecureRandom secureRandom = new SecureRandom();
    private final ConcurrentHashMap<String, Instant> activeSessions = new ConcurrentHashMap<>();

    public AuthManager(IdsConfig config) {
        IdsConfig cfg = (config != null) ? config : IdsConfig.getInstance();
        this.authEnabled = cfg.isAuthEnabled();
        this.validUsername = cfg.getAuthUsername();
        this.validPassword = cfg.getAuthPassword();
        this.sessionTimeoutMs = cfg.getAuthSessionTimeoutMinutes() * 60_000L;

        if (authEnabled) {
            logger.info("Autenticación del Dashboard habilitada (usuario: {}, timeout: {} min)",
                    validUsername, cfg.getAuthSessionTimeoutMinutes());
        } else {
            logger.info("Autenticación del Dashboard deshabilitada.");
        }
    }

    /**
     * Indica si la autenticación está habilitada en la configuración.
     */
    public boolean isAuthEnabled() {
        return authEnabled;
    }

    /**
     * Valida las credenciales proporcionadas contra las configuradas.
     *
     * @param username nombre de usuario
     * @param password contraseña
     * @return true si las credenciales son válidas
     */
    public boolean authenticate(String username, String password) {
        if (username == null || password == null) {
            return false;
        }
        return validUsername.equals(username.trim()) && validPassword.equals(password);
    }

    /**
     * Crea una nueva sesión activa y retorna el token opaco generado.
     *
     * @return token de sesión seguro codificado en Base64 URL-safe
     */
    public String createSession() {
        byte[] tokenBytes = new byte[TOKEN_BYTE_LENGTH];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        activeSessions.put(token, Instant.now());
        logger.debug("Nueva sesión creada. Sesiones activas: {}", activeSessions.size());
        return token;
    }

    /**
     * Valida si un token de sesión es válido y no ha expirado.
     *
     * @param token el token de sesión a validar
     * @return true si la sesión existe y no ha expirado
     */
    public boolean isValidSession(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }

        Instant createdAt = activeSessions.get(token);
        if (createdAt == null) {
            return false;
        }

        if (Instant.now().toEpochMilli() - createdAt.toEpochMilli() > sessionTimeoutMs) {
            activeSessions.remove(token);
            logger.debug("Sesión expirada y eliminada.");
            return false;
        }

        return true;
    }

    /**
     * Invalida una sesión existente (logout).
     *
     * @param token el token de sesión a invalidar
     */
    public void invalidateSession(String token) {
        if (token != null) {
            activeSessions.remove(token);
            logger.debug("Sesión invalidada. Sesiones activas: {}", activeSessions.size());
        }
    }

    /**
     * Purga todas las sesiones expiradas de la memoria.
     * Diseñado para ser invocado periódicamente por un scheduler externo.
     */
    public void purgeExpiredSessions() {
        Iterator<Map.Entry<String, Instant>> it = activeSessions.entrySet().iterator();
        int purged = 0;
        long now = Instant.now().toEpochMilli();

        while (it.hasNext()) {
            Map.Entry<String, Instant> entry = it.next();
            if (now - entry.getValue().toEpochMilli() > sessionTimeoutMs) {
                it.remove();
                purged++;
            }
        }

        if (purged > 0) {
            logger.debug("Purgadas {} sesiones expiradas. Sesiones activas: {}", purged, activeSessions.size());
        }
    }

    /**
     * Retorna el número de sesiones activas actualmente en memoria.
     */
    public int getActiveSessionCount() {
        return activeSessions.size();
    }

    /**
     * Extrae el token de sesión (cookie IDS_SESSION) del header Cookie HTTP.
     *
     * @param cookieHeader el valor del header "Cookie" de la solicitud HTTP
     * @return el token de sesión o null si no se encontró
     */
    public static String extractSessionToken(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return null;
        }

        for (String cookie : cookieHeader.split(";")) {
            String trimmed = cookie.trim();
            if (trimmed.startsWith("IDS_SESSION=")) {
                String value = trimmed.substring("IDS_SESSION=".length());
                return value.isBlank() ? null : value;
            }
        }

        return null;
    }
}
