package org.example.ids.auth;

import org.example.ids.IdsConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class AuthManagerTest {

    private AuthManager authManager;

    @BeforeEach
    void setUp() {
        Properties props = new Properties();
        props.setProperty("ids.auth.enabled", "true");
        props.setProperty("ids.auth.username", "admin");
        props.setProperty("ids.auth.password", "secret123");
        props.setProperty("ids.auth.session.timeout.minutes", "30");
        IdsConfig config = new IdsConfig(props);
        authManager = new AuthManager(config);
    }

    @Test
    void loginExitosoConCredencialesCorrectas() {
        assertTrue(authManager.authenticate("admin", "secret123"));
    }

    @Test
    void loginFallidoConUsuarioIncorrecto() {
        assertFalse(authManager.authenticate("hacker", "secret123"));
    }

    @Test
    void loginFallidoConPasswordIncorrecto() {
        assertFalse(authManager.authenticate("admin", "wrong"));
    }

    @Test
    void loginFallidoConNull() {
        assertFalse(authManager.authenticate(null, null));
        assertFalse(authManager.authenticate("admin", null));
        assertFalse(authManager.authenticate(null, "secret123"));
    }

    @Test
    void loginAceptaUsuarioConEspacios() {
        assertTrue(authManager.authenticate("  admin  ", "secret123"));
    }

    @Test
    void crearSesionRetornaTokenNoNulo() {
        String token = authManager.createSession();
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    @Test
    void sesionRecienCreadaEsValida() {
        String token = authManager.createSession();
        assertTrue(authManager.isValidSession(token));
    }

    @Test
    void sesionInvalidadaNoEsValida() {
        String token = authManager.createSession();
        assertTrue(authManager.isValidSession(token));

        authManager.invalidateSession(token);
        assertFalse(authManager.isValidSession(token));
    }

    @Test
    void tokenInexistenteNoEsValido() {
        assertFalse(authManager.isValidSession("token-falso-inexistente"));
    }

    @Test
    void tokenNuloOVacioNoEsValido() {
        assertFalse(authManager.isValidSession(null));
        assertFalse(authManager.isValidSession(""));
        assertFalse(authManager.isValidSession("   "));
    }

    @Test
    void multipleSesionesSimultaneas() {
        String token1 = authManager.createSession();
        String token2 = authManager.createSession();
        String token3 = authManager.createSession();

        assertTrue(authManager.isValidSession(token1));
        assertTrue(authManager.isValidSession(token2));
        assertTrue(authManager.isValidSession(token3));
        assertEquals(3, authManager.getActiveSessionCount());

        authManager.invalidateSession(token2);
        assertTrue(authManager.isValidSession(token1));
        assertFalse(authManager.isValidSession(token2));
        assertTrue(authManager.isValidSession(token3));
        assertEquals(2, authManager.getActiveSessionCount());
    }

    @Test
    void sesionExpiradaEsInvalidada() throws InterruptedException {
        // Crear AuthManager con timeout de 0 minutos (expiración inmediata)
        Properties props = new Properties();
        props.setProperty("ids.auth.enabled", "true");
        props.setProperty("ids.auth.username", "admin");
        props.setProperty("ids.auth.password", "pass");
        props.setProperty("ids.auth.session.timeout.minutes", "0");
        IdsConfig config = new IdsConfig(props);
        AuthManager shortLivedManager = new AuthManager(config);

        String token = shortLivedManager.createSession();
        // Esperar 1ms para que la sesión expire (timeout=0ms)
        Thread.sleep(1);
        assertFalse(shortLivedManager.isValidSession(token));
    }

    @Test
    void purgeExpiredSessionsLimpiaSesionesExpiradas() throws InterruptedException {
        Properties props = new Properties();
        props.setProperty("ids.auth.enabled", "true");
        props.setProperty("ids.auth.username", "admin");
        props.setProperty("ids.auth.password", "pass");
        props.setProperty("ids.auth.session.timeout.minutes", "0");
        IdsConfig config = new IdsConfig(props);
        AuthManager shortLivedManager = new AuthManager(config);

        shortLivedManager.createSession();
        shortLivedManager.createSession();
        shortLivedManager.createSession();

        // Esperar 1ms para que las sesiones expiren
        Thread.sleep(1);

        // Purgar debería eliminar las 3 sesiones expiradas
        shortLivedManager.purgeExpiredSessions();
        assertEquals(0, shortLivedManager.getActiveSessionCount());
    }

    @Test
    void extractSessionTokenDeCookieValida() {
        String token = AuthManager.extractSessionToken("IDS_SESSION=abc123; other=value");
        assertEquals("abc123", token);
    }

    @Test
    void extractSessionTokenDeCookieUnica() {
        String token = AuthManager.extractSessionToken("IDS_SESSION=mytoken");
        assertEquals("mytoken", token);
    }

    @Test
    void extractSessionTokenRetornaNullSiNoExiste() {
        String token = AuthManager.extractSessionToken("other_cookie=value; another=123");
        assertNull(token);
    }

    @Test
    void extractSessionTokenRetornaNullConHeaderNulo() {
        assertNull(AuthManager.extractSessionToken(null));
        assertNull(AuthManager.extractSessionToken(""));
        assertNull(AuthManager.extractSessionToken("   "));
    }

    @Test
    void extractSessionTokenRetornaNullConCookieVacia() {
        assertNull(AuthManager.extractSessionToken("IDS_SESSION="));
        assertNull(AuthManager.extractSessionToken("IDS_SESSION=   "));
    }

    @Test
    void authDeshabilitadaReportaCorrectamente() {
        Properties props = new Properties();
        props.setProperty("ids.auth.enabled", "false");
        IdsConfig config = new IdsConfig(props);
        AuthManager disabledManager = new AuthManager(config);

        assertFalse(disabledManager.isAuthEnabled());
    }

    @Test
    void authHabilitadaReportaCorrectamente() {
        assertTrue(authManager.isAuthEnabled());
    }

    @Test
    void invalidateSessionConNullNoLanzaExcepcion() {
        assertDoesNotThrow(() -> authManager.invalidateSession(null));
    }
}
