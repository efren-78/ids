package org.example.ids;

/**
 * Interfaz común para todos los detectores de intrusiones.
 *
 * Cada implementación analiza un tipo específico de anomalía
 * (port scan, SYN flood, etc.) y puede purgar su estado interno
 * cuando las ventanas de tiempo expiran.
 */
public interface Detector {

    /**
     * Analiza un evento de red y lo clasifica si detecta una anomalía.
     * Si el evento ya fue clasificado (tipo != NORMAL), la implementación
     * puede optar por no procesarlo.
     *
     * @param event el evento de red a analizar
     */
    void analyze(Event event);

    /**
     * Purga datos internos cuya ventana de tiempo ya expiró,
     * liberando memoria.
     */
    void purgeExpired();
}
