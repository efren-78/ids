package org.example.ids.detectors;

import org.example.ids.Event;

/**
 * Interfaz común para todos los detectores de intrusiones.
 *
 * Cada implementación analiza un tipo específico de anomalía
 * (port scan, SYN flood, brute force, etc.) y puede purgar su estado interno
 * cuando las ventanas de tiempo expiran.
 */
public interface Detector {

    /**
     * Analiza un evento de red y lo clasifica si detecta una anomalía.
     *
     * @param event el evento de red a analizar
     */
    void analyze(Event event);

    /**
     * Purga datos internos cuya ventana de tiempo ya expiró,
     * liberando memoria en la caché.
     */
    void purgeExpired();
}
