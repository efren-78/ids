package org.example.ids.detectors;

import org.example.ids.IdsConfig;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class DetectorLoaderTest {

    @Test
    void loadDetectorsDescubreEInstanciaTodosLosDetectoresDelPaquete() {
        IdsConfig config = IdsConfig.getInstance();
        List<Detector> detectors = DetectorLoader.loadDetectors(config);

        assertNotNull(detectors);
        assertFalse(detectors.isEmpty(), "Debe cargar al menos los detectores estándar del sistema");

        Set<Class<? extends Detector>> loadedClasses = detectors.stream()
                .map(Detector::getClass)
                .collect(Collectors.toSet());

        assertTrue(loadedClasses.contains(PortScanDetector.class), "Debe incluir PortScanDetector");
        assertTrue(loadedClasses.contains(SynFloodDetector.class), "Debe incluir SynFloodDetector");
        assertTrue(loadedClasses.contains(BruteForceDetector.class), "Debe incluir BruteForceDetector");
        assertTrue(loadedClasses.contains(SuspiciousPortDetector.class), "Debe incluir SuspiciousPortDetector");
    }

    @Test
    void scanForDetectorClassesExcluyeInterfacesYClasesNoValidas() {
        Set<Class<? extends Detector>> classes = DetectorLoader.scanForDetectorClasses("org.example.ids.detectors");

        assertNotNull(classes);
        // Debe contener las implementaciones concretas
        assertTrue(classes.contains(PortScanDetector.class));
        assertTrue(classes.contains(SynFloodDetector.class));
        assertTrue(classes.contains(BruteForceDetector.class));
        assertTrue(classes.contains(SuspiciousPortDetector.class));

        // NO debe contener la interfaz Detector.class ni clases utilitarias como DetectorLoader.class
        for (Class<?> clazz : classes) {
            assertFalse(clazz.isInterface(), "No debe incluir interfaces");
            assertTrue(Detector.class.isAssignableFrom(clazz), "Todas deben implementar Detector");
        }
    }

    @Test
    void paqueteInexistenteRetornaListaVaciaSinExcepcion() {
        List<Detector> detectors = DetectorLoader.loadDetectors("org.example.ids.nonexistent", IdsConfig.getInstance());
        assertNotNull(detectors);
        assertTrue(detectors.isEmpty());
    }
}
