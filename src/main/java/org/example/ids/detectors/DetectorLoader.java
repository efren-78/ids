package org.example.ids.detectors;

import org.example.ids.IdsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Cargador dinámico de detectores mediante escaneo automático del classpath y reflexión.
 *
 * Permite una arquitectura 100% extensible (Open/Closed Principle): cualquier clase
 * que implemente {@link Detector} ubicada en el paquete {@code org.example.ids.detectors}
 * será descubierta e instanciada automáticamente al iniciar el motor, sin necesidad
 * de registrarla manualmente en {@link org.example.ids.DetectionEngine}.
 */
public final class DetectorLoader {

    private static final Logger logger = LoggerFactory.getLogger(DetectorLoader.class);
    private static final String DETECTORS_PACKAGE = "org.example.ids.detectors";

    private DetectorLoader() {
        // Clase de utilidad estática
    }

    /**
     * Descubre e instancia todas las implementaciones de {@link Detector} disponibles
     * en el paquete de detectores por defecto.
     *
     * @param config Configuración del IDS para inyectar en los detectores.
     * @return Lista de detectores instanciados.
     */
    public static List<Detector> loadDetectors(IdsConfig config) {
        return loadDetectors(DETECTORS_PACKAGE, config);
    }

    /**
     * Descubre e instancia todas las implementaciones de {@link Detector} en un paquete específico.
     *
     * @param packageName Paquete a escanear.
     * @param config Configuración del IDS para inyectar en los detectores.
     * @return Lista de detectores instanciados.
     */
    public static List<Detector> loadDetectors(String packageName, IdsConfig config) {
        List<Detector> detectors = new ArrayList<>();
        Set<Class<? extends Detector>> detectorClasses = scanForDetectorClasses(packageName);

        for (Class<? extends Detector> clazz : detectorClasses) {
            try {
                Detector detector = instantiateDetector(clazz, config);
                if (detector != null) {
                    detectors.add(detector);
                    logger.info("Detector cargado automáticamente: {}", clazz.getSimpleName());
                }
            } catch (Exception e) {
                logger.error("No se pudo instanciar el detector {}: {}", clazz.getName(), e.getMessage(), e);
            }
        }

        return detectors;
    }

    /**
     * Instancia un detector buscando preferentemente el constructor con {@link IdsConfig},
     * y haciendo fallback al constructor por defecto sin parámetros.
     */
    static Detector instantiateDetector(Class<? extends Detector> clazz, IdsConfig config) throws Exception {
        // 1. Intentar constructor con IdsConfig
        if (config != null) {
            try {
                Constructor<? extends Detector> configCtor = clazz.getDeclaredConstructor(IdsConfig.class);
                configCtor.setAccessible(true);
                return configCtor.newInstance(config);
            } catch (NoSuchMethodException ignored) {
                // Proceder al constructor sin parámetros
            }
        }

        // 2. Intentar constructor por defecto
        Constructor<? extends Detector> defaultCtor = clazz.getDeclaredConstructor();
        defaultCtor.setAccessible(true);
        return defaultCtor.newInstance();
    }

    /**
     * Escanea el classpath en busca de clases que implementen {@link Detector} dentro del paquete dado.
     */
    public static Set<Class<? extends Detector>> scanForDetectorClasses(String packageName) {
        Set<Class<? extends Detector>> classes = new HashSet<>();
        String packagePath = packageName.replace('.', '/');
        ClassLoader classLoader = getClassLoader();

        try {
            Enumeration<URL> resources = classLoader.getResources(packagePath);
            while (resources.hasMoreElements()) {
                URL resource = resources.nextElement();
                String protocol = resource.getProtocol();

                if ("file".equalsIgnoreCase(protocol)) {
                    String decodedPath = URLDecoder.decode(resource.getFile(), StandardCharsets.UTF_8);
                    File dir = new File(decodedPath);
                    scanDirectory(dir, packageName, classLoader, classes);
                } else if ("jar".equalsIgnoreCase(protocol)) {
                    scanJar(resource, packagePath, classLoader, classes);
                }
            }
        } catch (IOException e) {
            logger.error("Error al escanear recursos para el paquete {}: {}", packageName, e.getMessage(), e);
        }

        return classes;
    }

    private static void scanDirectory(File dir, String packageName, ClassLoader classLoader, Set<Class<? extends Detector>> classes) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) {
            return;
        }

        File[] files = dir.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.isDirectory()) {
                scanDirectory(file, packageName + "." + file.getName(), classLoader, classes);
            } else if (file.getName().endsWith(".class") && !file.getName().contains("$")) {
                String className = packageName + '.' + file.getName().substring(0, file.getName().length() - 6);
                checkAndAddDetectorClass(className, classLoader, classes);
            }
        }
    }

    private static void scanJar(URL resource, String packagePath, ClassLoader classLoader, Set<Class<? extends Detector>> classes) {
        try {
            JarURLConnection jarConn = (JarURLConnection) resource.openConnection();
            try (JarFile jarFile = jarConn.getJarFile()) {
                Enumeration<JarEntry> entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    String entryName = entry.getName();

                    if (entryName.startsWith(packagePath) && entryName.endsWith(".class") && !entryName.contains("$")) {
                        String className = entryName.replace('/', '.').substring(0, entryName.length() - 6);
                        checkAndAddDetectorClass(className, classLoader, classes);
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("No se pudo escanear el archivo JAR {}: {}", resource, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void checkAndAddDetectorClass(String className, ClassLoader classLoader, Set<Class<? extends Detector>> classes) {
        try {
            Class<?> clazz = Class.forName(className, false, classLoader);
            if (Detector.class.isAssignableFrom(clazz) && !clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers())) {
                classes.add((Class<? extends Detector>) clazz);
            }
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            logger.debug("No se pudo cargar la clase {}: {}", className, e.getMessage());
        }
    }

    private static ClassLoader getClassLoader() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        return (cl != null) ? cl : DetectorLoader.class.getClassLoader();
    }
}
