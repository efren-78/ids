package org.example.ids.ui;

import org.example.ids.Event;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Almacén en memoria acotado y concurrente para el historial de alertas detectadas.
 *
 * Soporta registro de listeners reactivos para Server-Sent Events (SSE).
 */
public class AlertHistory {

    private static final int DEFAULT_MAX_CAPACITY = 200;

    private final int maxCapacity;
    private final ConcurrentLinkedDeque<Event> alerts = new ConcurrentLinkedDeque<>();
    private final List<Consumer<Event>> listeners = new CopyOnWriteArrayList<>();

    public AlertHistory() {
        this(DEFAULT_MAX_CAPACITY);
    }

    public AlertHistory(int maxCapacity) {
        this.maxCapacity = Math.max(10, maxCapacity);
    }

    public void addAlert(Event event) {
        if (event == null) {
            return;
        }

        alerts.addFirst(event);
        while (alerts.size() > maxCapacity) {
            alerts.pollLast();
        }

        // Notificar a clientes SSE conectados
        for (Consumer<Event> listener : listeners) {
            try {
                listener.accept(event);
            } catch (Exception ignored) {
            }
        }
    }

    public List<Event> getRecentAlerts() {
        return new ArrayList<>(alerts);
    }

    public int getAlertCount() {
        return alerts.size();
    }

    public void addListener(Consumer<Event> listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(Consumer<Event> listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    public boolean removeAlert(String timestamp, String srcIp, int srcPort) {
        return alerts.removeIf(e -> 
            (timestamp == null || (e.getTimestamp() != null && e.getTimestamp().toString().equals(timestamp))) &&
            (srcIp == null || (e.getSrcIp() != null && e.getSrcIp().equals(srcIp))) &&
            (srcPort <= 0 || e.getSrcPort() == srcPort)
        );
    }

    public void clear() {
        alerts.clear();
    }
}
