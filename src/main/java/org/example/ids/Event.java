package org.example.ids;

import java.time.Instant;

/**
 * Representa un evento de red analizado por el IDS.
 */
public class Event {

    public enum EventType {
        NORMAL,
        PORT_SCAN,
        SYN_FLOOD,
        BRUTE_FORCE,
        SUSPICIOUS_CONNECTION
    }

    private Instant timestamp;
    private String srcIp;
    private String dstIp;
    private int srcPort;
    private int dstPort;
    private EventType eventType;
    private String protocol;
    private int numberOfPorts;
    private boolean syn;
    private boolean ack;
    private boolean fin;
    private boolean rst;

    public Event() {
        this.timestamp = Instant.now();
        this.eventType = EventType.NORMAL;
        this.numberOfPorts = 1;
    }

    public Event(Instant timestamp, String srcIp, String dstIp, int srcPort, int dstPort,
                 EventType eventType, int numberOfPorts, String protocol,
                 boolean syn, boolean ack, boolean fin, boolean rst) {
        this.timestamp = timestamp;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.eventType = (eventType != null) ? eventType : EventType.NORMAL;
        this.numberOfPorts = numberOfPorts;
        this.protocol = protocol;
        this.syn = syn;
        this.ack = ack;
        this.fin = fin;
        this.rst = rst;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public EventType getEventType() {
        return eventType;
    }

    public void setEventType(EventType eventType) {
        this.eventType = eventType;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public int getNumberOfPorts() {
        return numberOfPorts;
    }

    public void setNumberOfPorts(int numberOfPorts) {
        this.numberOfPorts = numberOfPorts;
    }

    public boolean isSyn() {
        return syn;
    }

    public void setSyn(boolean syn) {
        this.syn = syn;
    }

    public boolean isAck() {
        return ack;
    }

    public void setAck(boolean ack) {
        this.ack = ack;
    }

    public boolean isFin() {
        return fin;
    }

    public void setFin(boolean fin) {
        this.fin = fin;
    }

    public boolean isRst() {
        return rst;
    }

    public void setRst(boolean rst) {
        this.rst = rst;
    }

    @Override
    public String toString() {
        return String.format(
                "[%s] [%s] %s:%d -> %s:%d | tipo=%s | puertos_distintos=%d | SYN=%b ACK=%b FIN=%b RST=%b",
                timestamp, protocol, srcIp, srcPort, dstIp, dstPort,
                eventType, numberOfPorts, syn, ack, fin, rst);
    }
}
