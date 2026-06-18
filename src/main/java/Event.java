import java.sql.*;

public class Event {
    // Enum que define el tipo de evento
    public enum EventType {
        NORMAL,
        PORT_SCAN,
        SYN_FLOOD,
        SUSPICIOUS_CONNECTION
    }

    public Timestamp timestamp;
    public String srcIp;
    public String dstIp;
    public int srcPort;
    public int dstPort;
    public EventType event_type;
    public String protocol;
    public int number_of_ports;
    public boolean syn, ack, fin, rst;

    // Constructor por defecto
    public Event() {
        this.event_type = EventType.NORMAL;
        this.number_of_ports = 1;
    }

    // Constructor
    public Event(Timestamp timestamp, String srcIp, String dstIp, int srcPort, int dstPort, EventType event_type,
            int number_of_ports, String protocol, boolean syn, boolean ack, boolean fin, boolean rst) {
        this.timestamp = timestamp;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.event_type = event_type;
        this.protocol = protocol;
        this.number_of_ports = number_of_ports;
        this.syn = syn;
        this.ack = ack;
        this.fin = fin;
        this.rst = rst;
    }

    // Metodo que convierte el evento a string
    @Override
    public String toString() {
        return String.format(
                "[%s] [%s] %s:%d -> %s:%d | tipo=%s | puertos_distintos=%d | SYN=%b ACK=%b FIN=%b RST=%b",
                timestamp, protocol, srcIp, srcPort, dstIp, dstPort,
                event_type, number_of_ports, syn, ack, fin, rst);
    }
}
