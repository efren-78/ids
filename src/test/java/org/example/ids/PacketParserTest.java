package org.example.ids;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class PacketParserTest {

    private PacketParser parser;

    @BeforeEach
    void setUp() {
        parser = new PacketParser();
    }

    @Test
    void parseNullPacketReturnsNull() {
        assertNull(parser.parse(null, Instant.now()));
    }

    @Test
    void parseNonIpPacketReturnsNull() {
        // Paquete Ethernet sin capa IPv4 / IPv6
        EthernetPacket eth = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:11:22:33:44:55"))
                .dstAddr(MacAddress.getByName("66:77:88:99:aa:bb"))
                .type(EtherType.ARP)
                .paddingAtBuild(true)
                .build();

        assertNull(parser.parse(eth, Instant.now()));
    }

    @Test
    void parseValidIpv4TcpPacketReturnsEvent() throws UnknownHostException {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.100");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.1");

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) 12345))
                .dstPort(TcpPort.HTTP)
                .srcAddr(src)
                .dstAddr(dst)
                .syn(true)
                .ack(false)
                .rst(false)
                .fin(false)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos((org.pcap4j.packet.IpV4Packet.IpV4Tos) () -> (byte) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(tcpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        Packet packet = ipBuilder.build();
        Instant now = Instant.now();

        Event event = parser.parse(packet, now);

        assertNotNull(event);
        assertEquals("192.168.1.100", event.getSrcIp());
        assertEquals("192.168.1.1", event.getDstIp());
        assertEquals("TCP", event.getProtocol());
        assertEquals(12345, event.getSrcPort());
        assertEquals(80, event.getDstPort());
        assertTrue(event.isSyn());
        assertFalse(event.isAck());
        assertEquals(now, event.getTimestamp());
    }

    @Test
    void parseValidIpv4UdpPacketReturnsEvent() throws UnknownHostException {
        Inet4Address src = (Inet4Address) InetAddress.getByName("10.0.0.5");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("8.8.8.8");

        UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) 53530))
                .dstPort(UdpPort.getInstance((short) 53))
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos((org.pcap4j.packet.IpV4Packet.IpV4Tos) () -> (byte) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(udpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        Packet packet = ipBuilder.build();

        Event event = parser.parse(packet, null);

        assertNotNull(event);
        assertEquals("10.0.0.5", event.getSrcIp());
        assertEquals("8.8.8.8", event.getDstIp());
        assertEquals("UDP", event.getProtocol());
        assertEquals(53530, event.getSrcPort());
        assertEquals(53, event.getDstPort());
        assertNotNull(event.getTimestamp());
    }

    @Test
    void parseValidIpv6TcpPacketReturnsEvent() throws UnknownHostException {
        Inet6Address src = (Inet6Address) InetAddress.getByName("2001:db8::1");
        Inet6Address dst = (Inet6Address) InetAddress.getByName("2001:db8::2");

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) 44321))
                .dstPort(TcpPort.HTTPS)
                .srcAddr(src)
                .dstAddr(dst)
                .syn(true)
                .ack(true)
                .rst(false)
                .fin(false)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV6Packet.Builder ipBuilder = new IpV6Packet.Builder()
                .version(IpVersion.IPV6)
                .trafficClass((org.pcap4j.packet.IpV6Packet.IpV6TrafficClass) () -> (byte) 0)
                .flowLabel((org.pcap4j.packet.IpV6Packet.IpV6FlowLabel) () -> 0)
                .nextHeader(IpNumber.TCP)
                .hopLimit((byte) 64)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(tcpBuilder)
                .correctLengthAtBuild(true);

        Packet packet = ipBuilder.build();

        Event event = parser.parse(packet, Instant.now());

        assertNotNull(event);
        assertEquals(src.getHostAddress(), event.getSrcIp());
        assertEquals(dst.getHostAddress(), event.getDstIp());
        assertEquals("TCP", event.getProtocol());
        assertEquals(44321, event.getSrcPort());
        assertEquals(443, event.getDstPort());
        assertTrue(event.isSyn());
        assertTrue(event.isAck());
    }

    @Test
    void multicastIpv4IsFilteredAsNoise() throws UnknownHostException {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.50");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("224.0.0.1");

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) 1000))
                .dstPort(TcpPort.HTTP)
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos((org.pcap4j.packet.IpV4Packet.IpV4Tos) () -> (byte) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(src)
                .dstAddr(dst) // Multicast
                .payloadBuilder(tcpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        assertNull(parser.parse(ipBuilder.build(), Instant.now()));
    }

    @Test
    void broadcastIpv4IsFilteredAsNoise() throws UnknownHostException {
        Inet4Address src = (Inet4Address) InetAddress.getByName("0.0.0.0");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("255.255.255.255");

        UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) 67))
                .dstPort(UdpPort.getInstance((short) 68))
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos((org.pcap4j.packet.IpV4Packet.IpV4Tos) () -> (byte) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr(src)
                .dstAddr(dst) // Broadcast
                .payloadBuilder(udpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        assertNull(parser.parse(ipBuilder.build(), Instant.now()));
    }

    @Test
    void multicastIpv6IsFilteredAsNoise() throws UnknownHostException {
        Inet6Address src = (Inet6Address) InetAddress.getByName("fe80::1");
        Inet6Address dst = (Inet6Address) InetAddress.getByName("ff02::1");

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) 1000))
                .dstPort(TcpPort.HTTP)
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV6Packet.Builder ipBuilder = new IpV6Packet.Builder()
                .version(IpVersion.IPV6)
                .trafficClass((org.pcap4j.packet.IpV6Packet.IpV6TrafficClass) () -> (byte) 0)
                .flowLabel((org.pcap4j.packet.IpV6Packet.IpV6FlowLabel) () -> 0)
                .nextHeader(IpNumber.TCP)
                .hopLimit((byte) 64)
                .srcAddr(src)
                .dstAddr(dst) // Multicast IPv6
                .payloadBuilder(tcpBuilder)
                .correctLengthAtBuild(true);

        assertNull(parser.parse(ipBuilder.build(), Instant.now()));
    }

    @Test
    void esRuidoDeRedDirectChecks() {
        // Null o vacíos son considerados ruido
        assertTrue(parser.esRuidoDeRed(null, false));
        assertTrue(parser.esRuidoDeRed("", false));
        assertTrue(parser.esRuidoDeRed("   ", true));

        // IPv4 Multicast y Broadcast
        assertTrue(parser.esRuidoDeRed("224.0.0.1", false));
        assertTrue(parser.esRuidoDeRed("239.255.255.250", false));
        assertTrue(parser.esRuidoDeRed("255.255.255.255", false));

        // IPv4 Unicast normal NO es ruido
        assertFalse(parser.esRuidoDeRed("192.168.1.1", false));
        assertFalse(parser.esRuidoDeRed("10.0.0.1", false));
        assertFalse(parser.esRuidoDeRed("8.8.8.8", false));

        // IPv6 Multicast (empieza con ff)
        assertTrue(parser.esRuidoDeRed("ff02::1", true));
        assertTrue(parser.esRuidoDeRed("FF05::2", true));

        // IPv6 Unicast normal NO es ruido
        assertFalse(parser.esRuidoDeRed("2001:db8::1", true));
        assertFalse(parser.esRuidoDeRed("fe80::1", true));
    }
}
