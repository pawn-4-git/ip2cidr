package com.ip2cidr.util;

import com.ip2cidr.model.Cidr;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CidrUtilsTest {

    @Test
    void testIpv4CidrContainsAndGetters() {
        CidrBlock block = CidrBlock.parse("192.0.2.15/24");
        assertEquals("192.0.2.0/24", block.getCidr());
        assertEquals("192.0.2.0/24", block.toString());
        assertEquals(new Cidr("192.0.2.0", 24), block.toCidr());
        assertEquals("192.0.2.0", block.getNetworkAddress().getHostAddress());
        assertEquals("192.0.2.255", block.getBroadcastAddress().getHostAddress());
        assertEquals(24, block.getPrefixLength());
        assertEquals(32, block.getMaxBits());
        assertFalse(block.isIpv6());
        assertEquals("192.0.2.0 - 192.0.2.255", block.toRangeString());
        assertTrue(block.getStartValue().compareTo(block.getEndValue()) < 0);

        assertTrue(block.contains("192.0.2.0"));
        assertTrue(block.contains("192.0.2.1"));
        assertTrue(block.contains("192.0.2.255"));
        assertFalse(block.contains("192.0.1.255"));
        assertFalse(block.contains("192.0.3.0"));
        assertFalse(block.contains("2001:db8::1"));
        assertFalse(block.contains((String) null));
        assertFalse(block.contains("   "));
        assertFalse(block.contains("invalid-ip"));
        assertFalse(block.contains((InetAddress) null));
    }

    @Test
    void testIpv6CidrContains() {
        CidrBlock block = CidrBlock.parse("2001:db8:abcd:0012::1/48");
        assertTrue(block.isIpv6());
        assertEquals(48, block.getPrefixLength());
        assertEquals(128, block.getMaxBits());

        assertTrue(block.contains("2001:db8:abcd::"));
        assertTrue(block.contains("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff"));
        assertFalse(block.contains("2001:db8:abce::1"));
        assertFalse(block.contains("192.0.2.1"));
    }

    @Test
    void testRangeToCidrsSingleBlockAndZeroStart() {
        List<CidrBlock> blocks = CidrUtils.rangeToCidrs("203.0.113.0", "203.0.113.255");
        assertEquals(1, blocks.size());
        assertEquals("203.0.113.0/24", blocks.getFirst().getCidr());

        // 0.0.0.0 開始（current.signum() == 0 分岐）と /32（hostBits == 0 分岐）
        List<CidrBlock> zeroBlocks = CidrUtils.rangeToCidrs("0.0.0.0", "0.0.0.255");
        assertEquals(1, zeroBlocks.size());
        assertEquals("0.0.0.0/24", zeroBlocks.getFirst().getCidr());

        CidrBlock hostBlock = CidrUtils.parseCidr("255.255.255.255/32");
        assertEquals("255.255.255.255/32", hostBlock.getCidr());
        assertTrue(hostBlock.contains("255.255.255.255"));
    }

    @Test
    void testRangeToCidrsMultipleBlocks() {
        List<CidrBlock> blocks = CidrUtils.rangeToCidrs("192.0.2.0", "192.0.4.255");
        assertEquals(2, blocks.size());
        assertEquals("192.0.2.0/23", blocks.get(0).getCidr());
        assertEquals("192.0.4.0/24", blocks.get(1).getCidr());
    }

    @Test
    void testIpv6RangeToCidrs() {
        List<CidrBlock> blocks = CidrUtils.rangeToCidrs(
                "2001:db8::",
                "2001:db8:0:ffff:ffff:ffff:ffff:ffff");
        assertEquals(1, blocks.size());
        assertEquals(48, blocks.getFirst().getPrefixLength());
        assertTrue(blocks.getFirst().contains("2001:db8:0:1234::1"));
    }

    @Test
    void testParseIpAddressZoneIndexAndIsValidIpAddress() {
        InetAddress zoned = CidrUtils.parseIpAddress("fe80::1%lo0");
        assertEquals(CidrUtils.parseIpAddress("fe80::1"), zoned);

        assertTrue(CidrUtils.isValidIpAddress("192.0.2.1"));
        assertTrue(CidrUtils.isValidIpAddress("2001:db8::1"));
        assertFalse(CidrUtils.isValidIpAddress(null));
        assertFalse(CidrUtils.isValidIpAddress("   "));
        assertFalse(CidrUtils.isValidIpAddress("999.999.999.999"));
        assertFalse(CidrUtils.isValidIpAddress("%lo0"));
    }

    @Test
    void testCompareIpAddresses() {
        InetAddress ipv4Low = CidrUtils.parseIpAddress("10.0.0.1");
        InetAddress ipv4High = CidrUtils.parseIpAddress("192.0.2.1");
        InetAddress ipv6 = CidrUtils.parseIpAddress("2001:db8::1");

        assertTrue(CidrUtils.compareIpAddresses(ipv4Low, ipv4High) < 0);
        assertTrue(CidrUtils.compareIpAddresses(ipv4High, ipv4Low) > 0);
        assertEquals(0, CidrUtils.compareIpAddresses(ipv4Low, ipv4Low));
        assertTrue(CidrUtils.compareIpAddresses(ipv4High, ipv6) < 0);
        assertTrue(CidrUtils.compareIpAddresses(ipv6, ipv4Low) > 0);
    }

    @Test
    void testShortIpv4Expansion() {
        assertEquals("10.0.0.0/8", CidrUtils.parseCidr("10/8").getCidr());
        assertEquals("192.168.0.0/16", CidrUtils.parseCidr("192.168/16").getCidr());
        assertEquals("192.168.1.0/24", CidrUtils.parseCidr("192.168.1/24").getCidr());
    }

    @Test
    void testCidrBlockCompareToEqualsAndHashCode() {
        CidrBlock b24 = CidrBlock.parse("192.0.2.0/24");
        CidrBlock b24Dup = CidrBlock.parse("192.0.2.99/24");
        CidrBlock b25 = CidrBlock.parse("192.0.2.0/25");
        CidrBlock bOtherStart = CidrBlock.parse("198.51.100.0/24");
        CidrBlock bIpv6 = CidrBlock.parse("2001:db8::/32");
        CidrBlock bIpv6Prefix24 = CidrBlock.parse("2001:db8::/24");

        assertEquals(b24, b24);
        assertEquals(b24, b24Dup);
        assertEquals(b24.hashCode(), b24Dup.hashCode());
        assertNotEquals(b24, b25);
        assertNotEquals(b24, bOtherStart);
        assertNotEquals(b24, bIpv6);
        assertNotEquals(b24, bIpv6Prefix24);
        assertNotEquals(b24, "not-a-block");
        assertNotEquals(b24, null);

        assertEquals(0, b24.compareTo(b24Dup));
        assertTrue(b24.compareTo(b25) > 0); // 同じ開始アドレスならプレフィックス長が長い方が先
        assertTrue(b25.compareTo(b24) < 0);
        assertTrue(b24.compareTo(bOtherStart) < 0);
        assertTrue(bOtherStart.compareTo(b24) > 0);
        assertTrue(b24.compareTo(bIpv6) < 0);
        assertTrue(bIpv6.compareTo(b24) > 0);
    }

    @Test
    void testInvalidIpAndCidrThrows() {
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseIpAddress(null));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseIpAddress("   "));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseIpAddress("999.999.999.999"));

        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr(null));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("   "));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("192.0.2.0"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("/24"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("192.0.2.0/"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("192.0.2.0/abc"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("192.0.2.0/-1"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("192.0.2.0/33"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("2001:db8::/129"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("192..1/24"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("192.abc/16"));

        assertThrows(IllegalArgumentException.class, () -> CidrUtils.rangeToCidrs("192.0.2.10", "192.0.2.1"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.rangeToCidrs("192.0.2.1", "2001:db8::1"));
    }
}

