package com.ip2cidr.util;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CidrUtilsTest {

    @Test
    void testIpv4CidrContains() {
        CidrBlock block = CidrBlock.parse("192.0.2.15/24");
        assertEquals("192.0.2.0/24", block.getCidr());
        assertEquals("192.0.2.0 - 192.0.2.255", block.toRangeString());

        assertTrue(block.contains("192.0.2.0"));
        assertTrue(block.contains("192.0.2.1"));
        assertTrue(block.contains("192.0.2.255"));
        assertFalse(block.contains("192.0.1.255"));
        assertFalse(block.contains("192.0.3.0"));
        assertFalse(block.contains("2001:db8::1"));
    }

    @Test
    void testIpv6CidrContains() {
        CidrBlock block = CidrBlock.parse("2001:db8:abcd:0012::1/48");
        assertTrue(block.isIpv6());
        assertEquals(48, block.getPrefixLength());

        assertTrue(block.contains("2001:db8:abcd::"));
        assertTrue(block.contains("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff"));
        assertFalse(block.contains("2001:db8:abce::1"));
        assertFalse(block.contains("192.0.2.1"));
    }

    @Test
    void testRangeToCidrsSingleBlock() {
        List<CidrBlock> blocks = CidrUtils.rangeToCidrs("203.0.113.0", "203.0.113.255");
        assertEquals(1, blocks.size());
        assertEquals("203.0.113.0/24", blocks.getFirst().getCidr());
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
    void testInvalidIpAndCidrThrows() {
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseIpAddress("999.999.999.999"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.parseCidr("192.0.2.0/33"));
        assertThrows(IllegalArgumentException.class, () -> CidrUtils.rangeToCidrs("192.0.2.10", "192.0.2.1"));
    }
}

