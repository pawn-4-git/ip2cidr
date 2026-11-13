package com.ip2cidr.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModelTest {

    @Test
    void testCidrConstructorParseEqualsAndHashCode() {
        Cidr c1 = new Cidr(" 192.0.2.0 ", 24);
        Cidr c2 = Cidr.parse("192.0.2.0/24");
        Cidr c3 = Cidr.parse(" 2001:db8:: / 32 ");
        Cidr cDiffPrefix = new Cidr("192.0.2.0", 25);
        Cidr cDiffIp = new Cidr("198.51.100.0", 24);

        assertEquals("192.0.2.0", c1.getIpAddress());
        assertEquals(24, c1.getPrefixLength());
        assertEquals("192.0.2.0/24", c1.toString());

        assertEquals(c1, c1);
        assertEquals(c1, c2);
        assertEquals(c1.hashCode(), c2.hashCode());
        assertNotEquals(c1, c3);
        assertNotEquals(c1, cDiffPrefix);
        assertNotEquals(c1, cDiffIp);
        assertNotEquals(c1, "192.0.2.0/24");
        assertNotEquals(c1, null);

        assertThrows(IllegalArgumentException.class, () -> new Cidr(null, 24));
        assertThrows(IllegalArgumentException.class, () -> new Cidr("   ", 24));
        assertThrows(IllegalArgumentException.class, () -> new Cidr("192.0.2.0", -1));
        assertThrows(IllegalArgumentException.class, () -> new Cidr("192.0.2.0", 129));

        assertThrows(IllegalArgumentException.class, () -> Cidr.parse(null));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("   "));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("192.0.2.0"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("/24"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("192.0.2.0/"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("192.0.2.0/abc"));
    }

    @Test
    void testWhoisCidrInfoDefaultsMutationEqualsHashCodeAndToString() {
        Cidr primary = new Cidr("192.0.2.0", 24);

        // null / 空コレクションのデフォルト値検証
        WhoisCidrInfo withNulls = new WhoisCidrInfo(
                primary,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);

        assertEquals(primary, withNulls.getCidr());
        assertEquals(List.of(primary), withNulls.getAllCidrs());
        assertEquals("", withNulls.getIpRange());
        assertNull(withNulls.getInetnumCidr());
        assertNull(withNulls.getRouteCidr());
        assertEquals("", withNulls.getInetnumIpRange());
        assertEquals("", withNulls.getRouteIpRange());
        assertTrue(withNulls.getMatchedIpAddresses().isEmpty());
        assertEquals("", withNulls.getCountry());
        assertEquals("", withNulls.getRegistrant());
        assertEquals("", withNulls.getNetName());
        assertTrue(withNulls.getDescriptions().isEmpty());
        assertTrue(withNulls.getAdminContacts().isEmpty());
        assertTrue(withNulls.getTechContacts().isEmpty());
        assertTrue(withNulls.getAbuseContacts().isEmpty());
        assertEquals("", withNulls.getRawWhoisOutput());

        WhoisCidrInfo with16ArgsNullRanges = new WhoisCidrInfo(
                primary,
                null,
                null,
                new Cidr("192.0.2.0", 23),
                new Cidr("192.0.2.0", 24),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
        assertEquals(new Cidr("192.0.2.0", 23), with16ArgsNullRanges.getInetnumCidr());
        assertEquals(new Cidr("192.0.2.0", 24), with16ArgsNullRanges.getRouteCidr());
        assertEquals("", with16ArgsNullRanges.getInetnumIpRange());
        assertEquals("", with16ArgsNullRanges.getRouteIpRange());

        WhoisCidrInfo withEmptyAllCidrs = new WhoisCidrInfo(
                primary,
                List.of(),
                "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1"),
                "JP",
                "Org",
                "NET",
                List.of("Desc"),
                List.of("Admin"),
                List.of("Tech"),
                List.of("abuse@example.com"),
                "raw");
        assertEquals(List.of(primary), withEmptyAllCidrs.getAllCidrs());

        // addMatchedIpAddress の検証（null/空白無視・トリム・重複排除）
        withEmptyAllCidrs.addMatchedIpAddress(null);
        withEmptyAllCidrs.addMatchedIpAddress("   ");
        withEmptyAllCidrs.addMatchedIpAddress(" 192.0.2.2 ");
        withEmptyAllCidrs.addMatchedIpAddress("192.0.2.1");
        assertEquals(List.of("192.0.2.1", "192.0.2.2"), withEmptyAllCidrs.getMatchedIpAddresses());

        // equals / hashCode / toString の検証
        WhoisCidrInfo same = new WhoisCidrInfo(
                primary,
                List.of(primary),
                "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"),
                "JP",
                "Org",
                "NET",
                List.of("Desc"),
                List.of("Admin"),
                List.of("Tech"),
                List.of("abuse@example.com"),
                "raw");

        assertEquals(withEmptyAllCidrs, withEmptyAllCidrs);
        assertEquals(withEmptyAllCidrs, same);
        assertEquals(withEmptyAllCidrs.hashCode(), same.hashCode());
        assertNotEquals(withEmptyAllCidrs, "not-info");
        assertNotEquals(withEmptyAllCidrs, null);
        assertNotEquals(withEmptyAllCidrs, withNulls);

        // 各フィールド個別の不一致分岐をすべて検証
        assertNotEquals(same, new WhoisCidrInfo(new Cidr("10.0.0.0", 8), List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(new Cidr("192.0.2.0", 25)), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "diff-range",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                new Cidr("192.0.2.0", 23), null, "", "",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                null, new Cidr("192.0.2.0", 24), "", "",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                null, null, "192.0.2.0 - 192.0.3.255", "",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                null, null, "", "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.99"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "US", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "DiffOrg", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "DiffNET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("DiffDesc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("DiffAdmin"), List.of("Tech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("DiffTech"), List.of("abuse@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("diff@example.com"), "raw"));
        assertNotEquals(same, new WhoisCidrInfo(primary, List.of(primary), "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"), "JP", "Org", "NET", List.of("Desc"), List.of("Admin"), List.of("Tech"), List.of("abuse@example.com"), "diffRaw"));

        assertTrue(same.toString().contains("WhoisCidrInfo{"));
        assertTrue(same.toString().contains("192.0.2.0/24"));
    }
}

