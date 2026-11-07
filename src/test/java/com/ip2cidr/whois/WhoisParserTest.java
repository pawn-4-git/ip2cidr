package com.ip2cidr.whois;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WhoisParserTest {

    private final WhoisParser parser = new WhoisParser();

    @Test
    void testParseArinFormat() {
        String raw = """
                # ARIN WHOIS data and services are subject to the Terms of Use
                NetRange:       8.8.8.0 - 8.8.8.255
                CIDR:           8.8.8.0/24
                NetName:        GOGL
                OrgName:        Google LLC
                Country:        US
                OrgAdminHandle: ZG39-ARIN
                OrgTechHandle:  ZG39-ARIN
                OrgAbuseEmail:  network-abuse@google.com
                Comment:        Google Public DNS
                """;

        WhoisCidrInfo info = parser.parse("8.8.8.8", raw);
        assertEquals(new Cidr("8.8.8.0", 24), info.getCidr());
        assertEquals("8.8.8.0", info.getCidr().getIpAddress());
        assertEquals(24, info.getCidr().getPrefixLength());
        assertEquals("8.8.8.0/24", info.getCidr().toString());
        assertEquals("8.8.8.0 - 8.8.8.255", info.getIpRange());
        assertEquals(List.of("8.8.8.8"), info.getMatchedIpAddresses());
        assertEquals("US", info.getCountry());
        assertEquals("Google LLC", info.getRegistrant());
        assertEquals("GOGL", info.getNetName());
        assertEquals(List.of("Google Public DNS"), info.getDescriptions());
        assertEquals(List.of("ZG39-ARIN"), info.getAdminContacts());
        assertEquals(List.of("ZG39-ARIN"), info.getTechContacts());
        assertEquals(List.of("network-abuse@google.com"), info.getAbuseContacts());
        assertEquals(raw, info.getRawWhoisOutput());
    }

    @Test
    void testParseApnicInetnumWithoutExplicitCidrAndWithIanaHeader() {
        String raw = """
                % IANA WHOIS server
                inetnum:      0.0.0.0 - 255.255.255.255
                organisation: Internet Assigned Numbers Authority
                
                % [whois.apnic.net]
                % Abuse contact for '1.1.1.0 - 1.1.1.255' is 'abuse@cloudflare.com'
                inetnum:        1.1.1.0 - 1.1.1.255
                netname:        APNIC-LABS
                descr:          APNIC and Cloudflare DNS Resolver project
                descr:          Routed globally by AS13335/Cloudflare
                country:        AU
                admin-c:        AIC3-AP
                tech-c:         AIC3-AP
                abuse-mailbox:  abuse@cloudflare.com
                """;

        WhoisCidrInfo info = parser.parse("1.1.1.1", raw);
        assertEquals(new Cidr("1.1.1.0", 24), info.getCidr());
        assertEquals("1.1.1.0 - 1.1.1.255", info.getIpRange());
        assertEquals("AU", info.getCountry());
        assertEquals("APNIC and Cloudflare DNS Resolver project", info.getRegistrant());
        assertEquals("APNIC-LABS", info.getNetName());
        assertEquals(List.of("AIC3-AP"), info.getAdminContacts());
        assertEquals(List.of("AIC3-AP"), info.getTechContacts());
        assertEquals(List.of("abuse@cloudflare.com"), info.getAbuseContacts());
    }

    @Test
    void testParseJpnicFormat() {
        String raw = """
                [ JPNIC database provides information regarding IP address and ASN. ]
                a. [Network Number]             192.0.2.0-192.0.2.255
                b. [Network Name]               EXAMPLE-NET
                g. [Organization]               Example Japan Corporation
                m. [Administrative Contact]     JP00000001
                n. [Technical Contact]          JP00000002
                """;

        WhoisCidrInfo info = parser.parse("192.0.2.42", raw);
        assertEquals(new Cidr("192.0.2.0", 24), info.getCidr());
        assertEquals("192.0.2.0 - 192.0.2.255", info.getIpRange());
        assertEquals("Example Japan Corporation", info.getRegistrant());
        assertEquals("EXAMPLE-NET", info.getNetName());
        assertEquals(List.of("JP00000001"), info.getAdminContacts());
        assertEquals(List.of("JP00000002"), info.getTechContacts());
    }

    @Test
    void testParseIpv6Format() {
        String raw = """
                inet6num:       2404:6800:4004::/48
                netname:        GOOGLE-IPV6-JP
                descr:          Google Tokyo Data Center
                country:        JP
                admin-c:        GOGL-AP
                tech-c:         GOGL-AP
                abuse-mailbox:  network-abuse@google.com
                """;

        WhoisCidrInfo info = parser.parse("2404:6800:4004:800::200e", raw);
        assertTrue(info.getCidr().toString().endsWith("/48"));
        assertEquals(48, info.getCidr().getPrefixLength());
        assertEquals("JP", info.getCountry());
        assertEquals("Google Tokyo Data Center", info.getRegistrant());
        assertEquals("GOOGLE-IPV6-JP", info.getNetName());
    }
}

