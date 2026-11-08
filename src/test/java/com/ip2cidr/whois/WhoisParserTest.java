package com.ip2cidr.whois;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        void testParseJpnicJapaneseKeysAndCountry() {
                String raw = """
                                [ネットワーク番号] 192.0.2.0/24 # inline comment
                                [ネットワーク番号] invalid-range
                                [ネットワーク名]   JPNIC-JP-NET
                                [組織名]           日本サンプル株式会社
                                [管理者連絡窓口]   ADM-JP
                                [技術連絡担当者]   TECH-JP
                                [Country]          ZZ
                                [国コード]         World Wide
                                [国コード]         jp
                                [その他項目]       未定義キー
                                [空コメント項目]   # comment only
                                """;

                WhoisCidrInfo info = parser.parse("192.0.2.10", raw);
                assertEquals(new Cidr("192.0.2.0", 24), info.getCidr());
                assertEquals("JP", info.getCountry());
                assertEquals("日本サンプル株式会社", info.getRegistrant());
                assertEquals("JPNIC-JP-NET", info.getNetName());
                assertEquals(List.of("ADM-JP"), info.getAdminContacts());
                assertEquals(List.of("TECH-JP"), info.getTechContacts());
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

        @Test
        void testIsRateLimitedPatterns() {
                assertFalse(parser.isRateLimited(null));
                assertFalse(parser.isRateLimited(""));
                assertFalse(parser.isRateLimited("   "));
                assertFalse(parser.isRateLimited("CIDR: 192.0.2.0/24\nOrgName: Normal Output"));

                assertTrue(parser.isRateLimited("% Query rate limit exceeded"));
                assertTrue(parser.isRateLimited("Query limit exceeded"));
                assertTrue(parser.isRateLimited("Daily quota exceeded"));
                assertTrue(parser.isRateLimited("Too many requests from your IP"));
                assertTrue(parser.isRateLimited("Access from your host has been temporarily denied"));
                assertTrue(parser.isRateLimited("%ERROR:201: access denied"));
                assertTrue(parser.isRateLimited("You have exceeded the maximum allowable queries"));
                assertTrue(parser.isRateLimited("Please try again later"));
                assertTrue(parser.isRateLimited("Connection reset by peer"));
                assertTrue(parser.isRateLimited("Connection refused"));
                assertTrue(parser.isRateLimited("Operation timed out"));
        }

        @Test
        void testCandidateSelectionAndPlaceholdersAndFallback() {
                // 1. 同一プレフィックス長で非明示(inetnum)→明示(route)の順、さらに同条件で後続候補優先、その後より広い候補(/16)が来るケース
                String raw = """
                                netname:        IANA-BLK
                                org-name:       IANA-IPV4-MAPPED-RESERVED
                                descr:          Internet Assigned Numbers Authority
                                country:        ZZ
                                country:         EU # Worldwide
                                country:        DE # Germany
                                inetnum:        192.0.2.0 - 192.0.2.255
                                route:          192.0.2.0/24
                                CIDR:           192.0.2.0/25, , invalid-cidr, 192.0.2.0/26, 192.0.2.0/25, 192.0.2.128/25
                                CIDR:           invalid-only
                                inetnum:        192.0.0.0 - 192.0.255.255
                                inetnum:        192.0.2.255 - 192.0.2.0
                                inetnum:        not-a-range
                                netname:        ONLY-NETNAME
                                adminhandle:    ADM-H
                                techhandle:     TECH-H
                                zone-c:         ZONE-H
                                abuse-c:        ABUSE-H
                                orgabusehandle: ORG-ABUSE-H
                                comment:        # inline comment only
                                unknown-key:    some value
                                """;

                WhoisCidrInfo info = parser.parse("192.0.2.5", raw);
                // 192.0.2.0/26 が最も具体的（/26 > /25 > /24 > /16）なので選択される
                assertEquals(new Cidr("192.0.2.0", 26), info.getCidr());
                assertEquals(
                                List.of(new Cidr("192.0.2.0", 25), new Cidr("192.0.2.0", 26),
                                                new Cidr("192.0.2.128", 25)),
                                info.getAllCidrs());
                assertEquals("DE", info.getCountry());
                // orgCandidates も descriptions も空のため netName にフォールバック
                assertEquals("ONLY-NETNAME", info.getRegistrant());
                assertEquals(List.of("ADM-H"), info.getAdminContacts());
                assertEquals(List.of("TECH-H", "ZONE-H"), info.getTechContacts());
                assertEquals(List.of("ABUSE-H", "ORG-ABUSE-H"), info.getAbuseContacts());

                // 2. 同じプレフィックス長(/24)で明示CIDR同士が並んだ場合、後半の候補が優先され、その後の非明示(/24)では上書きされないこと
                String rawTieBreak = """
                                route:   192.0.2.0/24
                                CIDR:    192.0.2.0/24
                                inetnum: 192.0.2.0 - 192.0.2.255
                                """;
                WhoisCidrInfo tieInfo = parser.parse("192.0.2.1", rawTieBreak);
                assertEquals(new Cidr("192.0.2.0", 24), tieInfo.getCidr());
                assertEquals("", tieInfo.getRegistrant());

                // 3. 対象IPを直接包含するブロックが存在しない場合、逆順走査で /0 をスキップして最後の有効候補にフォールバックすること
                String rawNonContaining = """
                                route: 198.51.100.0/24
                                route: 0.0.0.0/0
                                """;
                WhoisCidrInfo nonContainingInfo = parser.parse("192.0.2.1", rawNonContaining);
                assertEquals(new Cidr("198.51.100.0", 24), nonContainingInfo.getCidr());

                // /0 しか候補がない場合は selectBestCandidate が null を返し、単一ホストCIDR(/32)にフォールバックすること
                WhoisCidrInfo onlyZeroPrefixInfo = parser.parse("192.0.2.1", "route: 0.0.0.0/0");
                assertEquals(new Cidr("192.0.2.1", 32), onlyZeroPrefixInfo.getCidr());

                // 4. rawWhoisOutput が null または空の場合、単一ホストCIDR (/32 または /128) にフォールバックすること
                WhoisCidrInfo fallbackIpv4 = parser.parse("192.0.2.9", null);
                assertEquals(new Cidr("192.0.2.9", 32), fallbackIpv4.getCidr());

                WhoisCidrInfo fallbackIpv6 = parser.parse("2001:db8::9", "");
                assertEquals(new Cidr("2001:db8:0:0:0:0:0:9", 128), fallbackIpv6.getCidr());

                // 5. queriedIp が null または空白の場合は例外
                assertThrows(IllegalArgumentException.class, () -> parser.parse(null, ""));
                assertThrows(IllegalArgumentException.class, () -> parser.parse("   ", ""));
        }
}
