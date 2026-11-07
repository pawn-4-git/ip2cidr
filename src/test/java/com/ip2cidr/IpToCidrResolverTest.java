package com.ip2cidr;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import com.ip2cidr.whois.WhoisExecutor;
import com.ip2cidr.whois.WhoisParser;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IpToCidrResolverTest {

    @Test
    void testReuseDetectedCidrAndRateLimitOnlyOnActualWhoisQueries() {
        List<String> executedQueries = new ArrayList<>();
        List<Duration> sleepDurations = new ArrayList<>();

        WhoisExecutor mockExecutor = ip -> {
            executedQueries.add(ip);
            if (ip.startsWith("192.0.2.")) {
                return """
                        CIDR: 192.0.2.0/24
                        NetName: TEST-NET-1
                        OrgName: Example Org 1
                        Country: JP
                        """;
            } else if (ip.startsWith("198.51.100.")) {
                return """
                        inetnum: 198.51.100.0 - 198.51.100.255
                        netname: TEST-NET-2
                        descr: Example Org 2
                        country: US
                        """;
            } else if (ip.startsWith("2001:db8:")) {
                return """
                        inet6num: 2001:db8::/32
                        netname: IPV6-DOC-NET
                        descr: IPv6 Example Org
                        country: JP
                        """;
            }
            throw new IllegalArgumentException("Unexpected IP: " + ip);
        };

        IpToCidrResolver resolver = new IpToCidrResolver(
                mockExecutor,
                new WhoisParser(),
                Duration.ofSeconds(5),
                sleepDurations::add);

        // 入力リスト:
        // 1. 192.0.2.1 -> 初回whois実行（待機なし） -> 192.0.2.0/24 検出
        // 2. 192.0.2.50 -> 192.0.2.0/24 に含まれるためwhoisスキップ・待機なし
        // 3. 198.51.100.10 -> 未検出のため5秒待機後にwhois実行 -> 198.51.100.0/24 検出
        // 4. 192.0.2.200 -> 192.0.2.0/24 に含まれるためwhoisスキップ・待機なし
        // 5. 198.51.100.99 -> 198.51.100.0/24 に含まれるためwhoisスキップ・待機なし
        // 6. 2001:db8::1 -> 未検出のため5秒待機後にwhois実行 -> 2001:db8::/32 検出
        // 7. 2001:db8:abcd::2 -> 2001:db8::/32 に含まれるためwhoisスキップ・待機なし
        List<WhoisCidrInfo> results = resolver.resolve(
                "192.0.2.1",
                "192.0.2.50",
                "198.51.100.10",
                "192.0.2.200",
                "198.51.100.99",
                "2001:db8::1",
                "2001:db8:abcd::2");

        // whoisコマンドは3回のみ実行されていること
        assertEquals(List.of("192.0.2.1", "198.51.100.10", "2001:db8::1"), executedQueries);

        // レートリミット待機（5秒）は2回目と3回目のwhois実行前の計2回のみ発生していること
        assertEquals(
                List.of(Duration.ofSeconds(5), Duration.ofSeconds(5)),
                sleepDurations);

        // 結果は3つのCIDRクラスに集約されていること
        assertEquals(3, results.size());

        WhoisCidrInfo first = results.get(0);
        assertEquals(new Cidr("192.0.2.0", 24), first.getCidr());
        assertEquals(List.of("192.0.2.1", "192.0.2.50", "192.0.2.200"), first.getMatchedIpAddresses());
        assertEquals("JP", first.getCountry());
        assertEquals("Example Org 1", first.getRegistrant());

        WhoisCidrInfo second = results.get(1);
        assertEquals(new Cidr("198.51.100.0", 24), second.getCidr());
        assertEquals(List.of("198.51.100.10", "198.51.100.99"), second.getMatchedIpAddresses());
        assertEquals("US", second.getCountry());
        assertEquals("Example Org 2", second.getRegistrant());

        WhoisCidrInfo third = results.get(2);
        assertEquals(List.of("2001:db8::1", "2001:db8:abcd::2"), third.getMatchedIpAddresses());
        assertEquals("JP", third.getCountry());
        assertEquals("IPv6 Example Org", third.getRegistrant());
    }

    @Test
    void testRateLimitCooldownWaitOneMinuteAndRetry() {
        List<Duration> sleepDurations = new ArrayList<>();
        int[] attempts = {0};

        WhoisExecutor mockExecutor = ip -> {
            attempts[0]++;
            if (attempts[0] == 1) {
                return """
                        %ERROR:201: access denied
                        % Query rate limit exceeded
                        """;
            }
            return """
                    CIDR: 203.0.113.0/24
                    NetName: RETRY-SUCCESS-NET
                    OrgName: Retry Success Org
                    Country: JP
                    """;
        };

        IpToCidrResolver resolver = new IpToCidrResolver(
                mockExecutor,
                new WhoisParser(),
                Duration.ofSeconds(5),
                sleepDurations::add);

        List<WhoisCidrInfo> results = resolver.resolve("203.0.113.5");

        // 1回目でレートリミットになり、1分（60秒）待機して2回目で成功すること
        assertEquals(2, attempts[0]);
        assertEquals(List.of(Duration.ofMinutes(1)), sleepDurations);
        assertEquals(1, results.size());
        assertEquals(new Cidr("203.0.113.0", 24), results.getFirst().getCidr());
        assertEquals("Retry Success Org", results.getFirst().getRegistrant());
    }
}

