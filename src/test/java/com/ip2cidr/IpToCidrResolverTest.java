package com.ip2cidr;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import com.ip2cidr.whois.WhoisException;
import com.ip2cidr.whois.WhoisExecutor;
import com.ip2cidr.whois.WhoisParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

                // 入力リスト（順不同で渡しても、最初にIPアドレスの数値昇順に並び替えられてから処理される）:
                // ソート後:
                // 1. 192.0.2.1 -> 初回whois実行（待機なし） -> 192.0.2.0/24 検出
                // 2. 192.0.2.50 -> 直前の 192.0.2.0/24 に含まれるためwhoisスキップ・0.5秒待機
                // 3. 192.0.2.200 -> 直前の 192.0.2.0/24 に含まれるためwhoisスキップ・0.5秒待機
                // 4. 198.51.100.10 -> 未検出のため5秒待機後にwhois実行 -> 198.51.100.0/24 検出
                // 5. 198.51.100.99 -> 直前の 198.51.100.0/24 に含まれるためwhoisスキップ・0.5秒待機
                // 6. 2001:db8::1 -> 未検出のため5秒待機後にwhois実行 -> 2001:db8::/32 検出
                // 7. 2001:db8:abcd::2 -> 直前の 2001:db8::/32 に含まれるためwhoisスキップ・0.5秒待機
                List<WhoisCidrInfo> results = resolver.resolve(
                                "2001:db8:abcd::2",
                                "198.51.100.99",
                                "192.0.2.200",
                                "192.0.2.1",
                                "198.51.100.10",
                                "2001:db8::1",
                                "192.0.2.50");

                // ソート順の先頭IP（192.0.2.1, 198.51.100.10, 2001:db8::1）に対してのみwhoisコマンドが3回実行されていること
                assertEquals(List.of("192.0.2.1", "198.51.100.10", "2001:db8::1"), executedQueries);

                // キャッシュヒット時は0.5秒待機、新規whois実行時は5秒待機が発生していること
                assertEquals(
                                List.of(
                                                Duration.ofMillis(500),
                                                Duration.ofMillis(500),
                                                Duration.ofSeconds(5),
                                                Duration.ofMillis(500),
                                                Duration.ofSeconds(5),
                                                Duration.ofMillis(500)),
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
                int[] attempts = { 0 };

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

                PrintStream originalOut = System.out;
                ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
                List<WhoisCidrInfo> results;
                try {
                        System.setOut(new PrintStream(capturedOut, true, StandardCharsets.UTF_8));
                        results = resolver.resolve("203.0.113.5");
                } finally {
                        System.setOut(originalOut);
                }
                String stdout = capturedOut.toString(StandardCharsets.UTF_8);
                System.out.print(stdout);

                // 1回目でレートリミットになり、1分（60秒）待機して2回目で成功すること
                assertEquals(2, attempts[0]);
                assertEquals(List.of(Duration.ofMinutes(1)), sleepDurations);
                assertEquals(1, results.size());
                assertEquals(new Cidr("203.0.113.0", 24), results.getFirst().getCidr());
                assertEquals("Retry Success Org", results.getFirst().getRegistrant());
                assertEquals(10, IpToCidrResolver.DEFAULT_MAX_RATE_LIMIT_RETRIES);
                assertTrue(stdout.contains("[WHOIS] Starting resolution for 1 IP address(es)"));
                assertTrue(stdout.contains("[WHOIS] [1/1] Querying whois for 203.0.113.5..."));
                assertTrue(stdout.contains(
                                "[WHOIS] [WARN] Rate limit detected for IP 203.0.113.5. Waiting 60 seconds before retry (1/10)..."));
                assertTrue(stdout.contains("[WHOIS] [1/1] 203.0.113.5 -> Resolved CIDR: 203.0.113.0/24"));
                assertTrue(stdout.contains("[WHOIS] Completed resolution:"));
        }

        @Test
        void testConstructorsAndValidation() {
                IpToCidrResolver defaultResolver = new IpToCidrResolver();
                assertNotNull(defaultResolver);

                IpToCidrResolver sourceResolver = new IpToCidrResolver(WhoisParser.CidrSource.INETNUM);
                assertNotNull(sourceResolver);

                WhoisExecutor dummyExec = ip -> "CIDR: 192.0.2.0/24";
                IpToCidrResolver customExecResolver = new IpToCidrResolver(dummyExec, Duration.ofMillis(1));
                assertNotNull(customExecResolver);
                // 2引数コンストラクタ内のデフォルトSleeperラムダを実行（1ms待機）
                assertEquals(1, customExecResolver.resolve("192.0.2.1", "198.51.100.1").size());

                // デフォルトコンストラクタ内のSleeperラムダもリフレクション経由で1ms実行して検証
                assertDoesNotThrow(() -> {
                        var m = IpToCidrResolver.class.getDeclaredMethod("lambda$new$0", Duration.class);
                        m.setAccessible(true);
                        m.invoke(null, Duration.ofMillis(1));
                });

                IpToCidrResolver sixArgResolver = new IpToCidrResolver(
                                dummyExec,
                                new WhoisParser(),
                                Duration.ZERO,
                                Duration.ZERO,
                                1,
                                d -> {
                                });
                assertNotNull(sixArgResolver);

                assertThrows(IllegalArgumentException.class, () -> new IpToCidrResolver(
                                dummyExec, new WhoisParser(), Duration.ofSeconds(-1), Duration.ZERO, Duration.ZERO, 1,
                                d -> {
                                }));
                assertThrows(IllegalArgumentException.class, () -> new IpToCidrResolver(
                                dummyExec, new WhoisParser(), Duration.ZERO, Duration.ofMillis(-1), Duration.ZERO, 1,
                                d -> {
                                }));
                assertThrows(IllegalArgumentException.class, () -> new IpToCidrResolver(
                                dummyExec, new WhoisParser(), Duration.ZERO, Duration.ZERO, Duration.ofSeconds(-1), 1,
                                d -> {
                                }));
                assertThrows(IllegalArgumentException.class, () -> new IpToCidrResolver(
                                dummyExec, new WhoisParser(), Duration.ZERO, Duration.ZERO, Duration.ZERO, -1, d -> {
                                }));
        }

        @Test
        void testEmptyAndBlankInputs() {
                IpToCidrResolver resolver = new IpToCidrResolver(ip -> "CIDR: 192.0.2.0/24", Duration.ZERO);

                assertTrue(resolver.resolve((String[]) null).isEmpty());
                assertTrue(resolver.resolve(new String[0]).isEmpty());
                assertTrue(resolver.resolve((Collection<String>) null).isEmpty());
                assertTrue(resolver.resolve(List.of()).isEmpty());
                assertTrue(resolver.resolve(Arrays.asList(null, "", "   ")).isEmpty());
        }

        @Test
        void testCacheLookupAcrossCallsAndClearCache() {
                WhoisExecutor mockExecutor = ip -> {
                        if (ip.equals("10.0.0.1")) {
                                return "CIDR: 10.0.0.0/24\nOrgName: Specific 10 Net";
                        } else if (ip.equals("10.1.0.1")) {
                                return "CIDR: 10.0.0.0/8\nOrgName: Broad 10 Net";
                        } else if (ip.equals("192.0.2.1")) {
                                return "CIDR: 192.0.2.0/24\nOrgName: Specific Net";
                        } else if (ip.equals("172.16.0.1")) {
                                // わざと既にキャッシュ済みのCIDRを返すケース（existingByCidr != null 分岐の検証）
                                return "CIDR: 192.0.2.0/24\nOrgName: Specific Net";
                        }
                        return "CIDR: 203.0.113.0/24";
                };

                IpToCidrResolver resolver = new IpToCidrResolver(
                                mockExecutor,
                                new WhoisParser(),
                                Duration.ZERO,
                                Duration.ZERO,
                                Duration.ZERO,
                                1,
                                d -> {
                                });

                // 1回目の呼び出しで 10.0.0.0/24, 10.0.0.0/8, 192.0.2.0/24 をキャッシュに登録（lastResolvedEntry は
                // 192.0.2.0/24）
                resolver.resolve("10.0.0.1", "10.1.0.1", "192.0.2.1");
                assertEquals(3, resolver.getCachedResults().size());

                // 2回目の呼び出しで 10.0.0.2 を解決 -> findContainingEntry で 10.0.0.0/24 と 10.0.0.0/8
                // の両方に包含されるが、
                // よりプレフィックス長が長い 10.0.0.0/24 が優先されること（24 > -1 が true、8 > 24 が false の両分岐を通過）
                // さらに 172.16.0.1 は whois 結果が既存CIDR (192.0.2.0/24) と一致し existingByCidr に統合される
                List<WhoisCidrInfo> secondBatch = resolver.resolve("10.0.0.2", "172.16.0.1");
                assertEquals(2, secondBatch.size());
                assertEquals(new Cidr("10.0.0.0", 24), secondBatch.get(0).getCidr());
                assertEquals(List.of("10.0.0.1", "10.0.0.2"), secondBatch.get(0).getMatchedIpAddresses());
                assertEquals(List.of("192.0.2.1", "172.16.0.1"), secondBatch.get(1).getMatchedIpAddresses());

                resolver.clearCache();
                assertTrue(resolver.getCachedResults().isEmpty());
        }

        @Test
        void testRetryExhaustionOnRateLimitAndWhoisException() {
                // 1. レートリミット応答がリトライ上限を超えて継続する場合
                IpToCidrResolver rateLimitedResolver = new IpToCidrResolver(
                                ip -> "% Query rate limit exceeded",
                                new WhoisParser(),
                                Duration.ZERO,
                                Duration.ZERO,
                                Duration.ofMillis(1),
                                2,
                                d -> {
                                });

                WhoisException rateLimitEx = assertThrows(
                                WhoisException.class,
                                () -> rateLimitedResolver.resolve("192.0.2.1"));
                assertTrue(rateLimitEx.getMessage().contains("Rate limit persisted after 2 retries"));

                // 2. WhoisException が1回目に発生し、2回目で成功する場合
                int[] count = { 0 };
                IpToCidrResolver recoveringResolver = new IpToCidrResolver(
                                ip -> {
                                        if (++count[0] == 1) {
                                                throw new WhoisException("Temporary failure");
                                        }
                                        return "CIDR: 192.0.2.0/24\nOrgName: Recovered Org";
                                },
                                new WhoisParser(),
                                Duration.ZERO,
                                Duration.ZERO,
                                Duration.ofMillis(1),
                                2,
                                d -> {
                                });
                List<WhoisCidrInfo> recovered = recoveringResolver.resolve("192.0.2.1");
                assertEquals(1, recovered.size());
                assertEquals("Recovered Org", recovered.getFirst().getRegistrant());

                // 3. WhoisException がリトライ上限を超えて発生し続ける場合
                IpToCidrResolver failingResolver = new IpToCidrResolver(
                                ip -> {
                                        throw new WhoisException("Persistent failure");
                                },
                                new WhoisParser(),
                                Duration.ZERO,
                                Duration.ZERO,
                                Duration.ofMillis(1),
                                1,
                                d -> {
                                });
                WhoisException failEx = assertThrows(
                                WhoisException.class,
                                () -> failingResolver.resolve("192.0.2.1"));
                assertEquals("Persistent failure", failEx.getMessage());
        }

        @Test
        void testSleepInterruptedThrowsWhoisException() {
                IpToCidrResolver resolver = new IpToCidrResolver(
                                ip -> "CIDR: 192.0.2.0/24",
                                new WhoisParser(),
                                Duration.ofSeconds(1),
                                Duration.ofMillis(100),
                                Duration.ofSeconds(1),
                                1,
                                d -> {
                                        throw new InterruptedException("sleep interrupted");
                                });

                try {
                        WhoisException ex = assertThrows(
                                        WhoisException.class,
                                        () -> resolver.resolve("192.0.2.1", "192.0.2.2"));
                        assertTrue(ex.getMessage().contains("Interrupted while waiting for whois rate limit"));
                        assertTrue(Thread.currentThread().isInterrupted());
                } finally {
                        Thread.interrupted(); // テストスレッドの割り込み状態をクリア
                }
        }
}
