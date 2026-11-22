package com.ip2cidr;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import com.ip2cidr.util.CidrBlock;
import com.ip2cidr.util.CidrUtils;
import com.ip2cidr.whois.CommandWhoisExecutor;
import com.ip2cidr.whois.WhoisException;
import com.ip2cidr.whois.WhoisExecutor;
import com.ip2cidr.whois.WhoisParser;

import java.net.InetAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 複数のIPアドレスを入力として受け取り、whois検索によってCIDRおよび登録者・国情報を整理して返すリゾルバ。
 * <ul>
 * <li>同一CIDRに属する複数のIPアドレスは1つの {@link WhoisCidrInfo} インスタンスに統合されます。</li>
 * <li>一度検出したCIDR領域に含まれる後続のIPアドレスはwhois検索をスキップし、検出済み情報を流用します。</li>
 * <li>whois検索を実行する際は、レートリミット対策として検索間隔（デフォルト5秒）を空けて実行します。</li>
 * </ul>
 */
public class IpToCidrResolver {

    /**
     * デフォルトのwhois検索間隔（5秒）。
     */
    public static final Duration DEFAULT_RATE_LIMIT_INTERVAL = Duration.ofSeconds(5);

    /**
     * 既に判定済みのCIDR範囲内に含まれるIPアドレスだった場合のデフォルト待機時間（0.5秒）。
     */
    public static final Duration DEFAULT_CACHE_HIT_INTERVAL = Duration.ofMillis(500);

    /**
     * レートリミット発生時の初回クールダウン待機時間（8分）。
     */
    public static final Duration DEFAULT_INITIAL_RATE_LIMIT_COOLDOWN = Duration.ofMinutes(8);

    /**
     * whoisサーバーからレートリミット（アクセス制限）を受けた際の2回目以降の基準クールダウン時間（1分）。
     */
    public static final Duration DEFAULT_RATE_LIMIT_COOLDOWN = Duration.ofMinutes(1);

    /**
     * レートリミット発生時のデフォルト最大リトライ回数（10回）。
     */
    public static final int DEFAULT_MAX_RATE_LIMIT_RETRIES = 10;

    /**
     * レートリミット発生時の段階的クールダウン待機時間のデフォルト上限（10分）。
     */
    public static final Duration DEFAULT_MAX_RATE_LIMIT_COOLDOWN = Duration.ofMinutes(10);

    /**
     * キャッシュヒットを挟まずに連続してwhois検索を実行する際のデフォルト加算時間（+1秒/回）。
     */
    public static final Duration DEFAULT_CONSECUTIVE_WHOIS_INCREMENT = Duration.ofSeconds(1);

    /**
     * 動的調整によるwhois検索間隔のデフォルト上限（60秒）。
     */
    public static final Duration DEFAULT_MAX_RATE_LIMIT_INTERVAL = Duration.ofSeconds(60);

    /**
     * 動的調整によるキャッシュヒット時待機時間のデフォルト上限（5秒）。
     */
    public static final Duration DEFAULT_MAX_CACHE_HIT_INTERVAL = Duration.ofSeconds(5);

    /**
     * レートリミット待機処理を抽象化する関数型インターフェース。
     */
    @FunctionalInterface
    public interface Sleeper {
        void sleep(Duration duration) throws InterruptedException;
    }

    private record ParsedIpInput(String rawIp, InetAddress address) implements Comparable<ParsedIpInput> {
        @Override
        public int compareTo(ParsedIpInput other) {
            return CidrUtils.compareIpAddresses(this.address, other.address);
        }
    }

    private record CachedEntry(WhoisCidrInfo info, List<CidrBlock> blocks) {
        boolean contains(InetAddress address) {
            for (CidrBlock block : blocks) {
                if (block.contains(address)) {
                    return true;
                }
            }
            return false;
        }
    }

    private final WhoisExecutor whoisExecutor;
    private final WhoisParser whoisParser;
    private final Duration rateLimitInterval;
    private final Duration cacheHitInterval;
    private final Duration initialRateLimitCooldown;
    private final Duration rateLimitCooldown;
    private final Duration maxRateLimitCooldown;
    private final int maxRateLimitRetries;
    private final Duration consecutiveWhoisIncrement;
    private final Duration maxRateLimitInterval;
    private final Duration maxCacheHitInterval;
    private final Sleeper sleeper;
    private final Clock clock;

    private final Map<Cidr, CachedEntry> cidrCache = new LinkedHashMap<>();
    private boolean hasExecutedWhois = false;
    private Duration currentRateLimitInterval;
    private Duration currentCacheHitInterval;
    private int consecutiveWhoisCount = 0;
    private Instant whoisWindowStart = null;
    private int whoisQueriesInWindow = 0;

    /**
     * デフォルト設定（OSのwhoisコマンド使用、inetnum優先、通常検索間隔5秒、キャッシュヒット時0.5秒待機、レートリミット発生時1分待機）でリゾルバを生成します。
     */
    public IpToCidrResolver() {
        this(WhoisParser.CidrSource.INETNUM);
    }

    /**
     * 採用するCIDR情報源（{@link WhoisParser.CidrSource#INETNUM} または {@link WhoisParser.CidrSource#ROUTE}）を指定してリゾルバを生成します。
     */
    public IpToCidrResolver(WhoisParser.CidrSource cidrSource) {
        this(
                new CommandWhoisExecutor(),
                new WhoisParser(cidrSource),
                DEFAULT_RATE_LIMIT_INTERVAL,
                DEFAULT_CACHE_HIT_INTERVAL,
                DEFAULT_RATE_LIMIT_COOLDOWN,
                DEFAULT_MAX_RATE_LIMIT_RETRIES,
                duration -> Thread.sleep(duration.toMillis()));
    }

    /**
     * カスタムの {@link WhoisExecutor} と検索間隔を指定してリゾルバを生成します。
     */
    public IpToCidrResolver(WhoisExecutor whoisExecutor, Duration rateLimitInterval) {
        this(
                whoisExecutor,
                new WhoisParser(),
                rateLimitInterval,
                DEFAULT_CACHE_HIT_INTERVAL,
                DEFAULT_RATE_LIMIT_COOLDOWN,
                DEFAULT_MAX_RATE_LIMIT_RETRIES,
                duration -> Thread.sleep(duration.toMillis()));
    }

    /**
     * コンポーネントを指定してリゾルバを生成します（テストやカスタマイズ用）。
     */
    public IpToCidrResolver(
            WhoisExecutor whoisExecutor,
            WhoisParser whoisParser,
            Duration rateLimitInterval,
            Sleeper sleeper) {
        this(
                whoisExecutor,
                whoisParser,
                rateLimitInterval,
                DEFAULT_CACHE_HIT_INTERVAL,
                DEFAULT_RATE_LIMIT_COOLDOWN,
                DEFAULT_MAX_RATE_LIMIT_RETRIES,
                sleeper);
    }

    /**
     * すべてのコンポーネント（レートリミット時の待機時間・リトライ回数を含む）を指定してリゾルバを生成します。
     */
    public IpToCidrResolver(
            WhoisExecutor whoisExecutor,
            WhoisParser whoisParser,
            Duration rateLimitInterval,
            Duration rateLimitCooldown,
            int maxRateLimitRetries,
            Sleeper sleeper) {
        this(
                whoisExecutor,
                whoisParser,
                rateLimitInterval,
                DEFAULT_CACHE_HIT_INTERVAL,
                rateLimitCooldown,
                maxRateLimitRetries,
                sleeper);
    }

    /**
     * すべてのコンポーネント（キャッシュヒット時の待機時間・レートリミット時の待機時間・リトライ回数を含む）を指定してリゾルバを生成します。
     */
    public IpToCidrResolver(
            WhoisExecutor whoisExecutor,
            WhoisParser whoisParser,
            Duration rateLimitInterval,
            Duration cacheHitInterval,
            Duration rateLimitCooldown,
            int maxRateLimitRetries,
            Sleeper sleeper) {
        this(
                whoisExecutor,
                whoisParser,
                rateLimitInterval,
                cacheHitInterval,
                rateLimitCooldown,
                maxRateLimitRetries,
                DEFAULT_CONSECUTIVE_WHOIS_INCREMENT,
                DEFAULT_MAX_RATE_LIMIT_INTERVAL,
                DEFAULT_MAX_CACHE_HIT_INTERVAL,
                sleeper,
                Clock.systemUTC());
    }

    /**
     * 動的待機時間調整パラメータおよび時刻取得用 {@link Clock} を含めてリゾルバを生成します（テストや高度なカスタマイズ用）。
     */
    public IpToCidrResolver(
            WhoisExecutor whoisExecutor,
            WhoisParser whoisParser,
            Duration rateLimitInterval,
            Duration cacheHitInterval,
            Duration rateLimitCooldown,
            int maxRateLimitRetries,
            Duration consecutiveWhoisIncrement,
            Duration maxRateLimitInterval,
            Duration maxCacheHitInterval,
            Sleeper sleeper,
            Clock clock) {
        this.whoisExecutor = Objects.requireNonNull(whoisExecutor, "whoisExecutor must not be null");
        this.whoisParser = Objects.requireNonNull(whoisParser, "whoisParser must not be null");
        this.rateLimitInterval = Objects.requireNonNull(rateLimitInterval, "rateLimitInterval must not be null");
        this.cacheHitInterval = Objects.requireNonNull(cacheHitInterval, "cacheHitInterval must not be null");
        this.initialRateLimitCooldown = DEFAULT_INITIAL_RATE_LIMIT_COOLDOWN;
        this.rateLimitCooldown = Objects.requireNonNull(rateLimitCooldown, "rateLimitCooldown must not be null");
        this.maxRateLimitCooldown = DEFAULT_MAX_RATE_LIMIT_COOLDOWN;
        this.maxRateLimitRetries = maxRateLimitRetries;
        this.consecutiveWhoisIncrement = Objects.requireNonNull(
                consecutiveWhoisIncrement, "consecutiveWhoisIncrement must not be null");
        this.maxRateLimitInterval = Objects.requireNonNull(
                maxRateLimitInterval, "maxRateLimitInterval must not be null");
        this.maxCacheHitInterval = Objects.requireNonNull(
                maxCacheHitInterval, "maxCacheHitInterval must not be null");
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
        if (rateLimitInterval.isNegative()) {
            throw new IllegalArgumentException("rateLimitInterval must not be negative");
        }
        if (cacheHitInterval.isNegative()) {
            throw new IllegalArgumentException("cacheHitInterval must not be negative");
        }
        if (rateLimitCooldown.isNegative()) {
            throw new IllegalArgumentException("rateLimitCooldown must not be negative");
        }
        if (maxRateLimitRetries < 0) {
            throw new IllegalArgumentException("maxRateLimitRetries must not be negative");
        }
        if (consecutiveWhoisIncrement.isNegative()) {
            throw new IllegalArgumentException("consecutiveWhoisIncrement must not be negative");
        }
        if (maxRateLimitInterval.isNegative()) {
            throw new IllegalArgumentException("maxRateLimitInterval must not be negative");
        }
        if (maxCacheHitInterval.isNegative()) {
            throw new IllegalArgumentException("maxCacheHitInterval must not be negative");
        }
        this.currentRateLimitInterval = rateLimitInterval;
        this.currentCacheHitInterval = cacheHitInterval;
    }

    /**
     * 可変長引数のIPアドレス群を解決し、CIDR単位に整理された {@link WhoisCidrInfo} のリストを返します。
     */
    public List<WhoisCidrInfo> resolve(String... ipAddresses) {
        if (ipAddresses == null || ipAddresses.length == 0) {
            return List.of();
        }
        return resolve(Arrays.asList(ipAddresses));
    }

    /**
     * 複数のIPアドレスを解決し、CIDR単位に整理された {@link WhoisCidrInfo} のリストを返します。
     * <ol>
     * <li>最初に入力IPアドレス群をIPアドレスの数値昇順に並び替えます。</li>
     * <li>CIDRを判定した直後の次のIPアドレスが、直前に判定したCIDR範囲内に含まれるかを即座にチェックします。</li>
     * <li>既に判定範囲内のIPアドレスだった場合も、次のwhois実行までの間隔を空けるために0.5秒（デフォルト）待機します。</li>
     * </ol>
     *
     * @param ipAddresses 入力IPアドレスのコレクション（IPv4 / IPv6対応）
     * @return CIDR単位に集約された {@link WhoisCidrInfo} のリスト
     */
    public synchronized List<WhoisCidrInfo> resolve(Collection<String> ipAddresses) {
        if (ipAddresses == null || ipAddresses.isEmpty()) {
            return List.of();
        }

        // 0. 入力IPアドレスをパースし、IPアドレス順（数値昇順）に並び替える
        List<ParsedIpInput> sortedInputs = new ArrayList<>();
        for (String rawIp : ipAddresses) {
            if (rawIp == null || rawIp.isBlank()) {
                continue;
            }
            String ip = rawIp.trim();
            InetAddress parsedIp = CidrUtils.parseIpAddress(ip);
            sortedInputs.add(new ParsedIpInput(ip, parsedIp));
        }
        if (sortedInputs.isEmpty()) {
            return List.of();
        }
        sortedInputs.sort(null);

        Map<Cidr, WhoisCidrInfo> batchResults = new LinkedHashMap<>();
        List<String> unresolvedIps = new ArrayList<>();
        CachedEntry lastResolvedEntry = null;
        int total = sortedInputs.size();

        logStatus("[WHOIS] Starting resolution for %d IP address(es) (sorted in ascending order)...", total);

        for (int i = 0; i < total; i++) {
            ParsedIpInput input = sortedInputs.get(i);
            int current = i + 1;
            String ip = input.rawIp();
            InetAddress parsedIp = input.address();

            // 1. 直前に判定したCIDR範囲に含まれるかを真っ先に判定し、該当しなければ既存キャッシュ全体を検索
            CachedEntry matchedEntry = (lastResolvedEntry != null && lastResolvedEntry.contains(parsedIp))
                    ? lastResolvedEntry
                    : findContainingEntry(parsedIp);
            if (matchedEntry != null) {
                WhoisCidrInfo existingInfo = matchedEntry.info();
                existingInfo.addMatchedIpAddress(ip);
                batchResults.putIfAbsent(existingInfo.getCidr(), existingInfo);
                lastResolvedEntry = matchedEntry;
                logStatus(
                        "[WHOIS] [%d/%d] %s -> Skipped (matched cached CIDR: %s, Country: %s, Registrant: %s)",
                        current,
                        total,
                        ip,
                        existingInfo.getCidr(),
                        existingInfo.getCountry(),
                        existingInfo.getRegistrant());
                // 既に判定範囲内のIPアドレスだった場合も、次のwhoisの実行を空けるために待機し、連続whoisカウントをリセット
                consecutiveWhoisCount = 0;
                sleepDuration(currentCacheHitInterval);
                continue;
            }

            // 2. 未検出のIPアドレスの場合はレートリミット（通常5秒間隔、制限検知時は1分待機リトライ）を適用してwhoisを実行
            String rawWhois;
            try {
                rawWhois = executeWhoisWithRetry(ip, current, total);
            } catch (WhoisException e) {
                if (Thread.currentThread().isInterrupted()) {
                    throw e;
                }
                logStatus(
                        "[WHOIS] [ERROR] Failed to resolve IP %s (%s). Aborting remaining WHOIS queries and returning partial results.",
                        ip,
                        e.getMessage());
                for (int j = i; j < total; j++) {
                    unresolvedIps.add(sortedInputs.get(j).rawIp());
                }
                break;
            }

            WhoisParser.ParsedResult parsedResult = whoisParser.parseWithBlocks(ip, rawWhois);
            WhoisCidrInfo newInfo = parsedResult.info();
            Cidr primaryCidr = newInfo.getCidr();

            logStatus(
                    "[WHOIS] [%d/%d] %s -> Resolved CIDR: %s (Range: %s, Country: %s, NetName: %s, Registrant: %s)",
                    current,
                    total,
                    ip,
                    primaryCidr,
                    newInfo.getIpRange(),
                    newInfo.getCountry(),
                    newInfo.getNetName(),
                    newInfo.getRegistrant());

            // 3. 同一CIDRが既に存在する場合は1つのWhoisCidrInfoクラスに統合
            CachedEntry existingByCidr = cidrCache.get(primaryCidr);
            if (existingByCidr != null) {
                WhoisCidrInfo existingInfo = existingByCidr.info();
                existingInfo.addMatchedIpAddress(ip);
                batchResults.putIfAbsent(primaryCidr, existingInfo);
                lastResolvedEntry = existingByCidr;
            } else {
                CachedEntry newEntry = new CachedEntry(newInfo, parsedResult.cidrBlocks());
                cidrCache.put(primaryCidr, newEntry);
                batchResults.put(primaryCidr, newInfo);
                lastResolvedEntry = newEntry;
            }
        }

        List<WhoisCidrInfo> finalResults = new ArrayList<>(batchResults.values());
        if (!unresolvedIps.isEmpty()) {
            for (String unresolvedIp : unresolvedIps) {
                finalResults.add(WhoisCidrInfo.failed(unresolvedIp));
            }
            logStatus(
                    "[WHOIS] [WARN] Unresolved IP address(es) (%d): %s",
                    unresolvedIps.size(),
                    String.join(", ", unresolvedIps));
            int resolvedIpCount = total - unresolvedIps.size();
            logStatus(
                    "[WHOIS] Completed resolution with errors: %d/%d IP address(es) resolved into %d CIDR block(s), %d IP address(es) unresolved.",
                    resolvedIpCount,
                    total,
                    batchResults.size(),
                    unresolvedIps.size());
        } else {
            logStatus(
                    "[WHOIS] Completed resolution: %d IP address(es) aggregated into %d CIDR block(s).",
                    total,
                    batchResults.size());
        }

        return finalResults;
    }

    /**
     * リゾルバ内にキャッシュされている検出済みCIDR情報および動的調整された待機時間状態をリセットします。
     */
    public synchronized void clearCache() {
        cidrCache.clear();
        hasExecutedWhois = false;
        currentRateLimitInterval = rateLimitInterval;
        currentCacheHitInterval = cacheHitInterval;
        consecutiveWhoisCount = 0;
        whoisWindowStart = null;
        whoisQueriesInWindow = 0;
    }

    /**
     * 現在の（動的調整後の）通常whois検索ベース間隔を返します。
     */
    public synchronized Duration getCurrentRateLimitInterval() {
        return currentRateLimitInterval;
    }

    /**
     * 現在の（動的調整後の）キャッシュヒット時待機時間を返します。
     */
    public synchronized Duration getCurrentCacheHitInterval() {
        return currentCacheHitInterval;
    }

    /**
     * これまでに検出・キャッシュされたすべての {@link WhoisCidrInfo} 一覧を返します。
     */
    public synchronized List<WhoisCidrInfo> getCachedResults() {
        return cidrCache.values().stream().map(CachedEntry::info).toList();
    }

    private CachedEntry findContainingEntry(InetAddress address) {
        // より具体的な（プレフィックス長が長い）CIDRキャッシュエントリを優先して検索
        CachedEntry bestEntry = null;
        int bestPrefix = -1;

        for (CachedEntry entry : cidrCache.values()) {
            for (CidrBlock block : entry.blocks()) {
                if (block.contains(address) && block.getPrefixLength() > bestPrefix) {
                    bestEntry = entry;
                    bestPrefix = block.getPrefixLength();
                }
            }
        }
        return bestEntry;
    }

    private String executeWhoisWithRetry(String ip, int current, int total) {
        waitForRateLimitIfNeeded(ip, current, total);

        int attempt = 0;
        while (true) {
            attempt++;
            hasExecutedWhois = true;
            if (whoisWindowStart == null) {
                whoisWindowStart = clock.instant();
            }
            whoisQueriesInWindow++;
            logStatus("[WHOIS] [%d/%d] Querying whois for %s...", current, total, ip);
            try {
                String rawWhois = whoisExecutor.executeWhois(ip);
                if (!whoisParser.isRateLimited(rawWhois)) {
                    consecutiveWhoisCount++;
                    return rawWhois;
                }
                adjustIntervalsOnRateLimit(ip);
                if (attempt > maxRateLimitRetries) {
                    throw new WhoisException(
                            "Rate limit persisted after " + maxRateLimitRetries + " retries for IP: " + ip);
                }
                Duration cooldown = calculateCooldownForAttempt(attempt, true);
                logStatus(
                        "[WHOIS] [WARN] Rate limit detected for IP %s. Waiting %d seconds before retry (%d/%d)...",
                        ip, cooldown.toSeconds(), attempt, maxRateLimitRetries);
                sleepDuration(cooldown);
                continue;
            } catch (WhoisException e) {
                if (attempt > maxRateLimitRetries) {
                    throw e;
                }
                Duration cooldown = calculateCooldownForAttempt(attempt, false);
                logStatus(
                        "[WHOIS] [WARN] Query failed (%s) for IP %s. Waiting %d seconds before retry (%d/%d)...",
                        e.getMessage(), ip, cooldown.toSeconds(), attempt, maxRateLimitRetries);
                sleepDuration(cooldown);
            }
        }
    }

    private Duration calculateCooldownForAttempt(int attempt, boolean isRateLimit) {
        if (rateLimitCooldown.isZero()) {
            return Duration.ZERO;
        }
        if (isRateLimit && attempt == 1) {
            return initialRateLimitCooldown;
        }
        long baseMillis = rateLimitCooldown.toMillis();
        long maxMillis = Math.max(baseMillis, maxRateLimitCooldown.toMillis());
        int shift = Math.min(Math.max(attempt - 1, 0), 30);
        long multiplier = 1L << shift;
        if (baseMillis > maxMillis / multiplier) {
            return Duration.ofMillis(maxMillis);
        }
        return Duration.ofMillis(Math.min(maxMillis, baseMillis * multiplier));
    }

    private void adjustIntervalsOnRateLimit(String ip) {
        Instant now = clock.instant();
        Duration elapsed = (whoisWindowStart != null)
                ? Duration.between(whoisWindowStart, now)
                : Duration.ZERO;
        if (elapsed.isNegative()) {
            elapsed = Duration.ZERO;
        }

        if (!currentRateLimitInterval.isZero()) {
            long currentMillis = currentRateLimitInterval.toMillis();
            long steppedMillis = Math.round(currentMillis * 1.5);
            if (steppedMillis <= currentMillis) {
                steppedMillis = currentMillis + 1_000L;
            }

            long elapsedBasedMillis = 0L;
            if (whoisQueriesInWindow > 1 && !elapsed.isZero()) {
                // レートリミット到達までの平均間隔を算出し、安全マージン（1.5倍）を次回待機間隔の目安とする
                long avgIntervalMillis = elapsed.toMillis() / (whoisQueriesInWindow - 1);
                elapsedBasedMillis = Math.round(avgIntervalMillis * 1.5);
            }

            long maxMillis = Math.max(currentMillis, maxRateLimitInterval.toMillis());
            long newRateLimitMillis = Math.min(maxMillis, Math.max(steppedMillis, elapsedBasedMillis));
            currentRateLimitInterval = Duration.ofMillis(newRateLimitMillis);
        }

        if (!currentCacheHitInterval.isZero()) {
            long currentCacheMillis = currentCacheHitInterval.toMillis();
            long maxCacheMillis = Math.max(currentCacheMillis, maxCacheHitInterval.toMillis());
            long newCacheMillis = Math.min(
                    maxCacheMillis,
                    Math.max(currentCacheMillis + 250L, Math.round(currentCacheMillis * 1.5)));
            currentCacheHitInterval = Duration.ofMillis(newCacheMillis);
        }

        logStatus(
                "[WHOIS] [INFO] Adjusted intervals after rate limit on %s (elapsed: %ds, queries: %d) -> whois interval: %s, cache-hit interval: %s",
                ip,
                elapsed.toSeconds(),
                whoisQueriesInWindow,
                formatDurationSeconds(currentRateLimitInterval),
                formatDurationSeconds(currentCacheHitInterval));

        consecutiveWhoisCount = 0;
        whoisWindowStart = null;
        whoisQueriesInWindow = 0;
    }

    private void waitForRateLimitIfNeeded(String ip, int current, int total) {
        if (!hasExecutedWhois || currentRateLimitInterval.isZero()) {
            return;
        }
        Duration additionalDelay = (!consecutiveWhoisIncrement.isZero() && consecutiveWhoisCount > 0)
                ? consecutiveWhoisIncrement.multipliedBy(consecutiveWhoisCount)
                : Duration.ZERO;
        Duration waitTime = currentRateLimitInterval.plus(additionalDelay);
        Duration effectiveMax = currentRateLimitInterval.compareTo(maxRateLimitInterval) > 0
                ? currentRateLimitInterval
                : maxRateLimitInterval;
        if (waitTime.compareTo(effectiveMax) > 0) {
            waitTime = effectiveMax;
        }
        logStatus(
                "[WHOIS] [%d/%d] Waiting %s for rate limit before querying %s...",
                current,
                total,
                formatDurationSeconds(waitTime),
                ip);
        sleepDuration(waitTime);
    }

    private static String formatDurationSeconds(Duration duration) {
        long millis = duration.toMillis();
        if (millis % 1_000L == 0L) {
            return (millis / 1_000L) + " second(s)";
        }
        return String.format("%.2f second(s)", millis / 1_000.0d);
    }

    private void logStatus(String format, Object... args) {
        System.out.println(String.format(format, args));
        System.out.flush();
    }

    private void sleepDuration(Duration duration) {
        if (duration.isZero()) {
            return;
        }
        try {
            sleeper.sleep(duration);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new WhoisException("Interrupted while waiting for whois rate limit", e);
        }
    }
}
