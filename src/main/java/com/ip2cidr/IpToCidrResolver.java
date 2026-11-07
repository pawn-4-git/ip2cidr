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
import java.time.Duration;
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
 *   <li>同一CIDRに属する複数のIPアドレスは1つの {@link WhoisCidrInfo} インスタンスに統合されます。</li>
 *   <li>一度検出したCIDR領域に含まれる後続のIPアドレスはwhois検索をスキップし、検出済み情報を流用します。</li>
 *   <li>whois検索を実行する際は、レートリミット対策として検索間隔（デフォルト5秒）を空けて実行します。</li>
 * </ul>
 */
public class IpToCidrResolver {

    /**
     * デフォルトのwhois検索間隔（5秒）。
     */
    public static final Duration DEFAULT_RATE_LIMIT_INTERVAL = Duration.ofSeconds(5);

    /**
     * whoisサーバーからレートリミット（アクセス制限）を受けた際のデフォルト待機時間（1分）。
     */
    public static final Duration DEFAULT_RATE_LIMIT_COOLDOWN = Duration.ofMinutes(1);

    /**
     * レートリミット発生時のデフォルト最大リトライ回数（3回）。
     */
    public static final int DEFAULT_MAX_RATE_LIMIT_RETRIES = 3;

    /**
     * レートリミット待機処理を抽象化する関数型インターフェース。
     */
    @FunctionalInterface
    public interface Sleeper {
        void sleep(Duration duration) throws InterruptedException;
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
    private final Duration rateLimitCooldown;
    private final int maxRateLimitRetries;
    private final Sleeper sleeper;

    private final Map<Cidr, CachedEntry> cidrCache = new LinkedHashMap<>();
    private boolean hasExecutedWhois = false;

    /**
     * デフォルト設定（OSのwhoisコマンド使用、通常検索間隔5秒、レートリミット発生時1分待機）でリゾルバを生成します。
     */
    public IpToCidrResolver() {
        this(
                new CommandWhoisExecutor(),
                new WhoisParser(),
                DEFAULT_RATE_LIMIT_INTERVAL,
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
        this.whoisExecutor = Objects.requireNonNull(whoisExecutor, "whoisExecutor must not be null");
        this.whoisParser = Objects.requireNonNull(whoisParser, "whoisParser must not be null");
        this.rateLimitInterval = Objects.requireNonNull(rateLimitInterval, "rateLimitInterval must not be null");
        this.rateLimitCooldown = Objects.requireNonNull(rateLimitCooldown, "rateLimitCooldown must not be null");
        this.maxRateLimitRetries = maxRateLimitRetries;
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper must not be null");
        if (rateLimitInterval.isNegative()) {
            throw new IllegalArgumentException("rateLimitInterval must not be negative");
        }
        if (rateLimitCooldown.isNegative()) {
            throw new IllegalArgumentException("rateLimitCooldown must not be negative");
        }
        if (maxRateLimitRetries < 0) {
            throw new IllegalArgumentException("maxRateLimitRetries must not be negative");
        }
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
     *
     * @param ipAddresses 入力IPアドレスのコレクション（IPv4 / IPv6対応）
     * @return CIDR単位に集約された {@link WhoisCidrInfo} のリスト
     */
    public synchronized List<WhoisCidrInfo> resolve(Collection<String> ipAddresses) {
        if (ipAddresses == null || ipAddresses.isEmpty()) {
            return List.of();
        }

        Map<Cidr, WhoisCidrInfo> batchResults = new LinkedHashMap<>();

        for (String rawIp : ipAddresses) {
            if (rawIp == null || rawIp.isBlank()) {
                continue;
            }
            String ip = rawIp.trim();
            InetAddress parsedIp = CidrUtils.parseIpAddress(ip);

            // 1. 既に検出済みのCIDR領域に含まれるかチェック（含まれる場合はwhois検索を行わず流用）
            CachedEntry matchedEntry = findContainingEntry(parsedIp);
            if (matchedEntry != null) {
                WhoisCidrInfo existingInfo = matchedEntry.info();
                existingInfo.addMatchedIpAddress(ip);
                batchResults.putIfAbsent(existingInfo.getCidr(), existingInfo);
                continue;
            }

            // 2. 未検出のIPアドレスの場合はレートリミット（通常5秒間隔、制限検知時は1分待機リトライ）を適用してwhoisを実行
            String rawWhois = executeWhoisWithRetry(ip);

            WhoisParser.ParsedResult parsedResult = whoisParser.parseWithBlocks(ip, rawWhois);
            WhoisCidrInfo newInfo = parsedResult.info();
            Cidr primaryCidr = newInfo.getCidr();

            // 3. 同一CIDRが既に存在する場合は1つのWhoisCidrInfoクラスに統合
            CachedEntry existingByCidr = cidrCache.get(primaryCidr);
            if (existingByCidr != null) {
                WhoisCidrInfo existingInfo = existingByCidr.info();
                existingInfo.addMatchedIpAddress(ip);
                batchResults.putIfAbsent(primaryCidr, existingInfo);
            } else {
                CachedEntry newEntry = new CachedEntry(newInfo, parsedResult.cidrBlocks());
                cidrCache.put(primaryCidr, newEntry);
                batchResults.put(primaryCidr, newInfo);
            }
        }

        return new ArrayList<>(batchResults.values());
    }

    /**
     * リゾルバ内にキャッシュされている検出済みCIDR情報をクリアします。
     */
    public synchronized void clearCache() {
        cidrCache.clear();
        hasExecutedWhois = false;
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

    private String executeWhoisWithRetry(String ip) {
        waitForRateLimitIfNeeded();

        int attempt = 0;
        while (true) {
            attempt++;
            hasExecutedWhois = true;
            try {
                String rawWhois = whoisExecutor.executeWhois(ip);
                if (!whoisParser.isRateLimited(rawWhois) || attempt > maxRateLimitRetries) {
                    return rawWhois;
                }
                System.err.printf(
                        "[WARN] Whois rate limit detected for IP %s. Waiting %d seconds before retry (%d/%d)...%n",
                        ip, rateLimitCooldown.toSeconds(), attempt, maxRateLimitRetries);
            } catch (WhoisException e) {
                if (attempt > maxRateLimitRetries) {
                    throw e;
                }
                System.err.printf(
                        "[WARN] Whois query failed (%s) for IP %s. Waiting %d seconds before retry (%d/%d)...%n",
                        e.getMessage(), ip, rateLimitCooldown.toSeconds(), attempt, maxRateLimitRetries);
            }
            sleepDuration(rateLimitCooldown);
        }
    }

    private void waitForRateLimitIfNeeded() {
        if (!hasExecutedWhois || rateLimitInterval.isZero()) {
            return;
        }
        sleepDuration(rateLimitInterval);
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

