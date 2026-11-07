package com.ip2cidr.whois;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import com.ip2cidr.util.CidrBlock;
import com.ip2cidr.util.CidrUtils;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * whoisコマンドの出力テキストを解析し、CIDR・IP範囲・国・登録組織・連絡先などを抽出するパーサー。
 * ARIN / APNIC / RIPE / LACNIC / AFRINIC / JPNIC 等の主要フォーマットに対応します。
 */
public class WhoisParser {

    private static final Pattern KEY_VALUE_PATTERN =
            Pattern.compile("^\\s*([A-Za-z0-9_\\-]+)\\s*:\\s*(.+?)\\s*$");

    // JPNIC形式: "a. [Network Number] 192.0.2.0/24" または "[ネットワーク番号] 192.0.2.0/24"
    private static final Pattern JPNIC_PATTERN =
            Pattern.compile("^\\s*(?:[a-z]\\.)?\\s*\\[([^\\]]+)\\]\\s*(.+?)\\s*$");

    // "% Abuse contact for '1.1.1.0 - 1.1.1.255' is 'abuse@cloudflare.com'"
    private static final Pattern COMMENT_ABUSE_EMAIL_PATTERN =
            Pattern.compile("(?i)abuse\\s+contact\\s+for\\s+.*\\s+is\\s+'([^']+)'");

    // "192.0.2.0 - 192.0.2.255" または "2001:db8:: - 2001:db8:ffff::"
    private static final Pattern IP_RANGE_PATTERN =
            Pattern.compile("^\\s*([0-9a-fA-F:.]+)\\s*-\\s*([0-9a-fA-F:.]+)\\s*$");

    // 各RIR（APNIC/RIPE/ARIN/LACNIC/AFRINIC/JPNIC等）のレートリミット・一時ブロック応答パターン
    private static final Pattern RATE_LIMIT_PATTERN = Pattern.compile(
            "(?i)(rate[-\\s]?limit|limit\\s+exceeded|quota\\s+exceeded"
                    + "|too\\s+many\\s+(requests|queries|connections)"
                    + "|access\\s+(from\\s+your\\s+host\\s+has\\s+been\\s+)?(temporarily\\s+)?denied"
                    + "|error:\\s*201"
                    + "|exceeded\\s+the\\s+maximum\\s+allowable"
                    + "|try\\s+again\\s+later"
                    + "|connection\\s+reset\\s+by\\s+peer"
                    + "|connection\\s+refused"
                    + "|operation\\s+timed\\s+out)");

    /**
     * 解析結果（WhoisCidrInfo と 判定用CidrBlockリストのペア）。
     */
    public record ParsedResult(WhoisCidrInfo info, List<CidrBlock> cidrBlocks) {
    }

    private record NetworkCandidate(List<CidrBlock> blocks, String ipRange, boolean explicitCidr, int order) {
        CidrBlock findMatchingBlock(InetAddress targetIp) {
            CidrBlock best = null;
            for (CidrBlock block : blocks) {
                if (block.getPrefixLength() == 0) {
                    continue;
                }
                if (block.contains(targetIp)) {
                    if (best == null || block.getPrefixLength() > best.getPrefixLength()) {
                        best = block;
                    }
                }
            }
            return best;
        }
    }

    /**
     * whois出力テキストにレートリミットや一時的なアクセス制限エラーが含まれているかを判定します。
     */
    public boolean isRateLimited(String rawWhoisOutput) {
        if (rawWhoisOutput == null || rawWhoisOutput.isBlank()) {
            return false;
        }
        return RATE_LIMIT_PATTERN.matcher(rawWhoisOutput).find();
    }

    /**
     * whois出力と検索対象IPアドレスから {@link WhoisCidrInfo} を生成します。
     */
    public WhoisCidrInfo parse(String queriedIp, String rawWhoisOutput) {
        return parseWithBlocks(queriedIp, rawWhoisOutput).info();
    }

    /**
     * whois出力と検索対象IPアドレスから {@link ParsedResult}（情報クラス＋CidrBlock一覧）を生成します。
     */
    public ParsedResult parseWithBlocks(String queriedIp, String rawWhoisOutput) {
        if (queriedIp == null || queriedIp.isBlank()) {
            throw new IllegalArgumentException("queriedIp must not be null or blank");
        }
        if (rawWhoisOutput == null) {
            rawWhoisOutput = "";
        }

        InetAddress targetAddress = CidrUtils.parseIpAddress(queriedIp.trim());

        List<NetworkCandidate> candidates = new ArrayList<>();
        int candidateOrder = 0;

        String country = "";
        List<String> orgCandidates = new ArrayList<>();
        List<String> netNames = new ArrayList<>();
        Set<String> descriptions = new LinkedHashSet<>();
        Set<String> adminContacts = new LinkedHashSet<>();
        Set<String> techContacts = new LinkedHashSet<>();
        Set<String> abuseContacts = new LinkedHashSet<>();

        String[] lines = rawWhoisOutput.split("\\R");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            // コメント内のAbuse連絡先抽出（RIPE / APNIC 等）
            if (trimmed.startsWith("%") || trimmed.startsWith("#")) {
                Matcher abuseMatcher = COMMENT_ABUSE_EMAIL_PATTERN.matcher(trimmed);
                if (abuseMatcher.find()) {
                    abuseContacts.add(abuseMatcher.group(1).trim());
                }
                continue;
            }

            // JPNIC形式の解析
            Matcher jpnicMatcher = JPNIC_PATTERN.matcher(trimmed);
            if (jpnicMatcher.matches()) {
                String jpKey = jpnicMatcher.group(1).trim().toLowerCase(Locale.ROOT);
                String jpVal = stripInlineComment(jpnicMatcher.group(2).trim());
                if (!jpVal.isEmpty()) {
                    switch (jpKey) {
                        case "network number", "ネットワーク番号" -> {
                            NetworkCandidate cand = parseNetworkValue(jpVal, candidateOrder++);
                            if (cand != null) {
                                candidates.add(cand);
                            }
                        }
                        case "network name", "ネットワーク名" -> netNames.add(jpVal);
                        case "organization", "組織名" -> orgCandidates.add(jpVal);
                        case "administrative contact", "管理者連絡窓口" -> adminContacts.add(jpVal);
                        case "technical contact", "技術連絡担当者" -> techContacts.add(jpVal);
                        case "country", "国コード" -> {
                            if (!isPlaceholderCountry(jpVal)) {
                                country = jpVal.toUpperCase(Locale.ROOT);
                            }
                        }
                        default -> {
                        }
                    }
                }
                continue;
            }

            // 標準的な Key: Value 行の解析
            Matcher kvMatcher = KEY_VALUE_PATTERN.matcher(trimmed);
            if (kvMatcher.matches()) {
                String key = kvMatcher.group(1).trim().toLowerCase(Locale.ROOT);
                String rawVal = kvMatcher.group(2).trim();
                String val = stripInlineComment(rawVal);
                if (val.isEmpty()) {
                    continue;
                }

                switch (key) {
                    case "cidr", "route", "route6" -> {
                        NetworkCandidate cand = parseExplicitCidrValue(val, candidateOrder++);
                        if (cand != null) {
                            candidates.add(cand);
                        }
                    }
                    case "inetnum", "inet6num", "netrange" -> {
                        NetworkCandidate cand = parseNetworkValue(val, candidateOrder++);
                        if (cand != null) {
                            candidates.add(cand);
                        }
                    }
                    case "country" -> {
                        if (!isPlaceholderCountry(rawVal) && !isPlaceholderCountry(val)) {
                            country = val.toUpperCase(Locale.ROOT);
                        }
                    }
                    case "org-name", "orgname", "organization", "owner" -> {
                        if (!isIanaPlaceholder(val)) {
                            orgCandidates.add(val);
                        }
                    }
                    case "netname" -> {
                        if (!isIanaPlaceholder(val)) {
                            netNames.add(val);
                        }
                    }
                    case "descr", "comment" -> {
                        if (!isIanaPlaceholder(val)) {
                            descriptions.add(val);
                        }
                    }
                    case "admin-c", "orgadminhandle", "adminhandle" -> adminContacts.add(val);
                    case "tech-c", "orgtechhandle", "techhandle", "zone-c" -> techContacts.add(val);
                    case "abuse-mailbox", "orgabuseemail", "abuse-c", "orgabusehandle" -> abuseContacts.add(val);
                    default -> {
                    }
                }
            }
        }

        // 検索対象IPを包含する最も具体的な（プレフィックス長が最大の）ネットワーク候補を選択
        NetworkCandidate selectedCandidate = selectBestCandidate(candidates, targetAddress);
        List<CidrBlock> finalBlocks;
        CidrBlock primaryBlock;
        String ipRange;

        if (selectedCandidate != null) {
            finalBlocks = selectedCandidate.blocks();
            CidrBlock matched = selectedCandidate.findMatchingBlock(targetAddress);
            primaryBlock = matched != null ? matched : finalBlocks.getFirst();
            ipRange = selectedCandidate.ipRange();
        } else {
            // 万一whois出力から有効なCIDRも範囲も検出できなかった場合は単一ホストCIDR (/32 または /128) にフォールバック
            int hostPrefix = targetAddress.getAddress().length * 8;
            primaryBlock = CidrUtils.parseCidr(targetAddress.getHostAddress() + "/" + hostPrefix);
            finalBlocks = List.of(primaryBlock);
            ipRange = primaryBlock.toRangeString();
        }

        List<Cidr> allCidrs = finalBlocks.stream().map(CidrBlock::toCidr).toList();
        String netName = netNames.isEmpty() ? "" : netNames.getLast();
        String registrant = resolveRegistrant(orgCandidates, descriptions, netName);

        WhoisCidrInfo info = new WhoisCidrInfo(
                primaryBlock.toCidr(),
                allCidrs,
                ipRange,
                List.of(queriedIp.trim()),
                country,
                registrant,
                netName,
                new ArrayList<>(descriptions),
                new ArrayList<>(adminContacts),
                new ArrayList<>(techContacts),
                new ArrayList<>(abuseContacts),
                rawWhoisOutput);

        return new ParsedResult(info, finalBlocks);
    }

    private NetworkCandidate selectBestCandidate(List<NetworkCandidate> candidates, InetAddress targetAddress) {
        NetworkCandidate bestMatching = null;
        CidrBlock bestMatchingBlock = null;

        for (NetworkCandidate candidate : candidates) {
            CidrBlock matchingBlock = candidate.findMatchingBlock(targetAddress);
            if (matchingBlock == null) {
                continue;
            }
            if (bestMatching == null) {
                bestMatching = candidate;
                bestMatchingBlock = matchingBlock;
            } else {
                int prefixCmp = Integer.compare(matchingBlock.getPrefixLength(), bestMatchingBlock.getPrefixLength());
                if (prefixCmp > 0) {
                    bestMatching = candidate;
                    bestMatchingBlock = matchingBlock;
                } else if (prefixCmp == 0) {
                    // 同じプレフィックス長なら、明示的なCIDR指定、または後半（より詳細なRIRセクション）を優先
                    if (candidate.explicitCidr() && !bestMatching.explicitCidr()) {
                        bestMatching = candidate;
                        bestMatchingBlock = matchingBlock;
                    } else if (candidate.explicitCidr() == bestMatching.explicitCidr()
                            && candidate.order() > bestMatching.order()) {
                        bestMatching = candidate;
                        bestMatchingBlock = matchingBlock;
                    }
                }
            }
        }

        if (bestMatching != null) {
            return bestMatching;
        }

        // 対象IPを直接包含するブロックが見つからない場合、/0以外の最後の有効な候補を返す
        for (int i = candidates.size() - 1; i >= 0; i--) {
            NetworkCandidate cand = candidates.get(i);
            if (cand.blocks().stream().anyMatch(b -> b.getPrefixLength() > 0)) {
                return cand;
            }
        }
        return null;
    }

    private NetworkCandidate parseExplicitCidrValue(String value, int order) {
        String[] parts = value.split(",");
        List<CidrBlock> blocks = new ArrayList<>();
        for (String part : parts) {
            String token = part.trim();
            if (token.isEmpty()) {
                continue;
            }
            try {
                blocks.add(CidrUtils.parseCidr(token));
            } catch (IllegalArgumentException ignored) {
                // 不正なトークンは無視
            }
        }
        if (blocks.isEmpty()) {
            return null;
        }
        CidrBlock first = blocks.getFirst();
        CidrBlock last = blocks.getLast();
        String range = first.getNetworkAddress().getHostAddress()
                + " - "
                + last.getBroadcastAddress().getHostAddress();
        return new NetworkCandidate(List.copyOf(blocks), range, true, order);
    }

    private NetworkCandidate parseNetworkValue(String value, int order) {
        if (value.contains("/")) {
            return parseExplicitCidrValue(value, order);
        }
        Matcher rangeMatcher = IP_RANGE_PATTERN.matcher(value);
        if (rangeMatcher.matches()) {
            String startIp = rangeMatcher.group(1).trim();
            String endIp = rangeMatcher.group(2).trim();
            try {
                List<CidrBlock> blocks = CidrUtils.rangeToCidrs(startIp, endIp);
                if (!blocks.isEmpty()) {
                    String canonicalRange = CidrUtils.parseIpAddress(startIp).getHostAddress()
                            + " - "
                            + CidrUtils.parseIpAddress(endIp).getHostAddress();
                    return new NetworkCandidate(blocks, canonicalRange, false, order);
                }
            } catch (IllegalArgumentException ignored) {
                // 解析不能な範囲は無視
            }
        }
        return null;
    }

    private static String resolveRegistrant(
            List<String> orgCandidates,
            Set<String> descriptions,
            String netName) {
        if (!orgCandidates.isEmpty()) {
            return orgCandidates.getLast();
        }
        if (!descriptions.isEmpty()) {
            return descriptions.iterator().next();
        }
        return netName != null ? netName : "";
    }

    private static String stripInlineComment(String value) {
        int hashIdx = value.indexOf('#');
        if (hashIdx >= 0) {
            return value.substring(0, hashIdx).trim();
        }
        return value.trim();
    }

    private static boolean isPlaceholderCountry(String rawValue) {
        String lower = rawValue.toLowerCase(Locale.ROOT);
        if (lower.contains("world wide") || lower.contains("worldwide")) {
            return true;
        }
        String cleaned = stripInlineComment(rawValue);
        return cleaned.isEmpty() || cleaned.equalsIgnoreCase("ZZ");
    }

    private static boolean isIanaPlaceholder(String value) {
        String upper = value.toUpperCase(Locale.ROOT);
        return upper.equals("IANA-BLK")
                || upper.equals("IANA-IPV4-MAPPED-RESERVED")
                || upper.contains("INTERNET ASSIGNED NUMBERS AUTHORITY");
    }
}

