package com.ip2cidr.util;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

/**
 * {@link WhoisCidrInfo} のリストをCSV形式（CIDR単位またはIP単位）に整形・出力するユーティリティクラス。
 */
public final class CsvFormatter {

    /**
     * 出力単位モード。
     */
    public enum OutputMode {
        /**
         * 1行につき1つのCIDRブロック情報を出力（デフォルト）。
         */
        CIDR,
        /**
         * 1行につき1つの入力IPアドレス情報を出力。
         */
        IP;

        public static OutputMode fromString(String value) {
            if (value == null || value.isBlank()) {
                return CIDR;
            }
            return switch (value.trim().toLowerCase()) {
                case "cidr" -> CIDR;
                case "ip" -> IP;
                default -> throw new IllegalArgumentException(
                        "Invalid mode '" + value + "'. Supported modes are: cidr, ip");
            };
        }
    }

    private CsvFormatter() {
    }

    /**
     * 解決結果リストを指定されたモードでCSV文字列に変換します。
     *
     * @param results 解決された {@link WhoisCidrInfo} のリスト
     * @param mode    出力単位（{@link OutputMode#CIDR} または {@link OutputMode#IP}）
     * @param showRaw 生のwhois出力カラムを含めるかどうか
     * @return CSV形式の文字列
     */
    public static String format(List<WhoisCidrInfo> results, OutputMode mode, boolean showRaw) {
        StringBuilder sb = new StringBuilder();
        if (mode == OutputMode.IP) {
            appendIpModeHeader(sb, showRaw);
            if (results != null) {
                for (WhoisCidrInfo info : results) {
                    for (String ip : info.getMatchedIpAddresses()) {
                        appendIpModeRow(sb, ip, info, showRaw);
                    }
                }
            }
        } else {
            appendCidrModeHeader(sb, showRaw);
            if (results != null) {
                for (WhoisCidrInfo info : results) {
                    appendCidrModeRow(sb, info, showRaw);
                }
            }
        }
        return sb.toString();
    }

    /**
     * 解決結果リストを指定されたファイルパスにCSV形式で書き出します（UTF-8）。
     */
    public static void writeToFile(
            Path filePath,
            List<WhoisCidrInfo> results,
            OutputMode mode,
            boolean showRaw) throws IOException {
        String csvContent = format(results, mode, showRaw);
        Path parent = filePath.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }
        Files.writeString(filePath, csvContent, StandardCharsets.UTF_8);
    }

    private static void appendCidrModeHeader(StringBuilder sb, boolean showRaw) {
        sb.append("CIDR,NetworkIP,PrefixLength,AllCIDRs,IPRange,MatchedIPs,Country,Registrant,NetName,Descriptions,AdminContacts,TechContacts,AbuseContacts");
        if (showRaw) {
            sb.append(",RawWhoisOutput");
        }
        sb.append(System.lineSeparator());
    }

    private static void appendIpModeHeader(StringBuilder sb, boolean showRaw) {
        sb.append("IPAddress,CIDR,NetworkIP,PrefixLength,AllCIDRs,IPRange,Country,Registrant,NetName,Descriptions,AdminContacts,TechContacts,AbuseContacts");
        if (showRaw) {
            sb.append(",RawWhoisOutput");
        }
        sb.append(System.lineSeparator());
    }

    private static void appendCidrModeRow(StringBuilder sb, WhoisCidrInfo info, boolean showRaw) {
        Cidr cidr = info.getCidr();
        String allCidrs = info.getAllCidrs().stream()
                .map(Cidr::toString)
                .collect(Collectors.joining("; "));
        String matchedIps = String.join("; ", info.getMatchedIpAddresses());

        sb.append(escapeCsv(cidr.toString())).append(',')
                .append(escapeCsv(cidr.getIpAddress())).append(',')
                .append(cidr.getPrefixLength()).append(',')
                .append(escapeCsv(allCidrs)).append(',')
                .append(escapeCsv(info.getIpRange())).append(',')
                .append(escapeCsv(matchedIps)).append(',')
                .append(escapeCsv(info.getCountry())).append(',')
                .append(escapeCsv(info.getRegistrant())).append(',')
                .append(escapeCsv(info.getNetName())).append(',')
                .append(escapeCsv(String.join(" | ", info.getDescriptions()))).append(',')
                .append(escapeCsv(String.join("; ", info.getAdminContacts()))).append(',')
                .append(escapeCsv(String.join("; ", info.getTechContacts()))).append(',')
                .append(escapeCsv(String.join("; ", info.getAbuseContacts())));

        if (showRaw) {
            sb.append(',').append(escapeCsv(info.getRawWhoisOutput()));
        }
        sb.append(System.lineSeparator());
    }

    private static void appendIpModeRow(StringBuilder sb, String ip, WhoisCidrInfo info, boolean showRaw) {
        Cidr cidr = info.getCidr();
        String allCidrs = info.getAllCidrs().stream()
                .map(Cidr::toString)
                .collect(Collectors.joining("; "));

        sb.append(escapeCsv(ip)).append(',')
                .append(escapeCsv(cidr.toString())).append(',')
                .append(escapeCsv(cidr.getIpAddress())).append(',')
                .append(cidr.getPrefixLength()).append(',')
                .append(escapeCsv(allCidrs)).append(',')
                .append(escapeCsv(info.getIpRange())).append(',')
                .append(escapeCsv(info.getCountry())).append(',')
                .append(escapeCsv(info.getRegistrant())).append(',')
                .append(escapeCsv(info.getNetName())).append(',')
                .append(escapeCsv(String.join(" | ", info.getDescriptions()))).append(',')
                .append(escapeCsv(String.join("; ", info.getAdminContacts()))).append(',')
                .append(escapeCsv(String.join("; ", info.getTechContacts()))).append(',')
                .append(escapeCsv(String.join("; ", info.getAbuseContacts())));

        if (showRaw) {
            sb.append(',').append(escapeCsv(info.getRawWhoisOutput()));
        }
        sb.append(System.lineSeparator());
    }

    // Excel/Google Sheets等でCSVを開いた際に数式として実行されるのを防ぐための先頭文字
    private static final String FORMULA_TRIGGER_CHARS = "=+-@";

    static String escapeCsv(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        // whois応答（第三者が管理するレジストリ情報）由来の値が "=", "+", "-", "@" で始まる場合、
        // 表計算ソフトで開いた際に数式として評価されるCSVインジェクションを防ぐため先頭にシングルクォートを付与する
        String sanitized = FORMULA_TRIGGER_CHARS.indexOf(value.charAt(0)) >= 0 ? "'" + value : value;

        boolean needsQuotes = sanitized.indexOf(',') >= 0
                || sanitized.indexOf('"') >= 0
                || sanitized.indexOf('\n') >= 0
                || sanitized.indexOf('\r') >= 0
                || sanitized.length() != value.length();
        if (!needsQuotes) {
            return sanitized;
        }
        return "\"" + sanitized.replace("\"", "\"\"") + "\"";
    }
}

