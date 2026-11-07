package com.ip2cidr.model;

import java.util.Objects;

/**
 * CIDRのネットワークIPアドレスとプレフィックス長（"/" 以降の数値）をまとめたモデルクラス。
 */
public final class Cidr {

    private final String ipAddress;
    private final int prefixLength;

    /**
     * ネットワークIPアドレスとプレフィックス長を指定して {@link Cidr} を生成します。
     *
     * @param ipAddress    ネットワークIPアドレス（例: "8.8.8.0", "2001:db8::"）
     * @param prefixLength プレフィックス長（例: 24, 32）
     */
    public Cidr(String ipAddress, int prefixLength) {
        if (ipAddress == null || ipAddress.isBlank()) {
            throw new IllegalArgumentException("ipAddress must not be null or blank");
        }
        if (prefixLength < 0 || prefixLength > 128) {
            throw new IllegalArgumentException("prefixLength must be between 0 and 128: " + prefixLength);
        }
        this.ipAddress = ipAddress.trim();
        this.prefixLength = prefixLength;
    }

    /**
     * CIDR表記文字列（例: "8.8.8.0/24", "2001:db8::/32"）から {@link Cidr} インスタンスを生成します。
     *
     * @param cidrNotation CIDR表記文字列
     * @return 解析された {@link Cidr}
     */
    public static Cidr parse(String cidrNotation) {
        if (cidrNotation == null || cidrNotation.isBlank()) {
            throw new IllegalArgumentException("cidrNotation must not be null or blank");
        }
        String trimmed = cidrNotation.trim();
        int slashIdx = trimmed.indexOf('/');
        if (slashIdx <= 0 || slashIdx == trimmed.length() - 1) {
            throw new IllegalArgumentException("Invalid CIDR notation: " + cidrNotation);
        }
        String ipPart = trimmed.substring(0, slashIdx).trim();
        String prefixPart = trimmed.substring(slashIdx + 1).trim();
        try {
            int prefixLen = Integer.parseInt(prefixPart);
            return new Cidr(ipPart, prefixLen);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid prefix length in CIDR notation: " + cidrNotation, e);
        }
    }

    /**
     * CIDRのIPアドレス部分（例: "8.8.8.0", "2001:db8::"）を返します。
     */
    public String getIpAddress() {
        return ipAddress;
    }

    /**
     * CIDRのプレフィックス長（"/" 以降の数値、例: 24, 32）を返します。
     * 範囲の大きさや検出結果の妥当性を判断する指標として使用できます（数値が小さいほど範囲が広い）。
     */
    public int getPrefixLength() {
        return prefixLength;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Cidr cidr)) return false;
        return prefixLength == cidr.prefixLength
                && Objects.equals(ipAddress, cidr.ipAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ipAddress, prefixLength);
    }

    /**
     * "IPアドレス/プレフィックス長" 形式のCIDR表記文字列（例: "8.8.8.0/24"）を返します。
     */
    @Override
    public String toString() {
        return ipAddress + "/" + prefixLength;
    }
}

