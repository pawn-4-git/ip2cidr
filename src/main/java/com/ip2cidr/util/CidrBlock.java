package com.ip2cidr.util;

import com.ip2cidr.model.Cidr;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.Objects;

/**
 * IPv4 / IPv6 の単一CIDRブロックを表し、包含判定や範囲算出を行う不変クラス。
 */
public final class CidrBlock implements Comparable<CidrBlock> {

    private final String cidr;
    private final InetAddress networkAddress;
    private final InetAddress broadcastAddress;
    private final int prefixLength;
    private final int maxBits;
    private final BigInteger startValue;
    private final BigInteger endValue;

    CidrBlock(
            String cidr,
            InetAddress networkAddress,
            InetAddress broadcastAddress,
            int prefixLength,
            int maxBits,
            BigInteger startValue,
            BigInteger endValue) {
        this.cidr = Objects.requireNonNull(cidr, "cidr must not be null");
        this.networkAddress = Objects.requireNonNull(networkAddress, "networkAddress must not be null");
        this.broadcastAddress = Objects.requireNonNull(broadcastAddress, "broadcastAddress must not be null");
        this.prefixLength = prefixLength;
        this.maxBits = maxBits;
        this.startValue = Objects.requireNonNull(startValue, "startValue must not be null");
        this.endValue = Objects.requireNonNull(endValue, "endValue must not be null");
    }

    /**
     * CIDR文字列（例: "192.0.2.0/24" または "2001:db8::/32"）をパースします。
     */
    public static CidrBlock parse(String cidrText) {
        return CidrUtils.parseCidr(cidrText);
    }

    /**
     * 指定されたIPアドレス文字列がこのCIDR領域に含まれるかを判定します。
     */
    public boolean contains(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return false;
        }
        try {
            InetAddress target = CidrUtils.parseIpAddress(ipAddress.trim());
            return contains(target);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * 指定されたInetAddressがこのCIDR領域に含まれるかを判定します。
     */
    public boolean contains(InetAddress address) {
        if (address == null) {
            return false;
        }
        byte[] raw = address.getAddress();
        if (raw.length * 8 != this.maxBits) {
            return false;
        }
        BigInteger value = new BigInteger(1, raw);
        return value.compareTo(startValue) >= 0 && value.compareTo(endValue) <= 0;
    }

    /**
     * 正規化されたCIDR表記（例: "192.0.2.0/24"）を返します。
     */
    public String getCidr() {
        return cidr;
    }

    /**
     * このブロックを {@link Cidr} モデルインスタンスに変換して返します。
     */
    public Cidr toCidr() {
        return new Cidr(networkAddress.getHostAddress(), prefixLength);
    }

    /**
     * ネットワーク開始アドレスを返します。
     */
    public InetAddress getNetworkAddress() {
        return networkAddress;
    }

    /**
     * ブロードキャスト（終端）アドレスを返します。
     */
    public InetAddress getBroadcastAddress() {
        return broadcastAddress;
    }

    /**
     * プレフィックス長（IPv4: 0〜32, IPv6: 0〜128）を返します。
     */
    public int getPrefixLength() {
        return prefixLength;
    }

    /**
     * アドレスファミリーの最大ビット数（IPv4: 32, IPv6: 128）を返します。
     */
    public int getMaxBits() {
        return maxBits;
    }

    /**
     * IPv6ブロックであるかを返します。
     */
    public boolean isIpv6() {
        return maxBits == 128;
    }

    /**
     * "開始IP - 終了IP" 形式の範囲文字列を返します。
     */
    public String toRangeString() {
        return networkAddress.getHostAddress() + " - " + broadcastAddress.getHostAddress();
    }

    public BigInteger getStartValue() {
        return startValue;
    }

    public BigInteger getEndValue() {
        return endValue;
    }

    @Override
    public int compareTo(CidrBlock other) {
        int bitCmp = Integer.compare(this.maxBits, other.maxBits);
        if (bitCmp != 0) {
            return bitCmp;
        }
        int startCmp = this.startValue.compareTo(other.startValue);
        if (startCmp != 0) {
            return startCmp;
        }
        return Integer.compare(other.prefixLength, this.prefixLength);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CidrBlock cidrBlock)) return false;
        return prefixLength == cidrBlock.prefixLength
                && maxBits == cidrBlock.maxBits
                && Objects.equals(startValue, cidrBlock.startValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(prefixLength, maxBits, startValue);
    }

    @Override
    public String toString() {
        return cidr;
    }
}

