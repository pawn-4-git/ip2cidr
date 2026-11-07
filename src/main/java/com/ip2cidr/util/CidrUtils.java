package com.ip2cidr.util;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * IPv4 / IPv6 アドレスおよびCIDR・IP範囲変換のユーティリティクラス。
 */
public final class CidrUtils {

    private CidrUtils() {
    }

    /**
     * DNS逆引きを行わずにIPアドレスリテラルを解析します。
     */
    public static InetAddress parseIpAddress(String ipText) {
        if (ipText == null || ipText.isBlank()) {
            throw new IllegalArgumentException("IP address must not be null or blank");
        }
        String cleaned = ipText.trim();
        int zoneIdx = cleaned.indexOf('%');
        if (zoneIdx > 0) {
            cleaned = cleaned.substring(0, zoneIdx);
        }
        return InetAddress.ofLiteral(cleaned);
    }

    /**
     * 文字列が有効なIPv4またはIPv6アドレスリテラルであるかを判定します。
     */
    public static boolean isValidIpAddress(String ipText) {
        try {
            parseIpAddress(ipText);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * 2つの {@link InetAddress} を数値順（IPv4 → IPv6、各オクテットの符号なし数値昇順）で比較します。
     */
    public static int compareIpAddresses(InetAddress a, InetAddress b) {
        byte[] bytesA = a.getAddress();
        byte[] bytesB = b.getAddress();
        int lenCmp = Integer.compare(bytesA.length, bytesB.length);
        if (lenCmp != 0) {
            return lenCmp;
        }
        return Arrays.compareUnsigned(bytesA, bytesB);
    }

    /**
     * CIDR表記（例: "203.0.113.0/24", "192.168/16", "2001:db8::/32"）を解析してCidrBlockを生成します。
     */
    public static CidrBlock parseCidr(String cidrText) {
        if (cidrText == null || cidrText.isBlank()) {
            throw new IllegalArgumentException("CIDR must not be null or blank");
        }
        String trimmed = cidrText.trim();
        int slashIdx = trimmed.indexOf('/');
        if (slashIdx <= 0 || slashIdx == trimmed.length() - 1) {
            throw new IllegalArgumentException("Invalid CIDR format: " + cidrText);
        }

        String ipPart = trimmed.substring(0, slashIdx).trim();
        String prefixPart = trimmed.substring(slashIdx + 1).trim();

        int prefixLength;
        try {
            prefixLength = Integer.parseInt(prefixPart);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid prefix length in CIDR: " + cidrText, e);
        }

        if (!ipPart.contains(":")) {
            ipPart = expandShortIpv4(ipPart);
        }

        InetAddress address = parseIpAddress(ipPart);
        byte[] raw = address.getAddress();
        int maxBits = raw.length * 8;

        if (prefixLength < 0 || prefixLength > maxBits) {
            throw new IllegalArgumentException(
                    "Prefix length out of bounds (" + prefixLength + " for " + maxBits + " bits): " + cidrText);
        }

        BigInteger value = new BigInteger(1, raw);
        return createCidrBlock(value, prefixLength, maxBits);
    }

    /**
     * 開始IPアドレスと終了IPアドレスの範囲から、その範囲を過不足なく表現する最小数のCidrBlockリストへ変換します。
     */
    public static List<CidrBlock> rangeToCidrs(String startIpText, String endIpText) {
        InetAddress startAddr = parseIpAddress(startIpText);
        InetAddress endAddr = parseIpAddress(endIpText);

        byte[] startBytes = startAddr.getAddress();
        byte[] endBytes = endAddr.getAddress();
        if (startBytes.length != endBytes.length) {
            throw new IllegalArgumentException(
                    "Start IP and End IP must belong to the same address family: " + startIpText + " - " + endIpText);
        }

        int maxBits = startBytes.length * 8;
        BigInteger start = new BigInteger(1, startBytes);
        BigInteger end = new BigInteger(1, endBytes);

        if (start.compareTo(end) > 0) {
            throw new IllegalArgumentException("Start IP must be <= End IP: " + startIpText + " - " + endIpText);
        }

        List<CidrBlock> blocks = new ArrayList<>();
        BigInteger current = start;

        while (current.compareTo(end) <= 0) {
            int trailingZeros = current.signum() == 0 ? maxBits : current.getLowestSetBit();
            BigInteger remaining = end.subtract(current).add(BigInteger.ONE);
            int maxBitsFromRemaining = remaining.bitLength() - 1;
            int hostBits = Math.min(trailingZeros, maxBitsFromRemaining);
            int prefixLength = maxBits - hostBits;

            blocks.add(createCidrBlock(current, prefixLength, maxBits));
            current = current.add(BigInteger.ONE.shiftLeft(hostBits));
        }

        return List.copyOf(blocks);
    }

    private static CidrBlock createCidrBlock(BigInteger ipValue, int prefixLength, int maxBits) {
        int hostBits = maxBits - prefixLength;
        BigInteger allOnes = BigInteger.ONE.shiftLeft(maxBits).subtract(BigInteger.ONE);
        BigInteger hostMask = hostBits == 0
                ? BigInteger.ZERO
                : BigInteger.ONE.shiftLeft(hostBits).subtract(BigInteger.ONE);
        BigInteger netMask = allOnes.xor(hostMask);

        BigInteger startValue = ipValue.and(netMask);
        BigInteger endValue = startValue.or(hostMask);

        InetAddress networkAddress = toInetAddress(startValue, maxBits / 8);
        InetAddress broadcastAddress = toInetAddress(endValue, maxBits / 8);
        String canonicalCidr = networkAddress.getHostAddress() + "/" + prefixLength;

        return new CidrBlock(
                canonicalCidr,
                networkAddress,
                broadcastAddress,
                prefixLength,
                maxBits,
                startValue,
                endValue);
    }

    private static InetAddress toInetAddress(BigInteger value, int byteLength) {
        byte[] raw = value.toByteArray();
        byte[] padded = new byte[byteLength];

        int srcPos = Math.max(0, raw.length - byteLength);
        int copyLen = Math.min(raw.length, byteLength);
        int destPos = byteLength - copyLen;
        System.arraycopy(raw, srcPos, padded, destPos, copyLen);

        try {
            return InetAddress.getByAddress(padded);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Unexpected error converting bytes to InetAddress", e);
        }
    }

    /**
     * "192.168" -> "192.168.0.0" のような短縮IPv4表記を4オクテットに補完します。
     */
    private static String expandShortIpv4(String ipv4Part) {
        String[] parts = ipv4Part.split("\\.", -1);
        if (parts.length >= 1 && parts.length < 4) {
            for (String p : parts) {
                if (p.isEmpty() || !p.chars().allMatch(Character::isDigit)) {
                    return ipv4Part;
                }
            }
            StringBuilder sb = new StringBuilder(ipv4Part);
            for (int i = parts.length; i < 4; i++) {
                sb.append(".0");
            }
            return sb.toString();
        }
        return ipv4Part;
    }
}

