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

    private static final int IPV4_BYTE_LENGTH = 4;
    private static final int IPV6_BYTE_LENGTH = 16;
    private static final int IPV6_GROUP_COUNT = 8;

    private CidrUtils() {
    }

    /**
     * DNS逆引きやホスト名解決を一切行わずに、IPv4 / IPv6 アドレスリテラルを厳密に検証・解析します（Java 21互換）。
     * {@link InetAddress#getByName(String)}（内部で {@code getAllByName} によるDNS解決へフォールバックしうる）は使用せず、
     * リテラル文字列をバイト配列（4バイトまたは16バイト）へ変換した上で {@link InetAddress#getByAddress(byte[])} を呼び出します。
     */
    public static InetAddress parseIpAddress(String ipText) {
        if (ipText == null || ipText.isBlank()) {
            throw new IllegalArgumentException("IP address must not be null or blank");
        }
        String cleaned = ipText.trim();
        int zoneIdx = cleaned.indexOf('%');
        if (zoneIdx >= 0) {
            // ゾーンインデックス（%lo0 等）はIPv6リテラルのみ許可し、%の前後が空でないことを要求する
            if (zoneIdx == 0 || zoneIdx == cleaned.length() - 1 || cleaned.indexOf(':') < 0) {
                throw new IllegalArgumentException("Invalid IP address literal: " + ipText);
            }
            cleaned = cleaned.substring(0, zoneIdx);
        }

        byte[] rawBytes = cleaned.indexOf(':') >= 0
                ? textToNumericFormatV6(cleaned)
                : textToNumericFormatV4(cleaned);
        if (rawBytes == null) {
            throw new IllegalArgumentException("Invalid IP address literal: " + ipText);
        }
        try {
            return InetAddress.getByAddress(rawBytes);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Unexpected byte length for InetAddress", e);
        }
    }

    /**
     * IPv4リテラル文字列（"a.b.c.d"）を検証し、4バイト配列に変換します。不正な場合は {@code null} を返します。
     */
    static byte[] textToNumericFormatV4(String text) {
        String[] parts = text.split("\\.", -1);
        if (parts.length != IPV4_BYTE_LENGTH) {
            return null;
        }
        byte[] bytes = new byte[IPV4_BYTE_LENGTH];
        for (int i = 0; i < IPV4_BYTE_LENGTH; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 3) {
                return null;
            }
            if (part.length() > 1 && part.charAt(0) == '0') {
                return null;
            }
            int val = 0;
            for (int j = 0; j < part.length(); j++) {
                char c = part.charAt(j);
                if (c < '0' || c > '9') {
                    return null;
                }
                val = val * 10 + (c - '0');
            }
            if (val > 255) {
                return null;
            }
            bytes[i] = (byte) val;
        }
        return bytes;
    }

    /**
     * IPv6リテラル文字列（8グループ・"::"ゼロ圧縮・末尾IPv4埋め込み表記）をRFC 4291準拠で検証し、
     * 16バイト配列に変換します。不正な場合は {@code null} を返します。
     */
    static byte[] textToNumericFormatV6(String text) {
        if (text.length() < 2) {
            return null;
        }

        String hexText = text;
        if (hexText.indexOf('.') >= 0) {
            int lastColon = hexText.lastIndexOf(':');
            byte[] ipv4Bytes = textToNumericFormatV4(hexText.substring(lastColon + 1));
            if (ipv4Bytes == null) {
                return null;
            }
            String ipv4HexGroups = String.format(
                    "%02x%02x:%02x%02x",
                    ipv4Bytes[0] & 0xff,
                    ipv4Bytes[1] & 0xff,
                    ipv4Bytes[2] & 0xff,
                    ipv4Bytes[3] & 0xff);
            hexText = hexText.substring(0, lastColon + 1) + ipv4HexGroups;
        }

        if ((hexText.startsWith(":") && !hexText.startsWith("::"))
                || (hexText.endsWith(":") && !hexText.endsWith("::"))) {
            return null;
        }

        byte[] bytes = new byte[IPV6_BYTE_LENGTH];
        int doubleColonIdx = hexText.indexOf("::");
        if (doubleColonIdx >= 0) {
            if (hexText.indexOf("::", doubleColonIdx + 1) >= 0) {
                return null;
            }
            String leftPart = hexText.substring(0, doubleColonIdx);
            String rightPart = hexText.substring(doubleColonIdx + 2);
            String[] leftGroups = leftPart.isEmpty() ? new String[0] : leftPart.split(":", -1);
            String[] rightGroups = rightPart.isEmpty() ? new String[0] : rightPart.split(":", -1);

            if (leftGroups.length + rightGroups.length >= IPV6_GROUP_COUNT) {
                return null;
            }

            for (int i = 0; i < leftGroups.length; i++) {
                int val = parseHexGroup16(leftGroups[i]);
                if (val < 0) {
                    return null;
                }
                bytes[i * 2] = (byte) (val >>> 8);
                bytes[i * 2 + 1] = (byte) val;
            }

            int rightStartGroup = IPV6_GROUP_COUNT - rightGroups.length;
            for (int i = 0; i < rightGroups.length; i++) {
                int val = parseHexGroup16(rightGroups[i]);
                if (val < 0) {
                    return null;
                }
                int groupIdx = rightStartGroup + i;
                bytes[groupIdx * 2] = (byte) (val >>> 8);
                bytes[groupIdx * 2 + 1] = (byte) val;
            }
            return bytes;
        }

        String[] groups = hexText.split(":", -1);
        if (groups.length != IPV6_GROUP_COUNT) {
            return null;
        }
        for (int i = 0; i < IPV6_GROUP_COUNT; i++) {
            int val = parseHexGroup16(groups[i]);
            if (val < 0) {
                return null;
            }
            bytes[i * 2] = (byte) (val >>> 8);
            bytes[i * 2 + 1] = (byte) val;
        }
        return bytes;
    }

    private static int parseHexGroup16(String group) {
        if (group.length() > 4) {
            return -1;
        }
        int val = 0;
        for (int i = 0; i < group.length(); i++) {
            char c = group.charAt(i);
            int digit;
            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                digit = c - 'A' + 10;
            } else {
                return -1;
            }
            val = (val << 4) | digit;
        }
        return val;
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
     * CIDR表記（例: "203.0.113.0/24", "192.168/16",
     * "2001:db8::/32"）を解析してCidrBlockを生成します。
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
