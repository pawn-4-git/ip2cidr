package com.ip2cidr.util;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import com.ip2cidr.util.CsvFormatter.OutputMode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsvFormatterTest {

    @Test
    void testFormatCidrModeAndIpMode() {
        WhoisCidrInfo info = new WhoisCidrInfo(
                new Cidr("8.8.8.0", 24),
                List.of(new Cidr("8.8.8.0", 24)),
                "8.8.8.0 - 8.8.8.255",
                List.of("8.8.8.8", "8.8.8.4"),
                "US",
                "Google, LLC",
                "GOGL",
                List.of("Google Public DNS"),
                List.of("ZG39-ARIN"),
                List.of("ZG39-ARIN"),
                List.of("network-abuse@google.com"),
                "raw text");

        // CIDR単位モード（2つのIPが1行にまとまる）
        String cidrCsv = CsvFormatter.format(List.of(info), OutputMode.CIDR, false);
        String[] cidrLines = cidrCsv.trim().split("\\R");
        assertEquals(2, cidrLines.length);
        assertTrue(cidrLines[0].startsWith("CIDR,NetworkIP,PrefixLength,"));
        assertTrue(cidrLines[1].startsWith("8.8.8.0/24,8.8.8.0,24,8.8.8.0/24,8.8.8.0 - 8.8.8.255,8.8.8.8; 8.8.8.4,US,\"Google, LLC\",GOGL,"));

        // IP単位モード（1行につき1つのIPアドレスとして2行出力される）
        String ipCsv = CsvFormatter.format(List.of(info), OutputMode.IP, false);
        String[] ipLines = ipCsv.trim().split("\\R");
        assertEquals(3, ipLines.length);
        assertTrue(ipLines[0].startsWith("IPAddress,CIDR,NetworkIP,PrefixLength,"));
        assertTrue(ipLines[1].startsWith("8.8.8.8,8.8.8.0/24,8.8.8.0,24,"));
        assertTrue(ipLines[2].startsWith("8.8.8.4,8.8.8.0/24,8.8.8.0,24,"));
    }
}

