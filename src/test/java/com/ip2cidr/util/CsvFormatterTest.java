package com.ip2cidr.util;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import com.ip2cidr.util.CsvFormatter.OutputMode;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    @Test
    void testShowRawNullResultsAndOutputModeFromString() {
        assertEquals(OutputMode.CIDR, OutputMode.fromString(null));
        assertEquals(OutputMode.CIDR, OutputMode.fromString("   "));
        assertEquals(OutputMode.CIDR, OutputMode.fromString("cidr"));
        assertEquals(OutputMode.CIDR, OutputMode.fromString(" CIDR "));
        assertEquals(OutputMode.IP, OutputMode.fromString("ip"));
        assertEquals(OutputMode.IP, OutputMode.fromString(" IP "));
        assertThrows(IllegalArgumentException.class, () -> OutputMode.fromString("invalid"));

        WhoisCidrInfo info = new WhoisCidrInfo(
                new Cidr("192.0.2.0", 24),
                List.of(new Cidr("192.0.2.0", 25), new Cidr("192.0.2.128", 25)),
                "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1"),
                "JP",
                "Example Org",
                "EX-NET",
                List.of("Desc 1", "Desc 2"),
                List.of("ADM1"),
                List.of("TECH1"),
                List.of("abuse@example.jp"),
                "line1\nline2");

        String cidrRawCsv = CsvFormatter.format(List.of(info), OutputMode.CIDR, true);
        assertTrue(cidrRawCsv.contains(",RawWhoisOutput"));
        assertTrue(cidrRawCsv.contains("\"line1\nline2\""));

        String ipRawCsv = CsvFormatter.format(List.of(info), OutputMode.IP, true);
        assertTrue(ipRawCsv.contains(",RawWhoisOutput"));
        assertTrue(ipRawCsv.contains("\"line1\nline2\""));

        // null リストの場合はヘッダーのみ出力されること
        String nullCidrCsv = CsvFormatter.format(null, OutputMode.CIDR, false);
        assertEquals(1, nullCidrCsv.trim().split("\\R").length);

        String nullIpCsv = CsvFormatter.format(null, OutputMode.IP, false);
        assertEquals(1, nullIpCsv.trim().split("\\R").length);
    }

    @Test
    void testEscapeCsvAndFormulaInjectionProtection() {
        assertEquals("", CsvFormatter.escapeCsv(null));
        assertEquals("", CsvFormatter.escapeCsv(""));
        assertEquals("plain", CsvFormatter.escapeCsv("plain"));
        assertEquals("\"'=SUM(A1:A2)\"", CsvFormatter.escapeCsv("=SUM(A1:A2)"));
        assertEquals("\"'+12345\"", CsvFormatter.escapeCsv("+12345"));
        assertEquals("\"'-12345\"", CsvFormatter.escapeCsv("-12345"));
        assertEquals("\"'@cmd\"", CsvFormatter.escapeCsv("@cmd"));
        assertEquals("\"a,\"\"b\"\",c\"", CsvFormatter.escapeCsv("a,\"b\",c"));
        assertEquals("\"quote\"\"only\"", CsvFormatter.escapeCsv("quote\"only"));
        assertEquals("\"line1\rline2\"", CsvFormatter.escapeCsv("line1\rline2"));
    }

    @Test
    void testWriteToFile() throws IOException {
        WhoisCidrInfo info = new WhoisCidrInfo(
                new Cidr("192.0.2.0", 24),
                List.of(new Cidr("192.0.2.0", 24)),
                "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1"),
                "JP",
                "Example Org",
                "EX-NET",
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "raw");

        Path outPath = Path.of("build", "tmp", "test-csv-output", "sub_" + System.nanoTime(), "result.csv");
        CsvFormatter.writeToFile(outPath, List.of(info), OutputMode.CIDR, false);
        assertTrue(Files.exists(outPath));
        String content = Files.readString(outPath, StandardCharsets.UTF_8);
        assertTrue(content.contains("192.0.2.0/24,192.0.2.0,24"));

        // 既に親ディレクトリが存在する状態での上書き出力
        CsvFormatter.writeToFile(outPath, List.of(info), OutputMode.IP, true);
        String updatedContent = Files.readString(outPath, StandardCharsets.UTF_8);
        assertTrue(updatedContent.contains("IPAddress,CIDR,"));
    }
}

