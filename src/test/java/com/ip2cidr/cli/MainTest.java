package com.ip2cidr.cli;

import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainTest {

    @Test
    void testMainHelpAndOptionParsing() throws IOException {
        assertNotNull(new Main());

        Path inputFile = Path.of("build", "tmp", "test-cli", "ips_" + System.nanoTime() + ".txt");
        Files.createDirectories(inputFile.getParent());
        Files.writeString(inputFile, "# comment\n\n  192.0.2.1  \n", StandardCharsets.UTF_8);

        PrintStream originalOut = System.out;
        ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(capturedOut, true, StandardCharsets.UTF_8));
            Main.main(new String[] { "-h" });
            Main.main(new String[] {
                    "--raw",
                    "-c", "out.csv",
                    "--csv", "out.csv",
                    "csv", "out.csv",
                    "-o", "out.csv",
                    "--output", "out.csv",
                    "-m", "cidr",
                    "--mode", "ip",
                    "--cidr",
                    "--ip",
                    "-f", inputFile.toString(),
                    "--file", inputFile.toString(),
                    "198.51.100.1",
                    "--help"
            });
        } finally {
            System.setOut(originalOut);
        }

        String out = capturedOut.toString(StandardCharsets.UTF_8);
        assertTrue(out.contains("Usage: java -jar ip2cidr.jar"));
        assertTrue(out.contains("--file <path>"));
    }

    @Test
    void testMainWithEmptyArgsAndStdinCommentOrError() {
        PrintStream originalOut = System.out;
        InputStream originalIn = System.in;
        ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(capturedOut, true, StandardCharsets.UTF_8));

            // 1. 標準入力にコメント行と空行のみが含まれる場合 -> IPリストが空となりUsageを表示して正常終了
            ByteArrayInputStream commentStdin = new ByteArrayInputStream(
                    "# comment line\n   \n".getBytes(StandardCharsets.UTF_8));
            System.setIn(commentStdin);
            Main.main(new String[0]);

            // 2. 標準入力が0バイトの場合
            System.setIn(new ByteArrayInputStream(new byte[0]));
            Main.main(new String[0]);

            // 3. 標準入力読み取り時に IOException が発生する場合
            InputStream failingIn = new InputStream() {
                @Override
                public int available() throws IOException {
                    throw new IOException("stdin error");
                }

                @Override
                public int read() throws IOException {
                    throw new IOException("stdin error");
                }
            };
            System.setIn(failingIn);
            Main.main(new String[0]);
        } finally {
            System.setOut(originalOut);
            System.setIn(originalIn);
        }

        String out = capturedOut.toString(StandardCharsets.UTF_8);
        assertTrue(out.contains("Usage: java -jar ip2cidr.jar"));
    }

    @Test
    void testPrintTextByCidrAndPrintTextByIp() throws Exception {
        WhoisCidrInfo info1 = new WhoisCidrInfo(
                new Cidr("192.0.2.0", 24),
                List.of(new Cidr("192.0.2.0", 25), new Cidr("192.0.2.128", 25)),
                "192.0.2.0 - 192.0.2.255",
                List.of("192.0.2.1", "192.0.2.2"),
                "JP",
                "Example Org 1",
                "EX-NET-1",
                List.of("Desc A", "Desc B"),
                List.of("ADM-1"),
                List.of("TECH-1"),
                List.of("abuse@example.jp"),
                "RAW_WHOIS_1");

        WhoisCidrInfo info2 = new WhoisCidrInfo(
                new Cidr("198.51.100.0", 24),
                List.of(new Cidr("198.51.100.0", 24)),
                "198.51.100.0 - 198.51.100.255",
                List.of("198.51.100.1"),
                "US",
                "Example Org 2",
                "EX-NET-2",
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "RAW_WHOIS_2");

        Method printByCidr = Main.class.getDeclaredMethod("printTextByCidr", List.class, boolean.class);
        printByCidr.setAccessible(true);

        Method printByIp = Main.class.getDeclaredMethod("printTextByIp", List.class, boolean.class);
        printByIp.setAccessible(true);

        PrintStream originalOut = System.out;
        ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(capturedOut, true, StandardCharsets.UTF_8));
            printByCidr.invoke(null, List.of(info1, info2), true);
            printByIp.invoke(null, List.of(info1, info2), false);
        } finally {
            System.setOut(originalOut);
        }

        String out = capturedOut.toString(StandardCharsets.UTF_8);
        assertTrue(out.contains("CIDR            : 192.0.2.0/24"));
        assertTrue(out.contains("All CIDRs       : 192.0.2.0/25, 192.0.2.128/25"));
        assertTrue(out.contains("Matched IPs     : 192.0.2.1, 192.0.2.2"));
        assertTrue(out.contains("Descriptions    : Desc A | Desc B"));
        assertTrue(out.contains("Admin Contacts  : ADM-1"));
        assertTrue(out.contains("Tech Contacts   : TECH-1"));
        assertTrue(out.contains("Abuse Contacts  : abuse@example.jp"));
        assertTrue(out.contains("Raw Whois Output:"));
        assertTrue(out.contains("RAW_WHOIS_1"));
        assertTrue(out.contains("IP Address      : 192.0.2.1"));
        assertTrue(out.contains("IP Address      : 198.51.100.1"));
    }
}

