package com.ip2cidr.cli;

import com.ip2cidr.IpToCidrResolver;
import com.ip2cidr.model.Cidr;
import com.ip2cidr.model.WhoisCidrInfo;
import com.ip2cidr.util.CsvFormatter;
import com.ip2cidr.util.CsvFormatter.OutputMode;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 実行可能JAR用のCLIエントリーポイント。
 */
public class Main {

    public static void main(String[] args) {
        List<String> ipAddresses = new ArrayList<>();
        boolean showRaw = false;
        Path outputFilePath = null;
        OutputMode outputMode = OutputMode.CIDR;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("-h".equals(arg) || "--help".equals(arg)) {
                printUsage();
                return;
            } else if ("--raw".equals(arg)) {
                showRaw = true;
            } else if ("-c".equals(arg) || "--csv".equals(arg) || "csv".equals(arg) || "-o".equals(arg)
                    || "--output".equals(arg)) {
                if (i + 1 >= args.length || args[i + 1].startsWith("-")) {
                    System.err.println("Error: Missing CSV output file path after " + arg);
                    printUsage();
                    System.exit(1);
                }
                outputFilePath = Path.of(args[++i]);
            } else if ("-m".equals(arg) || "--mode".equals(arg)) {
                if (i + 1 >= args.length) {
                    System.err.println("Error: Missing mode (cidr or ip) after " + arg);
                    printUsage();
                    System.exit(1);
                }
                try {
                    outputMode = OutputMode.fromString(args[++i]);
                } catch (IllegalArgumentException e) {
                    System.err.println("Error: " + e.getMessage());
                    printUsage();
                    System.exit(1);
                }
            } else if ("--cidr".equals(arg)) {
                outputMode = OutputMode.CIDR;
            } else if ("--ip".equals(arg)) {
                outputMode = OutputMode.IP;
            } else if ("-f".equals(arg) || "--file".equals(arg)) {
                if (i + 1 >= args.length) {
                    System.err.println("Error: Missing file path after " + arg);
                    printUsage();
                    System.exit(1);
                }
                Path filePath = Path.of(args[++i]);
                try {
                    List<String> lines = Files.readAllLines(filePath, StandardCharsets.UTF_8);
                    for (String line : lines) {
                        String trimmed = line.trim();
                        if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                            ipAddresses.add(trimmed);
                        }
                    }
                } catch (IOException e) {
                    System.err.println("Error reading file " + filePath + ": " + e.getMessage());
                    System.exit(1);
                }
            } else {
                ipAddresses.add(arg);
            }
        }

        // 引数が指定されていない場合は標準入力から読み取る
        if (ipAddresses.isEmpty()) {
            try {
                if (System.in.available() > 0) {
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            String trimmed = line.trim();
                            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                                ipAddresses.add(trimmed);
                            }
                        }
                    }
                }
            } catch (IOException ignored) {
                // 標準入力が読み取れない場合はヘルプ表示へ
            }
        }

        if (ipAddresses.isEmpty()) {
            printUsage();
            return;
        }

        IpToCidrResolver resolver = new IpToCidrResolver();
        List<WhoisCidrInfo> results = resolver.resolve(ipAddresses);

        // ファイル出力が指定されている場合はCSVファイルへ書き出し
        if (outputFilePath != null) {
            try {
                CsvFormatter.writeToFile(outputFilePath, results, outputMode, showRaw);
                System.out.println("CSV output written to: " + outputFilePath.toAbsolutePath());
            } catch (IOException e) {
                System.err.println("Error writing CSV file " + outputFilePath + ": " + e.getMessage());
                System.exit(1);
            }
            return;
        }

        // ファイル指定がない場合は標準出力へ出力（CIDR単位 または IP単位）
        if (outputMode == OutputMode.IP) {
            printTextByIp(results, showRaw);
        } else {
            printTextByCidr(results, showRaw);
        }
    }

    private static void printTextByCidr(List<WhoisCidrInfo> results, boolean showRaw) {
        for (int i = 0; i < results.size(); i++) {
            WhoisCidrInfo info = results.get(i);
            if (i > 0) {
                System.out.println("------------------------------------------------------------");
            }
            System.out.println("CIDR            : " + info.getCidr());
            if (info.getAllCidrs().size() > 1) {
                String allCidrsStr = info.getAllCidrs().stream()
                        .map(Cidr::toString)
                        .collect(Collectors.joining(", "));
                System.out.println("All CIDRs       : " + allCidrsStr);
            }
            System.out.println("IP Range        : " + info.getIpRange());
            System.out.println("Matched IPs     : " + String.join(", ", info.getMatchedIpAddresses()));
            printCommonDetails(info, showRaw);
        }
    }

    private static void printTextByIp(List<WhoisCidrInfo> results, boolean showRaw) {
        boolean first = true;
        for (WhoisCidrInfo info : results) {
            for (String ip : info.getMatchedIpAddresses()) {
                if (!first) {
                    System.out.println("------------------------------------------------------------");
                }
                first = false;
                System.out.println("IP Address      : " + ip);
                System.out.println("CIDR            : " + info.getCidr());
                if (info.getAllCidrs().size() > 1) {
                    String allCidrsStr = info.getAllCidrs().stream()
                            .map(Cidr::toString)
                            .collect(Collectors.joining(", "));
                    System.out.println("All CIDRs       : " + allCidrsStr);
                }
                System.out.println("IP Range        : " + info.getIpRange());
                printCommonDetails(info, showRaw);
            }
        }
    }

    private static void printCommonDetails(WhoisCidrInfo info, boolean showRaw) {
        System.out.println("Country         : " + info.getCountry());
        System.out.println("Registrant      : " + info.getRegistrant());
        System.out.println("NetName         : " + info.getNetName());
        if (!info.getDescriptions().isEmpty()) {
            System.out.println("Descriptions    : " + String.join(" | ", info.getDescriptions()));
        }
        if (!info.getAdminContacts().isEmpty()) {
            System.out.println("Admin Contacts  : " + String.join(", ", info.getAdminContacts()));
        }
        if (!info.getTechContacts().isEmpty()) {
            System.out.println("Tech Contacts   : " + String.join(", ", info.getTechContacts()));
        }
        if (!info.getAbuseContacts().isEmpty()) {
            System.out.println("Abuse Contacts  : " + String.join(", ", info.getAbuseContacts()));
        }
        if (showRaw) {
            System.out.println("Raw Whois Output:");
            System.out.println(info.getRawWhoisOutput());
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar ip2cidr.jar [options] <ip1> <ip2> ...");
        System.out.println("Options:");
        System.out.println("  -f, --file <path>     Read IP addresses from a file (one IP per line)");
        System.out.println("  -c, --csv <path>      Write results to the specified CSV file (default: stdout)");
        System.out.println("  -o, --output <path>   Alias for --csv <path>");
        System.out.println("  -m, --mode <cidr|ip>  Output unit mode: 'cidr' (per CIDR, default) or 'ip' (per IP)");
        System.out.println("  --cidr                Shorthand for --mode cidr");
        System.out.println("  --ip                  Shorthand for --mode ip");
        System.out.println("  --raw                 Include full raw whois output");
        System.out.println("  -h, --help            Show this help message");
    }
}
