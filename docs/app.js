/**
 * ip2cidr GitHub Pages Interactive Documentation Script
 */
(function () {
  'use strict';

  const announcer = document.getElementById('live-announcer');
  let announceTimeoutId = null;

  function announce(message) {
    if (!announcer) return;
    if (announceTimeoutId) {
      clearTimeout(announceTimeoutId);
    }
    announceTimeoutId = setTimeout(() => {
      announcer.textContent = message;
    }, 80);
  }

  /* ========================================================================
     0. Internationalization (JA / EN Language Switcher — Default: JA)
     ======================================================================== */
  const SUPPORTED_LANGS = ['ja', 'en'];
  let currentLang = 'ja';

  const UI_STRINGS = {
    ja: {
      docTitle: 'ip2cidr ドキュメント & 使い方ガイド | IP to CIDR WHOIS Resolver',
      metaDescription:
        'ip2cidr の使い方ガイド。複数のIPv4/IPv6アドレスからwhois検索でCIDR・国コード・登録組織・連絡先を抽出し、CIDR単位またはIP単位で集約・CSV出力するJavaライブラリおよびCLIツール。',
      ogLocale: 'ja_JP',
      themeLabels: {
        system: 'テーマ: 自動',
        light: 'テーマ: ライト',
        dark: 'テーマ: ダーク',
      },
      themeSwitched: (label) => label + ' に切り替えました',
      langSwitched: '表示言語を日本語に切り替えました',
      copyBtn: 'コピー',
      copyDone: 'コピー完了',
      copySuccessAnnounce: 'コードをクリップボードにコピーしました',
      copyFailAnnounce: 'コピーに失敗しました。手動で選択してコピーしてください。',
      previewCsvLabel: (fileName) => '標準出力ログ + 生成される ' + fileName + ' の内容',
      previewStdoutIp: '標準出力プレビュー（IP単位モード）',
      previewStdoutCidr: '標準出力プレビュー（CIDR単位モード）',
    },
    en: {
      docTitle: 'ip2cidr Documentation & Usage Guide | IP to CIDR WHOIS Resolver',
      metaDescription:
        'Usage guide for ip2cidr: A Java library and CLI tool that resolves multiple IPv4/IPv6 addresses via WHOIS to extract CIDRs, country codes, registrants, and contacts, aggregating by CIDR or IP with CSV export.',
      ogLocale: 'en_US',
      themeLabels: {
        system: 'Theme: Auto',
        light: 'Theme: Light',
        dark: 'Theme: Dark',
      },
      themeSwitched: (label) => 'Switched to ' + label,
      langSwitched: 'Switched language to English',
      copyBtn: 'Copy',
      copyDone: 'Copied!',
      copySuccessAnnounce: 'Copied code to clipboard',
      copyFailAnnounce: 'Failed to copy. Please select and copy manually.',
      previewCsvLabel: (fileName) => 'Stdout Logs + Generated ' + fileName + ' Content',
      previewStdoutIp: 'Stdout Preview (Per-IP Mode)',
      previewStdoutCidr: 'Stdout Preview (Per-CIDR Mode)',
    },
  };

  const EN_TRANSLATIONS = {
    text: {
      skipLink: 'Skip to main content',
      'nav.features': 'Features',
      'nav.quickstart': 'Quick Start',
      'nav.cliBuilder': 'Command Builder',
      'nav.cliUsage': 'CLI Usage',
      'nav.csvSpec': 'CSV Spec',
      'nav.libraryApi': 'Java API',
      'hero.title': 'Resolve Multiple IP Addresses via WHOIS and Aggregate by CIDR Safely & Fast',
      'hero.btnQuickstart': 'Quick Start',
      'hero.btnBuilder': 'Try Command Builder',
      'hero.btnRepo': 'GitHub Repository',
      'hero.highlight1': 'Automatic aggregation into matching CIDRs',
      'hero.highlight2': 'Ascending IP sort & previous-CIDR check to save WHOIS queries',
      'hero.highlight3': '5s interval / 0.5s on cache hit / 60s × 10 retries on rate limit',
      'hero.highlight4': 'Supports ARIN / APNIC / RIPE / LACNIC / AFRINIC / JPNIC',
      'features.title': 'Key Features & Resolution Algorithm',
      'features.subtitle':
        'Accurately maps multiple IP addresses to CIDR blocks with minimal queries while respecting WHOIS server load and rate limits.',
      'features.card1.title': 'Automatic Same-CIDR Aggregation',
      'features.card2.title': 'Ascending Sort + Instant Previous-CIDR Check',
      'features.card3.title': 'Robust Rate-Limit Control',
      'features.card4.title': 'Global RIR & JPNIC Format Support',
      'features.step1.title': 'Numeric Ascending IP Sort',
      'features.step1.desc':
        'Parses IPv4 / IPv6 addresses and sorts them in numeric ascending order so adjacent IP addresses are processed consecutively.',
      'features.step2.title': 'Previous CIDR & Cache Lookup',
      'features.step2.desc':
        'Checks if the IP falls within the previously resolved CIDR block (or known cache). On a hit, waits only 0.5s and skips WHOIS.',
      'features.step3.title': 'WHOIS Execution & Auto-Retry',
      'features.step4.title': 'Output Formatting (Per-CIDR / Per-IP)',
      'features.step4.desc':
        'Outputs results per CIDR block or per IP address to stdout or a UTF-8 CSV file (with formula injection protection).',
      'quickstart.title': 'Quick Start (Requirements, Install & Build)',
      'quickstart.subtitle':
        'Download the pre-built JAR from GitHub Releases or build from source with Gradle to get started right away.',
      'quickstart.reqTitle': 'System Requirements',
      'quickstart.methodATitle': 'Option A: Download and Run JAR from GitHub Releases',
      'quickstart.methodBTitle': 'Option B: Build and Test from Source',
      'quickstart.codeGradleBuild': [
        'git clone https://github.com/pawn-4-git/ip2cidr.git',
        'cd ip2cidr',
        '',
        '# Build (generates build/libs/ip2cidr-1.0.0.jar)',
        'gradle build',
        '',
        '# Run tests and generate JaCoCo coverage report',
        'gradle test',
      ].join('\n'),
      'builder.title': 'Interactive CLI Command Builder & Output Simulator',
      'builder.subtitle':
        'Select the input source, output unit (Per-CIDR / Per-IP), and output destination (Stdout / CSV) to preview the exact CLI command and sample output in real time.',
      'builder.inputLabel': '1. IP Address Input Source',
      'builder.inputHint': 'Default: Command-line arguments (or stdin if neither args nor file is specified)',
      'builder.inputOptArgs': 'Pass directly as CLI arguments (Default)',
      'builder.inputOptFile': 'Read from file (-f ips.txt)',
      'builder.inputOptStdin': 'Pass via standard input pipe (cat ips.txt | ...)',
      'builder.modeLabel': '2. Output Unit Mode (-m / --mode)',
      'builder.modeHint': 'Default: cidr (aggregate by CIDR block)',
      'builder.modeOptCidr': 'Aggregate by CIDR block (Default: cidr)',
      'builder.modeOptIp': 'Expand per IP address (-m ip)',
      'builder.modeOptCidrExplicit': 'Explicitly specify CIDR mode (--cidr)',
      'builder.destLabel': '3. Output Destination Format',
      'builder.destHint': 'Default: Standard output (when --csv is omitted)',
      'builder.destOptStdout': 'Print text to stdout (Default)',
      'builder.destOptCsv': 'Write to CSV file (--csv)',
      'builder.generatedCmdTitle': 'Generated Command',
      'cli.title': 'CLI Usage & Options Reference',
      'cli.subtitle':
        'Supports three input methods—CLI arguments, text files, and standard input—with flexible switching between text and CSV output.',
      'cli.tableCaption': 'CLI Options, Arguments Reference, and Default Values',
      'cli.thParam': 'Parameter / Option',
      'cli.thAlias': 'Short / Alias',
      'cli.thArg': 'Argument',
      'cli.thDefault': 'Default (When Omitted)',
      'cli.thDesc': 'Description',
      'cli.row1.alias': 'Positional',
      'cli.row1.arg': 'IP addresses (multiple)',
      'cli.row3.desc':
        'Writes resolution results as a UTF-8 CSV file to the specified path (parent directories are created automatically if missing). Prints text to stdout when omitted.',
      'cli.argNone': 'None',
      'cli.row8.desc':
        'Displays the help message and exits (help is also shown by default if no IP addresses are provided via arguments, file, or stdin).',
      'cli.examplesTitle': 'Common CLI Execution Patterns',
      'cli.codeExamples': [
        '# 1. Pass IP addresses via arguments (stdout, per-CIDR mode)',
        'java -jar build/libs/ip2cidr-1.0.0.jar 8.8.8.8 8.8.8.4 1.1.1.1',
        '',
        '# 2. Read IP address list from a file (# comment lines and blank lines are skipped)',
        'java -jar build/libs/ip2cidr-1.0.0.jar -f ips.txt',
        '',
        '# 3. Pass IP addresses via standard input (pipe)',
        'cat ips.txt | java -jar build/libs/ip2cidr-1.0.0.jar',
        '',
        '# 4. Switch output unit to per-IP mode (1 block per IP) on stdout',
        'java -jar build/libs/ip2cidr-1.0.0.jar -f ips.txt -m ip',
        '',
        '# 5. Export to a CSV file (per-CIDR mode: default)',
        'java -jar build/libs/ip2cidr-1.0.0.jar -f ips.txt --csv result_cidr.csv',
        '',
        '# 6. Export to a CSV file (per-IP mode: 1 row per IP)',
        'java -jar build/libs/ip2cidr-1.0.0.jar -f ips.txt -m ip --csv result_ip.csv',
        '',
        '# 7. Include full raw whois output',
        'java -jar build/libs/ip2cidr-1.0.0.jar --raw 8.8.8.8',
      ].join('\n'),
      'cli.codeIpsTxt': [
        '# Google Public DNS (aggregated into the same CIDR)',
        '8.8.8.8',
        '8.8.8.4',
        '',
        '# Cloudflare DNS (IPv4 & IPv6)',
        '1.1.1.1',
        '2606:4700:4700::1111',
      ].join('\n'),
      'csv.title': 'CSV Output Format Specification',
      'csv.ipDesc':
        'Outputs one input IP address per row. Ideal for 1-to-1 matching against your original IP list or using VLOOKUP in Excel / Google Sheets.',
      'csv.secTitle': 'CSV Injection (Formula Execution) Protection',
      'api.title': 'Java Library Integration & API Guide',
      'api.codeJavaBasic': [
        'import com.ip2cidr.IpToCidrResolver;',
        'import com.ip2cidr.model.WhoisCidrInfo;',
        'import java.util.List;',
        '',
        'public class Example {',
        '    public static void main(String[] args) {',
        '        IpToCidrResolver resolver = new IpToCidrResolver();',
        '',
        '        List<WhoisCidrInfo> results = resolver.resolve(',
        '                "8.8.8.8",',
        '                "8.8.8.4",   // Contained in 8.8.8.0/24 -> skips whois and reuses cached result',
        '                "1.1.1.1"    // Executes whois query after a 5-second rate-limit wait',
        '        );',
        '',
        '        for (WhoisCidrInfo info : results) {',
        '            System.out.println("CIDR       : " + info.getCidr());                   // e.g. 8.8.8.0/24',
        '            System.out.println("Network IP : " + info.getCidr().getIpAddress());    // e.g. 8.8.8.0',
        '            System.out.println("PrefixLen  : " + info.getCidr().getPrefixLength()); // e.g. 24',
        '            System.out.println("IP Range   : " + info.getIpRange());                // e.g. 8.8.8.0 - 8.8.8.255',
        '            System.out.println("Matched IPs: " + info.getMatchedIpAddresses());     // e.g. [8.8.8.4, 8.8.8.8]',
        '            System.out.println("Country    : " + info.getCountry());                // e.g. US',
        '            System.out.println("Registrant : " + info.getRegistrant());             // e.g. Google LLC',
        '            System.out.println("NetName    : " + info.getNetName());                // e.g. GOGL',
        '            System.out.println("Admin      : " + info.getAdminContacts());',
        '            System.out.println("Tech       : " + info.getTechContacts());',
        '            System.out.println("Abuse      : " + info.getAbuseContacts());',
        '        }',
        '    }',
        '}',
      ].join('\n'),
      'api.customTitle': '2. Customizing Rate-Limit Settings & CSV Output Utility',
      'api.configTableCaption': 'Java API Configuration Parameters and Default Values',
      'api.thClass': 'Target Class',
      'api.thParam': 'Parameter',
      'api.thType': 'Type',
      'api.thDefault': 'Default Value (Constant)',
      'api.thDesc': 'Description',
      'api.cfg3.desc':
        'Cooldown duration to wait before retrying when a rate-limit response or temporary error is received from the WHOIS server.',
      'api.cfg4.desc': 'Maximum number of automatic retries upon rate limiting or command execution errors.',
      'api.cfg6.desc': 'Parser implementation that extracts CIDR blocks and organization details from raw WHOIS text.',
      'api.cfg7.desc':
        'Functional interface responsible for waiting. Can be mocked in unit tests to eliminate wait times.',
      'api.cfg8.desc': 'OS WHOIS command name (or executable path) invoked as a subprocess.',
      'api.codeJavaCustom': [
        'import com.ip2cidr.IpToCidrResolver;',
        'import com.ip2cidr.model.WhoisCidrInfo;',
        'import com.ip2cidr.util.CsvFormatter;',
        'import com.ip2cidr.util.CsvFormatter.OutputMode;',
        'import com.ip2cidr.whois.CommandWhoisExecutor;',
        'import com.ip2cidr.whois.WhoisParser;',
        '',
        'import java.nio.file.Path;',
        'import java.time.Duration;',
        'import java.util.List;',
        '',
        'public class CustomResolverExample {',
        '    public static void main(String[] args) throws Exception {',
        '        IpToCidrResolver resolver = new IpToCidrResolver(',
        '                new CommandWhoisExecutor(Duration.ofSeconds(30)), // Command timeout: 30s',
        '                new WhoisParser(),',
        '                Duration.ofSeconds(5),    // Standard whois query interval: 5s',
        '                Duration.ofMillis(500),   // Cache hit wait: 0.5s',
        '                Duration.ofMinutes(1),    // Rate-limit cooldown wait: 1 min',
        '                10,                       // Max retries: 10',
        '                duration -> Thread.sleep(duration.toMillis())',
        '        );',
        '',
        '        List<WhoisCidrInfo> results = resolver.resolve(List.of("1.1.1.1", "8.8.8.8"));',
        '',
        '        // Format as per-CIDR CSV string',
        '        String csvText = CsvFormatter.format(results, OutputMode.CIDR, false);',
        '',
        '        // Write per-IP CSV directly to a file',
        '        CsvFormatter.writeToFile(Path.of("output_ip.csv"), results, OutputMode.IP, false);',
        '    }',
        '}',
      ].join('\n'),
      'api.methodsTableCaption': 'WhoisCidrInfo Primary Getter Methods',
      'api.thMethod': 'Method',
      'api.thReturn': 'Return Type',
      'api.m2.desc': 'Returns all detected CIDRs (including when an IP range is split across multiple CIDR blocks).',
      'api.m4.desc': 'Returns the list of unique input IP addresses classified under this CIDR block.',
      'api.m9.desc': 'Returns the lists of administrative, technical, and abuse contacts respectively.',
      'footer.backToTop': 'Back to top',
    },
    html: {
      'hero.lead':
        '<code>ip2cidr</code> is a Java library and CLI tool that takes a large list of IPv4 / IPv6 addresses, queries the OS <code>whois</code> command, and automatically extracts and organizes CIDR blocks, country codes, registrant organizations, and admin/tech/abuse contacts.',
      'features.card1.desc':
        'When multiple input IP addresses belong to the same CIDR block, they are consolidated into a single <code>WhoisCidrInfo</code> instance while preserving the list of matching input IPs (<code>Matched IPs</code>).',
      'features.card2.desc':
        'Sorts input IPs in numeric ascending order first. Immediately checks whether the next IP falls within the just-resolved CIDR range, skipping redundant <code>whois</code> executions and reusing the cache.',
      'features.card3.desc':
        'Waits <strong>5 seconds</strong> by default between new queries and <strong>0.5 seconds</strong> on cache hits to prevent bursts. Automatically retries up to <strong>10 times with a 60-second cooldown</strong> if rate-limited.',
      'features.card4.desc':
        'Supports ARIN / APNIC / RIPE / LACNIC / AFRINIC / JPNIC. Automatically calculates exact CIDR blocks from <code>inetnum</code> or <code>NetRange</code> IP boundaries even when an explicit <code>CIDR:</code> line is absent.',
      'features.step3.desc':
        'Executes <code>whois</code> at 5-second intervals only for unresolved IPs. On rate-limit detection, waits 60 seconds and retries up to 10 times.',
      'quickstart.reqDesc':
        'Ensure your environment has <strong>Java (JDK 21–25 recommended)</strong> and the standard OS <strong><code>whois</code> command</strong> (pre-installed on macOS / Linux).',
      'quickstart.methodADesc':
        'Download the latest <code>ip2cidr-&lt;version&gt;.jar</code> from the <a href="https://github.com/pawn-4-git/ip2cidr/releases" target="_blank" rel="noopener noreferrer">GitHub Releases page</a> and run it directly with <code>java -jar</code>.',
      'quickstart.methodBDesc':
        'Clone the repository and run <code>gradle build</code> to generate <code>build/libs/ip2cidr-1.0.0.jar</code>. You can pass <code>-PreleaseVersion=x.y.z</code> to assign a custom version number.',
      'builder.rawLabel': 'Include full raw WHOIS output (<code>--raw</code> / Default: OFF)',
      'cli.row1.default':
        '<strong>Read from standard input (<code>stdin</code>)</strong><br><small>(*when <code>--file</code> is also omitted)</small>',
      'cli.row1.desc':
        'Directly specifies target IPv4 / IPv6 addresses to resolve. If both positional arguments and <code>--file</code> are omitted, IPs are read automatically from stdin (one IP per line).',
      'cli.row2.default': '<strong>None</strong><br><small>(uses positional args or stdin)</small>',
      'cli.row2.desc':
        'Reads IP addresses (one per line) from a UTF-8 text file. Blank lines and comment lines starting with <code>#</code> are ignored. Can be combined with positional arguments.',
      'cli.row3.default': '<strong>None (prints text to <code>stdout</code>)</strong>',
      'cli.row4.default': '<strong><code>cidr</code> (per CIDR block)</strong>',
      'cli.row4.desc':
        'Switches the output aggregation unit. Defaults to <code>cidr</code> (aggregates same CIDR into one record); specify <code>ip</code> to expand output to one record per input IP address.',
      'cli.row5.default': '<strong>Enabled (Default: <code>cidr</code> mode)</strong>',
      'cli.row5.desc':
        'Shorthand for <code>--mode cidr</code>. Outputs results per CIDR block, matching the default behavior.',
      'cli.row6.default': '<strong>Disabled (defaults to <code>cidr</code> mode)</strong>',
      'cli.row6.desc': 'Shorthand for <code>--mode ip</code>. Switches the output unit to per IP address.',
      'cli.row7.default': '<strong><code>false</code> (excludes raw WHOIS output)</strong>',
      'cli.row7.desc':
        'By default, only extracted structured fields are output. Specifying <code>--raw</code> appends the full raw <code>whois</code> output (<code>RawWhoisOutput</code>) at the end.',
      'cli.row8.default': '<strong><code>false</code> (normal execution)</strong>',
      'cli.sampleFileTitle': 'Sample Input File (<code>ips.txt</code>)',
      'cli.sampleFileDesc':
        'You can mix IPv4 and IPv6 addresses in the same file. Lines starting with <code>#</code> and blank lines are automatically skipped.',
      'csv.subtitle':
        'Column structure and security specifications for CSV files generated via the <code>--csv &lt;path&gt;</code> option (or the <code>CsvFormatter</code> class).',
      'csv.cidrTitle': 'Per-CIDR Mode (Default: <code>-m cidr</code>)',
      'csv.cidrDesc':
        'Outputs one CIDR block per row. Multiple input IPs belonging to the same CIDR are joined with semicolons (<code>; </code>) in the <code>MatchedIPs</code> column.',
      'csv.cidrCol1': '<code>CIDR</code> — Primary CIDR (e.g. <code>8.8.8.0/24</code>)',
      'csv.cidrCol2': '<code>NetworkIP</code> — Network address (e.g. <code>8.8.8.0</code>)',
      'csv.cidrCol3': '<code>PrefixLength</code> — Prefix length (e.g. <code>24</code>)',
      'csv.cidrCol4': '<code>AllCIDRs</code> — All detected CIDRs (separated by <code>; </code>)',
      'csv.cidrCol5': '<code>IPRange</code> — IP range notation (e.g. <code>8.8.8.0 - 8.8.8.255</code>)',
      'csv.cidrCol6': '<code>MatchedIPs</code> — Matched input IPs (separated by <code>; </code>)',
      'csv.cidrCol7': '<code>Country</code> — Country code (e.g. <code>US</code>, <code>JP</code>)',
      'csv.cidrCol8': '<code>Registrant</code> — Registrant organization / name',
      'csv.cidrCol9': '<code>NetName</code> — Network name',
      'csv.cidrCol10': '<code>Descriptions</code> — Descriptions / remarks (separated by <code> | </code>)',
      'csv.cidrCol11': '<code>AdminContacts</code> — Administrative contacts (separated by <code>; </code>)',
      'csv.cidrCol12': '<code>TechContacts</code> — Technical contacts (separated by <code>; </code>)',
      'csv.cidrCol13': '<code>AbuseContacts</code> — Abuse contacts (separated by <code>; </code>)',
      'csv.cidrCol14': '<code>RawWhoisOutput</code> — Full raw WHOIS output (only when <code>--raw</code> is set)',
      'csv.ipTitle': 'Per-IP Mode (<code>-m ip</code> / <code>--ip</code>)',
      'csv.ipCol1': '<code>IPAddress</code> — Input IP address (e.g. <code>8.8.8.4</code>)',
      'csv.ipCol2': '<code>CIDR</code> — Matching primary CIDR (e.g. <code>8.8.8.0/24</code>)',
      'csv.ipCol7': '<code>Country</code> — Country code',
      'csv.secDesc':
        'If text from an external WHOIS registry begins with <code>=</code>, <code>+</code>, <code>-</code>, or <code>@</code>, a leading single quote (<code>\'</code>) is automatically prepended and escaped in double quotes to prevent spreadsheet applications (Excel, Google Sheets) from executing it as a formula.',
      'api.subtitle':
        'Call <code>com.ip2cidr.IpToCidrResolver</code> directly from your Java application to obtain results as type-safe model classes (<code>WhoisCidrInfo</code>, <code>Cidr</code>).',
      'api.basicTitle': '1. Basic Usage (<code>IpToCidrResolver</code>)',
      'api.customDesc':
        'The no-argument constructor <code>new IpToCidrResolver()</code> automatically applies the default settings below. You can customize each parameter via the full constructor.',
      'api.cfg1.default': '<strong><code>5 seconds</code></strong><br><small>(<code>DEFAULT_RATE_LIMIT_INTERVAL</code>)</small>',
      'api.cfg1.desc':
        'Standard wait interval before executing a new <code>whois</code> command (applied from the second WHOIS query onward).',
      'api.cfg2.default':
        '<strong><code>0.5 seconds (500ms)</code></strong><br><small>(<code>DEFAULT_CACHE_HIT_INTERVAL</code>)</small>',
      'api.cfg2.desc':
        'Wait duration when an input IP falls within an already-resolved CIDR block and the <code>whois</code> execution is skipped.',
      'api.cfg3.default':
        '<strong><code>1 minute (60s)</code></strong><br><small>(<code>DEFAULT_RATE_LIMIT_COOLDOWN</code>)</small>',
      'api.cfg4.default':
        '<strong><code>10 retries</code></strong><br><small>(<code>DEFAULT_MAX_RATE_LIMIT_RETRIES</code>)</small>',
      'api.cfg5.desc':
        'Implementation class that executes WHOIS lookups. By default, runs the OS <code>whois</code> command as a subprocess.',
      'api.cfg9.default': '<strong><code>30 seconds</code></strong><br><small>(<code>DEFAULT_TIMEOUT</code>)</small>',
      'api.cfg9.desc':
        'Maximum timeout per <code>whois</code> command execution. Terminates the process forcibly if exceeded.',
      'api.cfg10.desc':
        'CSV aggregation unit (defaults to <code>CIDR</code> when <code>OutputMode.fromString(null)</code> or an empty string is passed).',
      'api.methodsTitle': '3. <code>WhoisCidrInfo</code> Methods Reference',
      'api.m1.desc':
        'Returns the primary CIDR object (holding <code>getIpAddress()</code> and <code>getPrefixLength()</code>).',
      'api.m3.desc': 'Returns the IP range string (e.g. <code>"8.8.8.0 - 8.8.8.255"</code>).',
      'api.m5.desc': 'Returns the 2-letter country code (e.g. <code>"JP"</code>, <code>"US"</code>).',
      'api.m6.desc':
        'Returns the registrant organization or name (from <code>org-name</code> / <code>Organization</code> / <code>組織名</code>, etc.).',
      'api.m7.desc': 'Returns the network name (from <code>netname</code> / <code>NetName</code> / <code>ネットワーク名</code>).',
      'api.m8.desc': 'Returns the list of descriptions and remarks (from <code>descr</code> / <code>Comment</code>, etc.).',
      'api.m10.desc': 'Returns the full raw text output from the <code>whois</code> command.',
    },
    ariaLabel: {
      'nav.ariaLabel': 'Main',
      'lang.groupAria': 'Language selection',
      'copyAria.quickRun': 'Copy quick run command',
      'copyAria.gradleBuild': 'Copy Gradle build commands',
      'copyAria.generatedCmd': 'Copy generated CLI command',
      'copyAria.generatedOutput': 'Copy output preview',
      'copyAria.cliExamples': 'Copy CLI execution examples',
      'copyAria.ipsTxt': 'Copy ips.txt sample',
      'copyAria.javaBasic': 'Copy basic Java example code',
      'copyAria.javaCustom': 'Copy custom Java configuration example code',
    },
    alt: {
      'hero.iconAlt': 'ip2cidr icon',
    },
  };

  // Capture initial Japanese DOM state before any language mutation
  const JA_SNAPSHOT = {
    text: {},
    html: {},
    ariaLabel: {},
    alt: {},
  };

  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (key && !(key in JA_SNAPSHOT.text)) {
      JA_SNAPSHOT.text[key] = el.textContent;
    }
  });

  document.querySelectorAll('[data-i18n-html]').forEach((el) => {
    const key = el.getAttribute('data-i18n-html');
    if (key && !(key in JA_SNAPSHOT.html)) {
      JA_SNAPSHOT.html[key] = el.innerHTML;
    }
  });

  document.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
    const key = el.getAttribute('data-i18n-aria-label');
    if (key && !(key in JA_SNAPSHOT.ariaLabel)) {
      JA_SNAPSHOT.ariaLabel[key] = el.getAttribute('aria-label') || '';
    }
  });

  document.querySelectorAll('[data-i18n-alt]').forEach((el) => {
    const key = el.getAttribute('data-i18n-alt');
    if (key && !(key in JA_SNAPSHOT.alt)) {
      JA_SNAPSHOT.alt[key] = el.getAttribute('alt') || '';
    }
  });

  /* ========================================================================
     1. Theme Switcher (System / Light / Dark)
     ======================================================================== */
  const themeBtn = document.getElementById('theme-toggle');
  const themeLabel = document.getElementById('theme-toggle-label');
  const rootEl = document.documentElement;
  const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

  const THEME_MODES = ['system', 'light', 'dark'];

  let currentThemeMode = 'system';
  try {
    const saved = localStorage.getItem('ip2cidr-theme');
    if (saved && THEME_MODES.includes(saved)) {
      currentThemeMode = saved;
    }
  } catch (_) {
    // Ignore storage access errors in restricted contexts
  }

  function updateThemeLabel() {
    if (themeLabel) {
      themeLabel.textContent = UI_STRINGS[currentLang].themeLabels[currentThemeMode];
    }
  }

  function applyTheme(mode) {
    currentThemeMode = mode;
    if (mode === 'system') {
      rootEl.removeAttribute('data-theme');
    } else {
      rootEl.setAttribute('data-theme', mode);
    }
    updateThemeLabel();
  }

  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const nextIndex = (THEME_MODES.indexOf(currentThemeMode) + 1) % THEME_MODES.length;
      const nextMode = THEME_MODES[nextIndex];
      applyTheme(nextMode);
      try {
        localStorage.setItem('ip2cidr-theme', nextMode);
      } catch (_) {
        // Ignore storage errors
      }
      const label = UI_STRINGS[currentLang].themeLabels[nextMode];
      announce(UI_STRINGS[currentLang].themeSwitched(label));
    });
  }

  // Listen to OS color-scheme changes per modern-web-guidance
  darkQuery.addEventListener('change', () => {
    if (currentThemeMode === 'system') {
      applyTheme('system');
    }
  });

  /* ========================================================================
     2. Copy to Clipboard for Code Blocks
     ======================================================================== */
  async function copyText(text, buttonEl) {
    try {
      await navigator.clipboard.writeText(text.trim());
      buttonEl.dataset.copied = 'true';
      buttonEl.textContent = UI_STRINGS[currentLang].copyDone;
      announce(UI_STRINGS[currentLang].copySuccessAnnounce);

      setTimeout(() => {
        buttonEl.dataset.copied = 'false';
        buttonEl.textContent = UI_STRINGS[currentLang].copyBtn;
      }, 2000);
    } catch (_) {
      announce(UI_STRINGS[currentLang].copyFailAnnounce);
    }
  }

  document.querySelectorAll('[data-copy-target]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-copy-target');
      const codeEl = targetId ? document.getElementById(targetId) : null;
      if (codeEl) {
        copyText(codeEl.textContent || '', btn);
      }
    });
  });

  /* ========================================================================
     3. Interactive CLI Command Builder & Output Simulator
     ======================================================================== */
  const inputSourceSelect = document.getElementById('builder-input-source');
  const outputModeSelect = document.getElementById('builder-output-mode');
  const outputDestSelect = document.getElementById('builder-output-dest');
  const includeRawCheckbox = document.getElementById('builder-include-raw');
  const generatedCmdCode = document.getElementById('builder-generated-cmd');
  const generatedOutputCode = document.getElementById('builder-generated-output');
  const outputPreviewLabel = document.getElementById('builder-preview-label');

  function buildCommandAndPreview() {
    if (!inputSourceSelect || !outputModeSelect || !outputDestSelect || !includeRawCheckbox) {
      return;
    }

    const inputSource = inputSourceSelect.value;
    const outputMode = outputModeSelect.value;
    const outputDest = outputDestSelect.value;
    const includeRaw = includeRawCheckbox.checked;

    const args = [];
    let prefixPipe = '';

    if (inputSource === 'file') {
      args.push('-f ips.txt');
    } else if (inputSource === 'stdin') {
      prefixPipe = 'cat ips.txt | ';
    }

    if (outputMode === 'ip') {
      args.push('-m ip');
    } else if (outputMode === 'cidr-explicit') {
      args.push('--cidr');
    }

    if (outputDest === 'csv') {
      const fileName = outputMode === 'ip' ? 'result_ip.csv' : 'result_cidr.csv';
      args.push('--csv ' + fileName);
    }

    if (includeRaw) {
      args.push('--raw');
    }

    if (inputSource === 'args') {
      args.push('8.8.8.8 8.8.8.4 1.1.1.1');
    }

    const argString = args.length > 0 ? ' ' + args.join(' ') : '';
    const fullCommand = prefixPipe + 'java -jar build/libs/ip2cidr-1.0.0.jar' + argString;

    if (generatedCmdCode) {
      generatedCmdCode.textContent = fullCommand;
    }

    // Build realistic output preview
    const statusHeader = [
      '[WHOIS] Starting resolution for 3 IP address(es) (sorted in ascending order)...',
      '[WHOIS] [1/3] Querying whois for 1.1.1.1...',
      '[WHOIS] [1/3] 1.1.1.1 -> Resolved CIDR: 1.1.1.0/24 (Range: 1.1.1.0 - 1.1.1.255, Country: AU, NetName: APNIC-LABS, Registrant: APNIC and Cloudflare DNS Resolver project)',
      '[WHOIS] [2/3] Waiting 5 second(s) for rate limit before querying 8.8.8.4...',
      '[WHOIS] [2/3] Querying whois for 8.8.8.4...',
      '[WHOIS] [2/3] 8.8.8.4 -> Resolved CIDR: 8.8.8.0/24 (Range: 8.8.8.0 - 8.8.8.255, Country: US, NetName: GOGL, Registrant: Google LLC)',
      '[WHOIS] [3/3] 8.8.8.8 -> Skipped (matched cached CIDR: 8.8.8.0/24, Country: US, Registrant: Google LLC)',
      '[WHOIS] Completed resolution: 3 IP address(es) aggregated into 2 CIDR block(s).',
    ].join('\n');

    let previewText = '';
    if (outputDest === 'csv') {
      const fileName = outputMode === 'ip' ? 'result_ip.csv' : 'result_cidr.csv';
      if (outputPreviewLabel) {
        outputPreviewLabel.textContent = UI_STRINGS[currentLang].previewCsvLabel(fileName);
      }
      if (outputMode === 'ip') {
        const rawHeader = includeRaw ? ',RawWhoisOutput' : '';
        const rawCol1 = includeRaw ? ',"inetnum: 1.1.1.0 - 1.1.1.255 ..."' : '';
        const rawCol2 = includeRaw ? ',"NetRange: 8.8.8.0 - 8.8.8.255 ..."' : '';
        previewText =
          statusHeader +
          '\nCSV output written to: /path/to/' +
          fileName +
          '\n\n# --- ' +
          fileName +
          ' ---\n' +
          'IPAddress,CIDR,NetworkIP,PrefixLength,AllCIDRs,IPRange,Country,Registrant,NetName,Descriptions,AdminContacts,TechContacts,AbuseContacts' +
          rawHeader +
          '\n' +
          '1.1.1.1,1.1.1.0/24,1.1.1.0,24,1.1.1.0/24,1.1.1.0 - 1.1.1.255,AU,APNIC and Cloudflare DNS Resolver project,APNIC-LABS,APNIC and Cloudflare DNS Resolver project,AIC3-AP,AIC3-AP,helpdesk@apnic.net' +
          rawCol1 +
          '\n' +
          '8.8.8.4,8.8.8.0/24,8.8.8.0,24,8.8.8.0/24,8.8.8.0 - 8.8.8.255,US,Google LLC,GOGL,,ZG39-ARIN,ZG39-ARIN,network-abuse@google.com' +
          rawCol2 +
          '\n' +
          '8.8.8.8,8.8.8.0/24,8.8.8.0,24,8.8.8.0/24,8.8.8.0 - 8.8.8.255,US,Google LLC,GOGL,,ZG39-ARIN,ZG39-ARIN,network-abuse@google.com' +
          rawCol2;
      } else {
        const rawHeader = includeRaw ? ',RawWhoisOutput' : '';
        const rawCol1 = includeRaw ? ',"inetnum: 1.1.1.0 - 1.1.1.255 ..."' : '';
        const rawCol2 = includeRaw ? ',"NetRange: 8.8.8.0 - 8.8.8.255 ..."' : '';
        previewText =
          statusHeader +
          '\nCSV output written to: /path/to/' +
          fileName +
          '\n\n# --- ' +
          fileName +
          ' ---\n' +
          'CIDR,NetworkIP,PrefixLength,AllCIDRs,IPRange,MatchedIPs,Country,Registrant,NetName,Descriptions,AdminContacts,TechContacts,AbuseContacts' +
          rawHeader +
          '\n' +
          '1.1.1.0/24,1.1.1.0,24,1.1.1.0/24,1.1.1.0 - 1.1.1.255,1.1.1.1,AU,APNIC and Cloudflare DNS Resolver project,APNIC-LABS,APNIC and Cloudflare DNS Resolver project,AIC3-AP,AIC3-AP,helpdesk@apnic.net' +
          rawCol1 +
          '\n' +
          '8.8.8.0/24,8.8.8.0,24,8.8.8.0/24,8.8.8.0 - 8.8.8.255,"8.8.8.4; 8.8.8.8",US,Google LLC,GOGL,,ZG39-ARIN,ZG39-ARIN,network-abuse@google.com' +
          rawCol2;
      }
    } else {
      if (outputPreviewLabel) {
        outputPreviewLabel.textContent =
        outputMode === 'ip'
          ? UI_STRINGS[currentLang].previewStdoutIp
          : UI_STRINGS[currentLang].previewStdoutCidr;
      }
      const rawBlock1 = includeRaw
        ? '\nRaw Whois Output:\ninetnum:        1.1.1.0 - 1.1.1.255\nnetname:        APNIC-LABS\ncountry:        AU'
        : '';
      const rawBlock2 = includeRaw
        ? '\nRaw Whois Output:\nNetRange:       8.8.8.0 - 8.8.8.255\nCIDR:           8.8.8.0/24\nOrgName:        Google LLC'
        : '';

      if (outputMode === 'ip') {
        previewText =
          statusHeader +
          '\n' +
          [
            'IP Address      : 1.1.1.1',
            'CIDR            : 1.1.1.0/24',
            'IP Range        : 1.1.1.0 - 1.1.1.255',
            'Country         : AU',
            'Registrant      : APNIC and Cloudflare DNS Resolver project',
            'NetName         : APNIC-LABS',
            'Descriptions    : APNIC and Cloudflare DNS Resolver project',
            'Admin Contacts  : AIC3-AP',
            'Tech Contacts   : AIC3-AP',
            'Abuse Contacts  : helpdesk@apnic.net' + rawBlock1,
            '------------------------------------------------------------',
            'IP Address      : 8.8.8.4',
            'CIDR            : 8.8.8.0/24',
            'IP Range        : 8.8.8.0 - 8.8.8.255',
            'Country         : US',
            'Registrant      : Google LLC',
            'NetName         : GOGL',
            'Admin Contacts  : ZG39-ARIN',
            'Tech Contacts   : ZG39-ARIN',
            'Abuse Contacts  : network-abuse@google.com' + rawBlock2,
            '------------------------------------------------------------',
            'IP Address      : 8.8.8.8',
            'CIDR            : 8.8.8.0/24',
            'IP Range        : 8.8.8.0 - 8.8.8.255',
            'Country         : US',
            'Registrant      : Google LLC',
            'NetName         : GOGL',
            'Admin Contacts  : ZG39-ARIN',
            'Tech Contacts   : ZG39-ARIN',
            'Abuse Contacts  : network-abuse@google.com' + rawBlock2,
          ].join('\n');
      } else {
        previewText =
          statusHeader +
          '\n' +
          [
            'CIDR            : 1.1.1.0/24',
            'IP Range        : 1.1.1.0 - 1.1.1.255',
            'Matched IPs     : 1.1.1.1',
            'Country         : AU',
            'Registrant      : APNIC and Cloudflare DNS Resolver project',
            'NetName         : APNIC-LABS',
            'Descriptions    : APNIC and Cloudflare DNS Resolver project',
            'Admin Contacts  : AIC3-AP',
            'Tech Contacts   : AIC3-AP',
            'Abuse Contacts  : helpdesk@apnic.net' + rawBlock1,
            '------------------------------------------------------------',
            'CIDR            : 8.8.8.0/24',
            'IP Range        : 8.8.8.0 - 8.8.8.255',
            'Matched IPs     : 8.8.8.4, 8.8.8.8',
            'Country         : US',
            'Registrant      : Google LLC',
            'NetName         : GOGL',
            'Admin Contacts  : ZG39-ARIN',
            'Tech Contacts   : ZG39-ARIN',
            'Abuse Contacts  : network-abuse@google.com' + rawBlock2,
          ].join('\n');
      }
    }

    if (generatedOutputCode) {
      generatedOutputCode.textContent = previewText;
    }
  }

  [inputSourceSelect, outputModeSelect, outputDestSelect, includeRawCheckbox].forEach((control) => {
    if (control) {
      control.addEventListener('change', buildCommandAndPreview);
    }
  });

  /* ========================================================================
     4. Apply Language & Bind Language Switcher Controls
     ======================================================================== */
  const langButtons = document.querySelectorAll('.lang-btn[data-lang]');

  function setMetaContent(selector, value) {
    const el = document.querySelector(selector);
    if (el) {
      el.setAttribute('content', value);
    }
  }

  function applyLanguage(lang, shouldAnnounce) {
    const targetLang = SUPPORTED_LANGS.includes(lang) ? lang : 'ja';
    currentLang = targetLang;
    rootEl.lang = targetLang;

    const dict = targetLang === 'en' ? EN_TRANSLATIONS : JA_SNAPSHOT;
    const ui = UI_STRINGS[targetLang];

    // Update document title & meta tags
    document.title = ui.docTitle;
    setMetaContent('meta[name="title"]', ui.docTitle);
    setMetaContent('meta[name="description"]', ui.metaDescription);
    setMetaContent('meta[property="og:title"]', ui.docTitle);
    setMetaContent('meta[property="og:description"]', ui.metaDescription);
    setMetaContent('meta[property="og:locale"]', ui.ogLocale);
    setMetaContent('meta[name="twitter:title"]', ui.docTitle);
    setMetaContent('meta[name="twitter:description"]', ui.metaDescription);

    // Update textContent elements
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      if (key && dict.text[key] !== undefined) {
        el.textContent = dict.text[key];
      }
    });

    // Update innerHTML elements
    document.querySelectorAll('[data-i18n-html]').forEach((el) => {
      const key = el.getAttribute('data-i18n-html');
      if (key && dict.html[key] !== undefined) {
        el.innerHTML = dict.html[key];
      }
    });

    // Update aria-label elements
    document.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
      const key = el.getAttribute('data-i18n-aria-label');
      if (key && dict.ariaLabel[key] !== undefined) {
        el.setAttribute('aria-label', dict.ariaLabel[key]);
      }
    });

    // Update img alt elements
    document.querySelectorAll('[data-i18n-alt]').forEach((el) => {
      const key = el.getAttribute('data-i18n-alt');
      if (key && dict.alt[key] !== undefined) {
        el.setAttribute('alt', dict.alt[key]);
      }
    });

    // Update copy buttons text
    document.querySelectorAll('.copy-btn').forEach((btn) => {
      btn.textContent = btn.dataset.copied === 'true' ? ui.copyDone : ui.copyBtn;
    });

    // Update language toggle buttons aria-pressed state
    langButtons.forEach((btn) => {
      const isSelected = btn.getAttribute('data-lang') === targetLang;
      btn.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
    });

    // Update theme label and CLI builder preview
    updateThemeLabel();
    buildCommandAndPreview();

    if (shouldAnnounce) {
      announce(ui.langSwitched);
    }
  }

  // Determine initial language (Default: 'ja')
  let initialLang = 'ja';
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const queryLang = urlParams.get('lang');
    if (queryLang && SUPPORTED_LANGS.includes(queryLang)) {
      initialLang = queryLang;
    } else {
      const savedLang = localStorage.getItem('ip2cidr-lang');
      if (savedLang && SUPPORTED_LANGS.includes(savedLang)) {
        initialLang = savedLang;
      }
    }
  } catch (_) {
    // Ignore storage/URL errors and keep 'ja' as default
  }

  langButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const selectedLang = btn.getAttribute('data-lang');
      if (!selectedLang || selectedLang === currentLang) {
        return;
      }
      applyLanguage(selectedLang, true);
      try {
        localStorage.setItem('ip2cidr-lang', selectedLang);
      } catch (_) {
        // Ignore storage errors
      }
    });
  });

  applyTheme(currentThemeMode);
  applyLanguage(initialLang, false);
})();
