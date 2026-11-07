# ip2cidr

複数のIPアドレス（IPv4 / IPv6）を入力として受け取り、OSの `whois` コマンドを実行してCIDR・登録組織・国コード・連絡先情報などを抽出し、CIDR単位のクラス（`WhoisCidrInfo`）として整理・集約するJavaライブラリおよびCLIツールです。

## 主な特徴

1. **同一CIDRの集約**: 複数の入力IPアドレスが同一のCIDRに属する場合、1つの `WhoisCidrInfo` インスタンスにまとめて出力します。
2. **検出済みCIDR領域の再利用（whois検索スキップ）**: 一度検出したCIDR（またはIP範囲）に含まれる後続のIPアドレスについては、`whois` コマンドを実行せず、既に取得したCIDR情報を流用します。
3. **レートリミット制御（通常5秒間隔・制限発生時は1分待機してリトライ）**: `whois` サーバーのレートリミットを考慮し、通常検索時は **5秒間隔**（デフォルト）を空けて実行します（キャッシュヒット時は待機しません）。万一 `whois` サーバーからレートリミットやアクセス制限応答を受けた場合は、**1分間（60秒）待機してから自動的にリトライ**します。
4. **IPv4 / IPv6 & 各種RIRフォーマット対応**: ARIN / APNIC / RIPE / LACNIC / AFRINIC / JPNIC などの出力形式に対応し、明示的な `CIDR:` 行がない場合でも `inetnum` / `NetRange` のIP範囲からCIDRを算出・判定します。

## ビルド方法

Java 25（または利用可能な最新のJDK）と Gradle を使用してビルドし、JARファイルを生成します。

```bash
gradle build
```

ビルド完了後、以下のパスにJARファイルが生成されます。

```text
build/libs/ip2cidr-1.0.0.jar
```

## ライブラリとしての利用例

```java
import com.ip2cidr.IpToCidrResolver;
import com.ip2cidr.model.WhoisCidrInfo;
import java.util.List;

public class Example {
    public static void main(String[] args) {
        IpToCidrResolver resolver = new IpToCidrResolver();

        List<WhoisCidrInfo> results = resolver.resolve(
                "8.8.8.8",
                "8.8.8.4",   // 8.8.8.0/24 に含まれるため whois 検索をスキップして流用
                "1.1.1.1"    // 5秒待機後に whois 検索を実行
        );

        for (WhoisCidrInfo info : results) {
            System.out.println("CIDR       : " + info.getCidr()); // 例: 8.8.8.0/24
            System.out.println("Network IP : " + info.getCidr().getIpAddress()); // 例: 8.8.8.0
            System.out.println("PrefixLen  : " + info.getCidr().getPrefixLength()); // 例: 24
            System.out.println("Matched IPs: " + info.getMatchedIpAddresses());
            System.out.println("Country    : " + info.getCountry());
            System.out.println("Registrant : " + info.getRegistrant());
            System.out.println("NetName    : " + info.getNetName());
            System.out.println("Admin      : " + info.getAdminContacts());
            System.out.println("Tech       : " + info.getTechContacts());
            System.out.println("Abuse      : " + info.getAbuseContacts());
        }
    }
}
```

## CLIとしての実行例

```bash
# 引数でIPアドレスを渡す場合（標準出力・CIDR単位）
java -jar build/libs/ip2cidr-1.0.0.jar 8.8.8.8 8.8.8.4 1.1.1.1

# ファイルからIPアドレスリストを読み込む場合
java -jar build/libs/ip2cidr-1.0.0.jar -f ips.txt

# 出力単位をIP単位に切り替えて標準出力に表示する場合（-m ip または --ip）
java -jar build/libs/ip2cidr-1.0.0.jar -f ips.txt -m ip

# CSVファイルへ出力する場合（CIDR単位：デフォルト）
java -jar build/libs/ip2cidr-1.0.0.jar -f ips.txt --csv result_cidr.csv

# CSVファイルへ出力する場合（IP単位：1行1IP）
java -jar build/libs/ip2cidr-1.0.0.jar -f ips.txt -m ip --csv result_ip.csv

# 生のwhois出力も含める場合
java -jar build/libs/ip2cidr-1.0.0.jar --raw 8.8.8.8
```

