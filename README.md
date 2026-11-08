# ip2cidr

複数のIPアドレス（IPv4 / IPv6）を入力として受け取り、OSの `whois` コマンドを実行してCIDR・登録組織・国コード・連絡先情報などを抽出し、CIDR単位のクラス（`WhoisCidrInfo`）として整理・集約するJavaライブラリおよびCLIツールです。

## 主な特徴と解決アルゴリズム

### 主な特徴

1. **同一CIDRの集約**: 複数の入力IPアドレスが同一のCIDRに属する場合、1つの `WhoisCidrInfo` インスタンスにまとめて出力します。
2. **IPアドレス順ソートと直前CIDR領域による即時判定（whois検索スキップ）**: 複数のIPアドレスを受け取ると、最初にIPアドレスの数値昇順に並び替えます。CIDRを判定した直後の次のIPアドレスが、直前に解決したCIDR範囲内（複数CIDRに分解された場合はその全ブロック）に含まれるかを即座にチェックし、`whois` コマンドを実行せず既に取得したCIDR情報を流用します。
3. **レートリミット制御（通常5秒間隔・判定済み範囲ヒット時0.5秒・制限発生時は1分待機×最大10回リトライ）**: `whois` サーバーのレートリミットを考慮し、新規 `whois` 検索時は **5秒間隔**（デフォルト）、既に判定済みのCIDR範囲内のIPアドレスだった場合も次の `whois` 実行を空けるために **0.5秒** 待機します。万一 `whois` サーバーからレートリミット応答を受けた場合は、**1分間（60秒）待機してから最大10回まで自動的にリトライ**します。
4. **IPv4 / IPv6 & 各種RIRフォーマット対応（中途半端なIP帯域のCIDR自動分解）**: ARIN / APNIC / RIPE / LACNIC / AFRINIC / JPNIC などの出力形式に対応し、明示的な `CIDR:` 行がない場合でも `inetnum` / `NetRange` のIP範囲からCIDRを算出・判定します。**IPアドレス帯域が単一のCIDR境界に収まらない中途半端な範囲である場合は、その帯域を過不足なく表現する複数のCIDRブロックへ自動的に分解**して保持・判定します。

### 解決アルゴリズム

1. **STEP 1: IPアドレスの数値昇順ソート**: 入力されたIPv4 / IPv6アドレスを解析し、近接するIPアドレスが連続して処理されるように数値昇順で並び替えます。
2. **STEP 2: 直前CIDR・キャッシュ照合**: 直前に解決したCIDRブロック（中途半端なIP帯域から複数CIDRへ分解された全ブロックを含む）および既知キャッシュに包含されるかを判定し、ヒット時は0.5秒待機のみで `whois` 実行をスキップします。
3. **STEP 3: WHOIS実行＆CIDR分解・自動リトライ**: 未解決IPのみ5秒間隔で `whois` を実行します（制限検知時は60秒待機×最大10回リトライ）。取得した `inetnum` / `NetRange` のIPアドレス帯域が中途半端になる場合は、ビット演算によって過不足なく最小数のCIDRブロック群へ分解（例: `192.0.2.10 - 192.0.2.25` → `192.0.2.10/31`, `192.0.2.12/30`, `192.0.2.16/29`, `192.0.2.24/31`）し、対象IPを含む代表CIDRと全CIDR一覧（`AllCIDRs`）を算出します。
4. **STEP 4: 出力整形（CIDR単位 / IP単位）**: 標準出力またはUTF-8 CSVファイル（数式インジェクション対策済み）へCIDR単位またはIP単位で出力します。

## ビルド・テスト方法

Java 25（または利用可能な最新のJDK）と Gradle を使用してビルドし、JARファイルを生成します。

```bash
gradle build
```

ビルド完了後、以下のパスにJARファイルが生成されます（`-PreleaseVersion=x.y.z` で任意のバージョン名を指定可能です）。

```text
build/libs/ip2cidr-1.0.0.jar
```

### 自動リリース（GitHub Releases）

GitHub 上でタグ（例: `v1.0.0` または `1.0.0`）を作成またはプッシュすると、GitHub Actions（`.github/workflows/release.yml`）が自動実行されます。
タグ名からバージョン番号（先頭の `v` を除いた文字列）を抽出し、`ip2cidr-<バージョン>.jar` をビルドした上で GitHub Releases ページへ自動的に公開・添付します。

```bash
# コマンドラインからタグを作成してリリースする場合の例
git tag v1.1.0
git push origin v1.1.0
```

### テストとカバレッジ計測

テスト実行時には JaCoCo によるテストカバレッジが自動計測され、コンソールへのサマリ出力およびHTML/XML/CSVレポート生成が行われます。また、GitHub Actions（`.github/workflows/ci.yml`）および Git `pre-push` フック（`.githooks/pre-push`）により、PR作成時や `push` 時に自動でテストとカバレッジ計測が実行されます。

```bash
gradle test
```

- **HTMLカバレッジレポート**: `build/reports/jacoco/test/html/index.html`
- **XML/CSVカバレッジレポート**: `build/reports/jacoco/test/jacocoTestReport.xml`, `build/reports/jacoco/test/jacocoTestReport.csv`

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

## ドキュメント（GitHub Pages）

ツールの使い方ガイド・対話型CLIコマンドビルダー・Java APIリファレンスをまとめたWebページが `docs/` ディレクトリに配置されています。

- **ドキュメント本体**: `docs/index.html`（`docs/styles.css`, `docs/app.js`）
- **GitHub Pages 公開方法**:
  - **GitHub Actions で公開する場合（推奨）**: リポジトリの `Settings > Pages > Build and deployment > Source` で **GitHub Actions** を選択すると、`.github/workflows/pages.yml`（`Deploy GitHub Pages`）のみが動作し、`docs/` 配下が自動デプロイされます（※`Source` が `Deploy from a branch` かつ `/ (root)` のままだと、標準の `pages-build-deployment` が並列実行されて `README.md` の簡易ページで上書きされる競合が発生するため、必ず `GitHub Actions` を選択するか、ブランチ公開時は `/docs` フォルダを指定してください）。
  - **ブランチから公開する場合**: `Source` で **Deploy from a branch** を選択し、対象ブランチと `/docs` フォルダを指定してください。


