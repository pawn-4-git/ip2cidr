package com.ip2cidr.whois;

/**
 * IPアドレスに対するwhois検索を実行するインターフェース。
 */
@FunctionalInterface
public interface WhoisExecutor {

    /**
     * 指定されたIPアドレスに対してwhois検索を実行し、生出力テキストを返します。
     *
     * @param ipAddress 検索対象のIPアドレス
     * @return whoisコマンドの出力全文
     * @throws WhoisException 実行エラーまたはタイムアウト時
     */
    String executeWhois(String ipAddress) throws WhoisException;
}

