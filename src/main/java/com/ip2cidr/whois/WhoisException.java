package com.ip2cidr.whois;

/**
 * whoisコマンドの実行失敗や解析エラーを表す例外クラス。
 */
public class WhoisException extends RuntimeException {

    public WhoisException(String message) {
        super(message);
    }

    public WhoisException(String message, Throwable cause) {
        super(message, cause);
    }
}

