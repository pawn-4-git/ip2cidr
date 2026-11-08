package com.ip2cidr.whois;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * OSの {@code whois} コマンドをサブプロセスとして実行する標準実装クラス。
 */
public class CommandWhoisExecutor implements WhoisExecutor {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    private static final String DEFAULT_COMMAND = "whois";

    private final String whoisCommand;
    private final Duration timeout;

    public CommandWhoisExecutor() {
        this(DEFAULT_COMMAND, DEFAULT_TIMEOUT);
    }

    public CommandWhoisExecutor(Duration timeout) {
        this(DEFAULT_COMMAND, timeout);
    }

    public CommandWhoisExecutor(String whoisCommand, Duration timeout) {
        this.whoisCommand = Objects.requireNonNull(whoisCommand, "whoisCommand must not be null");
        this.timeout = Objects.requireNonNull(timeout, "timeout must not be null");
    }

    @Override
    public String executeWhois(String ipAddress) throws WhoisException {
        if (ipAddress == null || ipAddress.isBlank()) {
            throw new IllegalArgumentException("ipAddress must not be null or blank");
        }

        ProcessBuilder processBuilder = new ProcessBuilder(whoisCommand, ipAddress.trim());
        processBuilder.redirectErrorStream(true);

        Process process;
        try {
            process = processBuilder.start();
        } catch (IOException e) {
            throw new WhoisException("Failed to execute whois command for IP: " + ipAddress, e);
        }

        // 標準出力は別スレッドで読み取る。readAllBytes()をメインスレッドで呼ぶと、
        // プロセスが出力を終えず（EOFにならず）終了もしない場合にwaitForのタイムアウトが
        // 無意味になり、無期限にブロックしてしまうため。
        AtomicReference<byte[]> outputRef = new AtomicReference<>();
        AtomicReference<IOException> readErrorRef = new AtomicReference<>();
        Thread readerThread = new Thread(() -> {
            try (InputStream in = process.getInputStream()) {
                outputRef.set(in.readAllBytes());
            } catch (IOException e) {
                readErrorRef.set(e);
            }
        }, "whois-output-reader");
        readerThread.setDaemon(true);
        readerThread.start();

        try {
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                readerThread.interrupt();
                throw new WhoisException("whois command timed out for IP: " + ipAddress);
            }

            // プロセス終了後は標準出力ストリームも閉じられるため、読み取りスレッドは即座に完了するはず
            readerThread.join(Math.max(timeout.toMillis(), 1_000));

            IOException readError = readErrorRef.get();
            if (readError != null) {
                throw new WhoisException("Failed to read whois command output for IP: " + ipAddress, readError);
            }

            byte[] outputBytes = outputRef.get() != null ? outputRef.get() : new byte[0];
            String output = new String(outputBytes, StandardCharsets.UTF_8);
            int exitCode = process.exitValue();
            if (exitCode != 0 && output.isBlank()) {
                throw new WhoisException(
                        "whois command failed with exit code " + exitCode + " for IP: " + ipAddress);
            }
            return output;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new WhoisException("Interrupted while executing whois command for IP: " + ipAddress, e);
        }
    }
}

