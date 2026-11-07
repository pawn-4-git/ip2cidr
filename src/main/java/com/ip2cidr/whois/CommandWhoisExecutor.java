package com.ip2cidr.whois;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

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

        try {
            Process process = processBuilder.start();
            byte[] outputBytes;
            try (InputStream in = process.getInputStream()) {
                outputBytes = in.readAllBytes();
            }

            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new WhoisException("whois command timed out for IP: " + ipAddress);
            }

            String output = new String(outputBytes, StandardCharsets.UTF_8);
            int exitCode = process.exitValue();
            if (exitCode != 0 && output.isBlank()) {
                throw new WhoisException(
                        "whois command failed with exit code " + exitCode + " for IP: " + ipAddress);
            }
            return output;
        } catch (IOException e) {
            throw new WhoisException("Failed to execute whois command for IP: " + ipAddress, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new WhoisException("Interrupted while executing whois command for IP: " + ipAddress, e);
        }
    }
}

