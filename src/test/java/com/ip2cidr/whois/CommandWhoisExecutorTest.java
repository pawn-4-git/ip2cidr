package com.ip2cidr.whois;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CommandWhoisExecutorTest {

    @Test
    void testConstructorsAndSuccessfulExecution() {
        CommandWhoisExecutor defaultExec = new CommandWhoisExecutor();
        assertNotNull(defaultExec);

        CommandWhoisExecutor timeoutExec = new CommandWhoisExecutor(Duration.ofSeconds(10));
        assertNotNull(timeoutExec);

        CommandWhoisExecutor echoExec = new CommandWhoisExecutor("echo", Duration.ofSeconds(5));
        String output = echoExec.executeWhois(" 192.0.2.1 ");
        assertEquals("192.0.2.1", output.trim());
    }

    @Test
    void testInvalidIpAddressThrows() {
        CommandWhoisExecutor echoExec = new CommandWhoisExecutor("echo", Duration.ofSeconds(5));
        assertThrows(IllegalArgumentException.class, () -> echoExec.executeWhois(null));
        assertThrows(IllegalArgumentException.class, () -> echoExec.executeWhois("   "));
    }

    @Test
    void testCommandNotFoundThrowsWhoisException() {
        CommandWhoisExecutor badCmdExec = new CommandWhoisExecutor(
                "non_existent_whois_binary_xyz_99999",
                Duration.ofSeconds(5));
        WhoisException ex = assertThrows(WhoisException.class, () -> badCmdExec.executeWhois("192.0.2.1"));
        assertTrue(ex.getMessage().contains("Failed to execute whois command"));
        assertNotNull(ex.getCause());
    }

    @Test
    void testNonZeroExitCodeWithBlankOutputThrowsWhoisException() {
        CommandWhoisExecutor falseExec = new CommandWhoisExecutor("false", Duration.ofSeconds(5));
        WhoisException ex = assertThrows(WhoisException.class, () -> falseExec.executeWhois("192.0.2.1"));
        assertTrue(ex.getMessage().contains("whois command failed with exit code"));
    }

    @Test
    void testTimeoutThrowsWhoisException() {
        CommandWhoisExecutor sleepExec = new CommandWhoisExecutor("sleep", Duration.ofMillis(50));
        WhoisException ex = assertThrows(WhoisException.class, () -> sleepExec.executeWhois("2"));
        assertTrue(ex.getMessage().contains("whois command timed out"));
    }

    @Test
    void testInterruptedExecutionThrowsWhoisException() {
        CommandWhoisExecutor sleepExec = new CommandWhoisExecutor("sleep", Duration.ofSeconds(5));
        Thread.currentThread().interrupt();
        try {
            WhoisException ex = assertThrows(WhoisException.class, () -> sleepExec.executeWhois("2"));
            assertTrue(ex.getMessage().contains("Interrupted while executing whois command"));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted(); // テストスレッドの割り込みフラグを解除
        }
    }
}

