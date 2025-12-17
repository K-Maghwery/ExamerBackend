package com.online_exam.examer.util;

import org.springframework.stereotype.Component;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Component
public class EncryptionUtil {

    private static final String ALGORITHM = "AES";
    private static final String STATIC_KEY = "XbY32rtEw0Znr2fh"; // 16 characters (128 bits)

    private final SecretKeySpec secretKeySpec;

    public EncryptionUtil() {
        // Ensure STATIC_KEY is 16 bytes for AES-128
        String key = padKey(STATIC_KEY);
        this.secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    /**
     * Encrypts a Long ID and returns the encrypted value as a Base32 encoded string.
     */
    public String encryptId(Long id) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] idBytes = longToBytes(id);
            byte[] encryptedBytes = cipher.doFinal(idBytes);
            Base32 base32 = new Base32();
            return base32.encodeToString(encryptedBytes).replace("=", "");
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting ID", e);
        }
    }

    /**
     * Decrypts a Base32 encoded encrypted ID string to Long.
     */
    public Long decryptId(String encryptedId) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            Base32 base32 = new Base32();
            byte[] decodedBytes = base32.decode(encryptedId);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return bytesToLong(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting ID", e);
        }
    }

    /**
     * Encrypts an OTP string using AES and returns a Base32 encoded string.
     */
    public String encryptOtp(String otp) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedBytes = cipher.doFinal(otp.getBytes(StandardCharsets.UTF_8));
            Base32 base32 = new Base32();
            return base32.encodeToString(encryptedBytes).replace("=", "");
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting OTP", e);
        }
    }

    /**
     * Decrypts a Base32 encoded encrypted OTP string.
     */
    public String decryptOtp(String encryptedOtp) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            Base32 base32 = new Base32();
            byte[] decodedBytes = base32.decode(encryptedOtp);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting OTP", e);
        }
    }

    private byte[] longToBytes(Long value) {
        byte[] bytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return bytes;
    }

    private Long bytesToLong(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (bytes[i] & 0xFF);
        }
        return value;
    }

    /**
     * Pads the AES key to ensure it's exactly 16 bytes.
     */
    private String padKey(String key) {
        if (key.length() >= 16) {
            return key.substring(0, 16);
        }
        return String.format("%-16s", key); // pad with spaces
    }
}
