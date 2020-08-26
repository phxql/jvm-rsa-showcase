package de.mkammerer.rsaplayground.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class AES {
    private static final byte[] EMPTY_NONCE = new byte[96 / 8];
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private AES() {
    }

    public static byte[] generateKey(int sizeInBits) {
        byte[] sessionKey = new byte[sizeInBits / 8];
        SECURE_RANDOM.nextBytes(sessionKey);
        return sessionKey;
    }

    public static byte[] encrypt(byte[] data, byte[] sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        Key keySpec = new SecretKeySpec(sessionKey, "AES");
        // 128 is the size of the authentication tag in bits. 128 is the maximum.
        // Nonce is always 96 bit long. We use 0 as nonce here, as we generate a new session key each time. Reusing a nonce
        // is only fatal when the key is the same.
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, EMPTY_NONCE);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        Key keySpec = new SecretKeySpec(sessionKey, "AES");
        // See encrypt for the details on the numbers
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, EMPTY_NONCE);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(ciphertext);
    }
}
