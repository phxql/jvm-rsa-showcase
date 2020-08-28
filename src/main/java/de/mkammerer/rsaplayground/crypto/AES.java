package de.mkammerer.rsaplayground.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class AES {
    private static final byte[] EMPTY_NONCE = new byte[96 / 8];
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private AES() {
    }

    public static SecretKey generateKey(int sizeInBits) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(sizeInBits);
        return keyGenerator.generateKey();
    }

    public static byte[] encrypt(byte[] data, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // 128 is the size of the authentication tag in bits. 128 is the maximum.
        // Nonce is always 96 bit long. We use 0 as nonce here, as we generate a new session key each time. Reusing a nonce
        // is only fatal when the key is the same.
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, EMPTY_NONCE);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] ciphertext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // See encrypt for the details on the numbers
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, EMPTY_NONCE);

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(ciphertext);
    }
}
