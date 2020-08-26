package de.mkammerer.rsaplayground.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public final class RSA {
    private RSA() {
    }

    public static KeyPair generateKeyPair(int sizeInBits) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(sizeInBits);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encrypt(byte[] data, PublicKey recipientPublicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        rsa.init(Cipher.ENCRYPT_MODE, recipientPublicKey);

        return rsa.doFinal(data);
    }

    public static byte[] sign(byte[] data, PrivateKey senderPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(senderPrivateKey);

        rsa.update(data);
        return rsa.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey senderPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(senderPublicKey);

        rsa.update(data);
        return rsa.verify(signature);
    }

    public static byte[] decrypt(byte[] ciphertext, PrivateKey recipientSecretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        rsa.init(Cipher.DECRYPT_MODE, recipientSecretKey);

        return rsa.doFinal(ciphertext);
    }
}
