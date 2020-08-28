package de.mkammerer.rsaplayground;

import de.mkammerer.rsaplayground.crypto.AES;
import de.mkammerer.rsaplayground.crypto.RSA;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

class Alice {
    private final KeyPair alicesKeys;
    private final int aesKeySizeInBits;

    Alice(KeyPair alicesKeys, int aesKeySizeInBits) {
        this.alicesKeys = alicesKeys;
        this.aesKeySizeInBits = aesKeySizeInBits;
    }

    public PublicKey getPublicKey() {
        return alicesKeys.getPublic();
    }

    public InsecureWire encrypt(String message, PublicKey recipientPublicKey) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        // Generate random session key
        SecretKey sessionKey = AES.generateKey(aesKeySizeInBits);

        // AES Encrypt data with session key
        byte[] aesEncrypted = AES.encrypt(message.getBytes(StandardCharsets.UTF_8), sessionKey);

        // Encrypt the session key with RSA with recipient's public key
        byte[] rsaEncrypted = RSA.encrypt(sessionKey.getEncoded(), recipientPublicKey);
        // Sign the message with RSA with our own public key
        byte[] signature = RSA.sign(rsaEncrypted, alicesKeys.getPrivate());

        return new InsecureWire(rsaEncrypted, aesEncrypted, signature);
    }
}
