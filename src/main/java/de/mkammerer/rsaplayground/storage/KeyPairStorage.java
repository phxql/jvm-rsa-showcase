package de.mkammerer.rsaplayground.storage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class KeyPairStorage {
    private KeyPairStorage() {
    }

    public static void savePrivateKey(Path file, PrivateKey privateKey) throws IOException {
        // Saves the private key encoded in PKCS #8
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());

        Files.write(file, privateSpec.getEncoded());
    }

    public static void savePublicKey(Path file, PublicKey publicKey) throws IOException {
        // Saves the public key encoded in X.509
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKey.getEncoded());

        Files.write(file, publicSpec.getEncoded());
    }

    public static PrivateKey loadPrivateKey(Path file) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] privateKey = Files.readAllBytes(file);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // Expects the private key encoded in PKCS #8
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
    }

    public static PublicKey loadPublicKey(Path file) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] publicKey = Files.readAllBytes(file);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // Expects the public key encoded in X.509
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
    }
}
