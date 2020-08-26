package de.mkammerer.rsaplayground;

import de.mkammerer.rsaplayground.crypto.RSA;
import de.mkammerer.rsaplayground.storage.KeyPairStorage;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {
    private static final int RSA_KEY_SIZE = 2048; // bits
    private static final int AES_KEY_SIZE = 128; // bits

    public static void main(String[] args) throws Exception {
        new Main().run();
    }

    private void run() throws Exception {
        Alice alice = createAlice();
        Bob bob = createBob();

        String alicesMessage = "Dear Bob, this is my very secret message, only for your eyes.";
        InsecureWire insecureWire = alice.encrypt(alicesMessage, bob.getPublicKey());
        System.out.println("Alice sent  : " + alicesMessage);

        String bobsMessage = bob.decrypt(insecureWire, alice.getPublicKey());
        System.out.println("Bob received: " + bobsMessage);
    }

    private Alice createAlice() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        KeyPair keypair = RSA.generateKeyPair(RSA_KEY_SIZE);
        KeyPairStorage.savePrivateKey(Paths.get("alice.private"), keypair.getPrivate());
        KeyPairStorage.savePublicKey(Paths.get("alice.public"), keypair.getPublic());
        // This is redundant but showcases the loading of RSA keys from files
        keypair = new KeyPair(
            KeyPairStorage.loadPublicKey(Paths.get("alice.public")),
            KeyPairStorage.loadPrivateKey(Paths.get("alice.private"))
        );
        return new Alice(keypair, AES_KEY_SIZE);
    }

    private Bob createBob() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        KeyPair keypair = RSA.generateKeyPair(RSA_KEY_SIZE);
        KeyPairStorage.savePrivateKey(Paths.get("bob.private"), keypair.getPrivate());
        KeyPairStorage.savePublicKey(Paths.get("bob.public"), keypair.getPublic());
        // This is redundant but showcases the loading of RSA keys from files
        keypair = new KeyPair(
            KeyPairStorage.loadPublicKey(Paths.get("bob.public")),
            KeyPairStorage.loadPrivateKey(Paths.get("bob.private"))
        );
        return new Bob(keypair);
    }
}
