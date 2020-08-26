package de.mkammerer.rsaplayground;

class InsecureWire {
    // Encrypted with recipient public RSA key. Recipient needs his own RSA private key to decrypt
    private final byte[] encryptedSessionKey;
    // Encrypted with AES session key (which is stored encrypted in encryptedSessionKey)
    private final byte[] encryptedMessage;
    // Signed with senders private RSA key. Recipient needs senders public key to verify.
    private final byte[] signature;

    public InsecureWire(byte[] encryptedSessionKey, byte[] encryptedMessage, byte[] signature) {
        this.encryptedSessionKey = encryptedSessionKey;
        this.encryptedMessage = encryptedMessage;
        this.signature = signature;
    }

    public byte[] getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    public byte[] getEncryptedMessage() {
        return encryptedMessage;
    }

    public byte[] getSignature() {
        return signature;
    }
}
