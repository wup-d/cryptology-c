package SM2Impl;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class KeyPair {

    private ECPoint publicKey;
    private BigInteger privateKey;

    public KeyPair(ECPoint publicKey, BigInteger privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

}