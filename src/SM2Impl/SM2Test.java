package SM2Impl;

import org.junit.Test;

import java.util.Arrays;

public class SM2Test {
    private static final String smg = "SM2Impl test! SM2Impl test! SM2Impl test!";

    @Test
    public void test() {
        SM2 sm2 = new SM2();
        KeyPair keyPair = sm2.generateKeyPair();
        byte[] data = sm2.encrypt(smg, keyPair.getPublicKey());
        System.out.println("source info : " + Arrays.toString(data));
        sm2.decrypt(data, keyPair.getPrivateKey());
    }

}