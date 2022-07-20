package sm2;

import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import org.junit.Test;

import java.security.KeyPair;

public class PGPImplByHutool {

    @Test
    public void PGPTest() {

        String M = "PGPImpl";

        // generate privateKey and publicKey
        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();

        // Symmetric encryption
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto("RC2");
        byte[] sym_encrypt = symmetricCrypto.encrypt(M.getBytes());

        SM2 sm2 = SmUtil.sm2(privateKey, publicKey);

        // publicKey encryption
        String encrypt = sm2.encryptBcd(M, KeyType.PublicKey);
        System.out.println("encrypt: " + encrypt);

        // privateKey decryption
        String decrypt = StrUtil.utf8Str(sm2.decryptFromBcd(encrypt, KeyType.PrivateKey));
        System.out.println("decrypt: " + decrypt);

        // Symmetric decryption
        byte[] sym_decrypt = symmetricCrypto.decrypt(decrypt.getBytes());
        System.out.println(StrUtil.utf8Str(sym_decrypt));

    }
}
