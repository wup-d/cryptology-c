import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import org.junit.Test;

import java.security.KeyPair;

public class SM2PGPImpl {

    @Test
    public void PGPTest() {

        String enc_m = "PGPImpl SUCCESS!";
        System.out.println("source info : " + enc_m);

        // generate privateKey and publicKey.
        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();

        // generate symmetricCrypto obj.
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto("RC2");

        // symmetric encryption.
        byte[] sym_encrypt = symmetricCrypto.encrypt(enc_m);

        // generate sm2 obj.
        SM2 sm2 = SmUtil.sm2(privateKey, publicKey);

        // publicKey encryption.
        byte[] encrypt = sm2.encrypt(sym_encrypt, KeyType.PublicKey);

        // privateKey decryption.
        byte[] decrypt = sm2.decrypt(encrypt, KeyType.PrivateKey);

        // symmetric decryption.
        byte[] sym_decrypt = symmetricCrypto.decrypt(decrypt);

        String dec_m = StrUtil.utf8Str(sym_decrypt);
        System.out.println("double encryption and double decryption after : " + dec_m);
    }
}
