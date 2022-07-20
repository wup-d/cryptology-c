package sm2;

import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import org.junit.Test;

import java.security.KeyPair;

public class PGPImplByHutool {

    @Test
    public void PGPTest() {

        String M = "PGPImpl";
//
//        //使用随机生成的密钥对加密或解密
//        System.out.println("使用随机生成的密钥对加密或解密====开始");
//        SM2 sm2 = SmUtil.sm2();
//        // 公钥加密
//        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
//        System.out.println("公钥加密：" + encryptStr);
//        //私钥解密
//        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
//        System.out.println("私钥解密：" + decryptStr);
//        System.out.println("使用随机生成的密钥对加密或解密====结束");


        //使用自定义密钥对加密或解密
        System.out.println("使用自定义密钥对加密或解密====开始");

        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();

        SM2 sm22 = SmUtil.sm2(privateKey, publicKey);
        // 公钥加密
        String encKey2 = sm22.encryptBcd(M, KeyType.PublicKey);
        System.out.println("公钥加密：" + encKey2);
        //私钥解密
        String decKey2 = StrUtil.utf8Str(sm22.decryptFromBcd(encKey2, KeyType.PrivateKey));
        System.out.println("私钥解密：" + decKey2);
        System.out.println("使用自定义密钥对加密或解密====结束");

    }
}
