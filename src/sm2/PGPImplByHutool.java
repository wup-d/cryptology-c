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
//        //ʹ��������ɵ���Կ�Լ��ܻ����
//        System.out.println("ʹ��������ɵ���Կ�Լ��ܻ����====��ʼ");
//        SM2 sm2 = SmUtil.sm2();
//        // ��Կ����
//        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
//        System.out.println("��Կ���ܣ�" + encryptStr);
//        //˽Կ����
//        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
//        System.out.println("˽Կ���ܣ�" + decryptStr);
//        System.out.println("ʹ��������ɵ���Կ�Լ��ܻ����====����");


        //ʹ���Զ�����Կ�Լ��ܻ����
        System.out.println("ʹ���Զ�����Կ�Լ��ܻ����====��ʼ");

        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();

        SM2 sm22 = SmUtil.sm2(privateKey, publicKey);
        // ��Կ����
        String encKey2 = sm22.encryptBcd(M, KeyType.PublicKey);
        System.out.println("��Կ���ܣ�" + encKey2);
        //˽Կ����
        String decKey2 = StrUtil.utf8Str(sm22.decryptFromBcd(encKey2, KeyType.PrivateKey));
        System.out.println("˽Կ���ܣ�" + decKey2);
        System.out.println("ʹ���Զ�����Կ�Լ��ܻ����====����");

    }
}
