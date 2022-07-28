package SM2TwoPartyDecryptImpl;

import SM2Impl.KeyPair;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.ShortenedDigest;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;

public class P1Decrypt {

    /**
     * 素数 p
     */
    private static final BigInteger p = new BigInteger(
            "FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFF", 16);

    /**
     * 系数 a
     */
    private static final BigInteger a = new BigInteger(
            "FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFC", 16);

    /**
     * 系数 b
     */
    private static final BigInteger b = new BigInteger(
            "28E9FA9E" + "9D9F5E34" + "4D5A9E4B" + "CF6509A7" + "F39789F5" + "15AB8F92" + "DDBCBD41" + "4D940E93", 16);

    /**
     * 坐标 x
     */
    private static final BigInteger xg = new BigInteger(
            "32C4AE2C" + "1F198119" + "5F990446" + "6A39C994" + "8FE30BBF" + "F2660BE1" + "715A4589" + "334C74C7", 16);

    /**
     * 坐标 y
     */
    private static final BigInteger yg = new BigInteger(
            "BC3736A2" + "F4F6779C" + "59BDCEE3" + "6B692153" + "D0A9877C" + "C62A4740" + "02DF32E5" + "2139F0A0", 16);

    /**
     * 基点 G, G = (xg,yg),其介记为 n
     */
    private static final BigInteger n = new BigInteger(
            "FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "7203DF6B" + "21C6052B" + "53BBF409" + "39D54123", 16);

    private static SecureRandom random = new SecureRandom();
    private ECCurve.Fp curve;
    private ECPoint G;

    public static String printHexString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            String hex = Integer.toHexString(b[i] & 0xFF);
            if (hex.length() == 1) {
                sb.append(0);
                sb.append(hex);
                hex = '0' + hex;
            }
            System.out.print(hex.toUpperCase());
            sb.append(hex);
        }
        System.out.println();
        return sb.toString();
    }

    public BigInteger random(BigInteger max) {
        BigInteger r = new BigInteger(256, random);
        while (r.compareTo(max) >= 0) {
            r = new BigInteger(128, random);
        }
        return r;
    }

    private boolean allZero(byte[] buffer) {
        int len = buffer.length;
        for (int i = 0; i < len; i++) {
            if (buffer[i] != 0) return false;
        }
        return true;
    }

    @Test
    public void test() throws Exception {
        KeyPair keyPair = generateKeyPair();

        String input = "hello world!";
        ECPoint publicKey = keyPair.getPublicKey();

        byte[] inputBuffer = input.getBytes();

        /** 产生随机数 k，k 属于 [1, n-1] */
        BigInteger k = random(n);

        /** 计算椭圆曲线点 C1 = [k]G = (x1, y1) */
        ECPoint C1 = G.multiply(k);
        byte[] C1Buffer = C1.getEncoded(false);
        BigInteger d1 = keyPair.getPrivateKey();

        BigInteger privateKey = keyPair.getPrivateKey();

        System.out.println("privateKey : " + privateKey);

        // send info
        Socket socket = new Socket("127.0.0.1", 22333);
        OutputStream outputStream = socket.getOutputStream();
        ECPoint T1 = C1.multiply(d1);
        byte[] sendBytes = T1.getEncoded(false);
        outputStream.write(sendBytes.length >> 8);
        outputStream.write(sendBytes.length);
        outputStream.write(sendBytes);
        outputStream.flush();
        outputStream.close();
        // receive info
        int port = 33222;
        ServerSocket server = new ServerSocket(port);
        System.out.println("waiting for p2 reply...");
        socket = server.accept();
        InputStream inputStream = socket.getInputStream();
        byte[] bytes = new byte[1024];
        int len;
        StringBuilder sb = new StringBuilder();
        byte[] bs = new byte[65];
        while ((len = inputStream.read(bytes)) != -1) {
            sb.append(new String(bytes, 0, len));
            bs = Arrays.copyOf(bytes, 65);
        }
        inputStream.close();
//        C1 = curve.decodePoint(bs).normalize();
        System.out.println("receive p2 info success!");

        /** 计算 [k]PB = (x2, y2) */
        ECPoint kpb = publicKey.multiply(k).normalize();

        /** 计算 t = KDF(x2||y2, klen) */
        byte[] kpbBytes = kpb.getEncoded(false);
        DerivationFunction kdf = new KDF1BytesGenerator(new ShortenedDigest(new SHA256Digest(), 20));
        byte[] t = new byte[inputBuffer.length];
        kdf.init(new ISO18033KDFParameters(kpbBytes));
        kdf.generateBytes(t, 0, t.length);

        if (allZero(t)) {
            System.err.println("all zero!");
        }

        /** 计算 C2 = M ^ t */
        byte[] C2 = new byte[inputBuffer.length];
        for (int i = 0; i < inputBuffer.length; i++) {
            C2[i] = (byte) (inputBuffer[i] ^ t[i]);
        }

        /** 计算 C3 = Hash(x2 || M || y2) */
        byte[] C3 = calculateHash(kpb.getXCoord().toBigInteger(), inputBuffer, kpb.getYCoord().toBigInteger());

        /** 输出密文 C = C1 || C2 || C3 */
        byte[] encryptResult = new byte[C1Buffer.length + C2.length + C3.length];
        System.arraycopy(C1Buffer, 0, encryptResult, 0, C1Buffer.length);
        System.arraycopy(C2, 0, encryptResult, C1Buffer.length, C2.length);
        System.arraycopy(C3, 0, encryptResult, C1Buffer.length + C2.length, C3.length);


        byte[] encryptData = encryptResult;

        byte[] C1Byte = new byte[65];
        System.arraycopy(encryptData, 0, C1Byte, 0, C1Byte.length);

        C1 = curve.decodePoint(C1Byte).normalize();

        /** 计算 [dB]C1 = (x2, y2) */
        ECPoint dBC1 = C1.multiply(privateKey).normalize();

        /** 计算t = KDF(x2 || y2, klen) */
        byte[] dBC1Bytes = dBC1.getEncoded(false);
        kdf = new KDF1BytesGenerator(new ShortenedDigest(new SHA256Digest(), 20));
        int klen = encryptData.length - 65 - 20;

        t = new byte[klen];
        kdf.init(new ISO18033KDFParameters(dBC1Bytes));
        kdf.generateBytes(t, 0, t.length);

        if (allZero(t)) {
            System.err.println("all zero!");
        }

        /** 计算 M' = C2 ^ t */
        byte[] M = new byte[klen];
        for (int i = 0; i < M.length; i++) {
            M[i] = (byte) (encryptData[C1Byte.length + i] ^ t[i]);
        }

        /** 计算 u = Hash(x2 || M' || y2) 判断 u == C3 是否成立 */
        C3 = new byte[20];
        System.arraycopy(encryptData, encryptData.length - 20, C3, 0, 20);
        byte[] u = calculateHash(dBC1.getXCoord().toBigInteger(), M, dBC1.getYCoord().toBigInteger());
        if (Arrays.equals(u, C3)) {
            System.out.print("u = ");
            printHexString(u);
            System.out.print("C3 = ");
            printHexString(C3);
            System.out.println("successfully!");
            System.out.println("M' : " + new String(M));
        } else {
            System.out.print("u = ");
            printHexString(u);
            System.out.print("C3 = ");
            printHexString(C3);
            System.err.println("failed!");
        }
    }

    private byte[] calculateHash(BigInteger x2, byte[] M, BigInteger y2) {
        ShortenedDigest digest = new ShortenedDigest(new SHA256Digest(), 20);
        byte[] buf = x2.toByteArray();
        digest.update(buf, 0, buf.length);
        digest.update(M, 0, M.length);
        buf = y2.toByteArray();
        digest.update(buf, 0, buf.length);
        buf = new byte[20];
        digest.doFinal(buf, 0);
        return buf;
    }

    private boolean between(BigInteger param, BigInteger min, BigInteger max) {
        if (param.compareTo(min) >= 0 && param.compareTo(max) < 0) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 公钥校验
     */
    private boolean checkPublicKey(ECPoint publicKey) {
        if (!publicKey.isInfinity()) {
            BigInteger x = publicKey.getXCoord().toBigInteger();
            BigInteger y = publicKey.getYCoord().toBigInteger();
            if (between(x, new BigInteger("0"), p) && between(y, new BigInteger("0"), p)) {
                BigInteger xResult = x.pow(3).add(a.multiply(x)).add(b).mod(p);
                // System.out.println("xResult: " + xResult);
                BigInteger yResult = y.pow(2).mod(p);
                // System.out.println("yResult: " + yResult);
                if (yResult.equals(xResult) && publicKey.multiply(n).isInfinity()) {
                    return true;
                }
            }
            return false;
        } else {
            return false;
        }
    }

    /**
     * 获得公私钥对
     */
    public KeyPair generateKeyPair() {
        BigInteger d = random(n.subtract(new BigInteger("1")));
        KeyPair keyPair = new KeyPair(G.multiply(d).normalize(), d);
        if (checkPublicKey(keyPair.getPublicKey())) {
            System.out.println("generate key successfully!");
            return keyPair;
        } else {
            System.err.println("generate key failed!");
            return null;
        }
    }

    public P1Decrypt() {
        curve = new ECCurve.Fp(p, a, b);
        G = curve.createPoint(xg, yg);
    }

}