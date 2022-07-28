package SM2TwoPartyDecryptImpl;

import SM2Impl.KeyPair;
import SM2Impl.SM2;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

public class P2Decrypt {

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
    private static ECCurve.Fp curve;

    public static void main(String args[]) throws Exception {
        curve = new ECCurve.Fp(p, a, b);
        SM2 sm2 = new SM2();
        KeyPair keyPair = sm2.generateKeyPair();
        BigInteger d2 = keyPair.getPrivateKey();
        System.out.println("privateKey : " + d2);
        // 监听指定的端口
        int port = 22333;
        ServerSocket server = new ServerSocket(port);
        System.out.println("waiting for p1 reply... ");
        Socket socket = server.accept();
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
        ECPoint T1 = curve.decodePoint(bs).normalize();
        ECPoint T2 = T1.multiply(d2);
        socket = new Socket("127.0.0.1", 33222);
        OutputStream outputStream = socket.getOutputStream();
        byte[] sendBytes = T2.getEncoded(false);
        outputStream.write(sendBytes.length >> 8);
        outputStream.write(sendBytes.length);
        outputStream.write(sendBytes);
        outputStream.flush();
        outputStream.close();
        System.out.println("send info success!");
    }
}
