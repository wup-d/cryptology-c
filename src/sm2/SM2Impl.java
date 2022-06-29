package sm2;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.ECPoint;

public class SM2Impl {

    public enum Mode {
        C1C2C3, C1C3C2;
    }

    private final Digest digest;
    private final Mode mode;

    private boolean forEncryption;
    private ECKeyParameters ecKey;
    private ECDomainParameters ecParams;
    private int curveLength;
    private SecureRandom random;

    /***
     * 默认采用国标：C1||C3||C2
     */
    public SM2Impl() {
        this(new SM3Digest(), Mode.C1C3C2);
    }

    public SM2Impl(Mode mode) {
        this(new SM3Digest(), mode);
    }

    public SM2Impl(Digest digest) {
        this(digest, Mode.C1C2C3);
    }

    public SM2Impl(Digest digest, Mode mode) {
        if (mode == null) {
            throw new IllegalArgumentException("mode cannot be NULL");
        }
        this.digest = digest;
        this.mode = mode;
    }

    /**
     * 初始化
     * @param forEncryption true-公钥加密, false-私钥解密
     * @param param 密码参数，从中获取公或私钥、及椭圆曲线相关参数
     */
    public void init(boolean forEncryption, CipherParameters param) {
        this.forEncryption = forEncryption;

        if (forEncryption) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;

            ecKey = (ECKeyParameters) rParam.getParameters();
            ecParams = ecKey.getParameters();

            org.bouncycastle.math.ec.ECPoint s = ((ECPublicKeyParameters) ecKey).getQ().multiply(ecParams.getH());
            if (s.isInfinity()) {
                throw new IllegalArgumentException("invalid key: [h]Q at infinity");
            }

            random = rParam.getRandom();
        } else {
            ecKey = (ECKeyParameters) param;
            ecParams = ecKey.getParameters();
        }

        curveLength = (ecParams.getCurve().getFieldSize() + 7) / 8;
    }

    /**
     * 进行加密、或解密
     * @param in
     * @param inOff
     * @param inLen
     * @return
     * @throws InvalidCipherTextException
     */
    public byte[] processBlock(
            byte[] in,
            int inOff,
            int inLen)
            throws IOException, InvalidCipherTextException {
        if (forEncryption) {
            return encrypt(in, inOff, inLen);
        } else {
            return decrypt(in, inOff, inLen);
        }
    }

    public int getOutputSize(int inputLen) {
        return (1 + 2 * curveLength) + inputLen + digest.getDigestSize();
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    private byte[] encrypt(byte[] in, int inOff, int inLen)
            throws IOException {
        byte[] c2 = new byte[inLen];

        System.arraycopy(in, inOff, c2, 0, c2.length);

        ECMultiplier multiplier = createBasePointMultiplier();

        org.bouncycastle.math.ec.ECPoint c1P;
        ECPoint kPB = null;
        do {
            BigInteger k = nextK();

            c1P = multiplier.multiply(ecParams.getG(), k).normalize();
            // c1 = c1P.getEncoded(false);

//            kdf(digest, kPB, c2);
        }

        while (notEncrypted(c2, in, inOff));

        byte[] c3 = new byte[digest.getDigestSize()];

        addFieldElement(digest, kPB.getAffineX());
        digest.update(in, inOff, inLen);
        addFieldElement(digest, kPB.getAffineY());

        digest.doFinal(c3, 0);

        switch (mode) {
            case C1C3C2:

                final ASN1EncodableVector vector = new ASN1EncodableVector();
                vector.add(new ASN1Integer(c1P.getXCoord().toBigInteger()));
                vector.add(new ASN1Integer(c1P.getYCoord().toBigInteger()));
                vector.add(new DEROctetString(c3));
                vector.add(new DEROctetString(c2));
                return new DERSequence(vector).getEncoded();
            default:
                byte[] c1 = c1P.getEncoded(false);
                return Arrays.concatenate(c1, c2, c3);
        }
    }

    private byte[] decrypt(byte[] in, int inOff, int inLen)
            throws InvalidCipherTextException, IOException {

        org.bouncycastle.math.ec.ECPoint c1P; // = ecParams.getCurve().decodePoint(c1);
        byte[] inHash ;
        byte[] inCipherData;

        if (mode == Mode.C1C3C2) {

            ASN1InputStream inputStream = new ASN1InputStream(in);
            ASN1Sequence seq = (ASN1Sequence) inputStream.readObject();
            if (seq.size() != 4){
                throw new InvalidCipherTextException("invalid cipher text");
            }
            int index = 0;

            // C1 == XCoordinate 、YCoordinate
            BigInteger x = ((ASN1Integer) seq.getObjectAt(index ++)).getPositiveValue();
            // YCoordinate
            BigInteger y = ((ASN1Integer) seq.getObjectAt(index ++)).getPositiveValue();

            // XCoord 、YCoord ==> CEPoint (C1)
            c1P = ecParams.getCurve().createPoint(x, y);

            // HASH (C3)
            inHash = ((ASN1OctetString)seq.getObjectAt(index ++)).getOctets();

            // CipherText (C2)
            inCipherData = ((ASN1OctetString)seq.getObjectAt(index)).getOctets();
        } else {
            // C1
            byte[] c1 = new byte[curveLength * 2 + 1];
            System.arraycopy(in, inOff, c1, 0, c1.length);
            c1P = ecParams.getCurve().decodePoint(c1);

            // C2 == inCipherData
            int digestSize = this.digest.getDigestSize();
            inCipherData = new byte[inLen - c1.length - digestSize];
            System.arraycopy(in, inOff + c1.length, inCipherData, 0, inCipherData.length);

            // C3 == Hash
            inHash = new byte[digestSize];
            System.arraycopy(in, inOff + c1.length + inCipherData.length, inHash, 0, inHash.length);
        }

        // 解密 ==> inCipherData;
        org.bouncycastle.math.ec.ECPoint s = c1P.multiply(ecParams.getH());
        if (s.isInfinity())
        {
            throw new InvalidCipherTextException("[h]C1 at infinity");
        }

        c1P = c1P.multiply(((ECPrivateKeyParameters)ecKey).getD()).normalize();
//        kdf(digest, c1P, inCipherData);

        // 动态计算已解密的明文的摘要并比较
        byte[] cipherDigest = new byte[digest.getDigestSize()];
        addFieldElement(digest, c1P.getXCoord().toBigInteger());
        digest.update(inCipherData, 0, inCipherData.length);
        addFieldElement(digest, c1P.getYCoord().toBigInteger());

        digest.doFinal(cipherDigest, 0);

        int check = 0;
        if (mode == Mode.C1C3C2)
        {
            for (int i = 0; i != cipherDigest.length; i++) {
                check |= cipherDigest[i] ^ inHash[i];
            }
        } else {
            for (int i = 0; i != cipherDigest.length; i++) {
                check |= cipherDigest[i] ^ inHash[i];
            }
        }

        // Arrays.fill(c1, (byte)0);
        Arrays.fill(cipherDigest, (byte)0);

        if (check != 0)
        {
            Arrays.fill(inCipherData, (byte)0);
            throw new InvalidCipherTextException("invalid cipher text");
        }

        // return c2;
        return inCipherData;
    }

    private boolean notEncrypted(byte[] encData, byte[] in, int inOff) {
        for (int i = 0; i != encData.length; i++) {
            if (encData[i] != in[inOff + i]) {
                return false;
            }
        }

        return true;
    }

    private void kdf(Digest digest, ECPoint c1, byte[] encData) {
        int digestSize = digest.getDigestSize();
        byte[] buf = new byte[Math.max(4, digestSize)];
        int off = 0;

        Memoable memo = null;
        Memoable copy = null;

        if (digest instanceof Memoable) {
            addFieldElement(digest, c1.getAffineX());
            addFieldElement(digest, c1.getAffineY());
            memo = (Memoable) digest;
            copy = memo.copy();
        }

        int ct = 0;

        while (off < encData.length) {
            if (memo != null) {
                memo.reset(copy);
            } else {
                addFieldElement(digest, c1.getAffineX());
                addFieldElement(digest, c1.getAffineY());
            }

            Pack.intToBigEndian(++ct, buf, 0);
            digest.update(buf, 0, 4);
            digest.doFinal(buf, 0);

            int xorLen = Math.min(digestSize, encData.length - off);
            xor(encData, buf, off, xorLen);
            off += xorLen;
        }
    }

    private void xor(byte[] data, byte[] kdfOut, int dOff, int dRemaining) {
        for (int i = 0; i != dRemaining; i++) {
            data[dOff + i] ^= kdfOut[i];
        }
    }

    private BigInteger nextK() {
        int qBitLength = ecParams.getN().bitLength();

        BigInteger k;
        do {
            k = BigIntegers.createRandomBigInteger(qBitLength, random);
        }
        while (k.equals(BigIntegers.ZERO) || k.compareTo(ecParams.getN()) >= 0);

        return k;
    }

    private void addFieldElement(Digest digest, BigInteger v) {
        byte[] p = BigIntegers.asUnsignedByteArray(curveLength, v);

        digest.update(p, 0, p.length);
    }
}