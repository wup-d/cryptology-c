package attack_for_sm3;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * example for length extension attack.
 */
public class AttackImpl {
    private static final String[] IV_C = {"422f0657b5b92e635ebb918f8833bf5b", "4f4fdbb59e273255aa901b13fce6ef6e",
            "fd6e8dff7bd95abeb645135ca18bba95", "ba991d0f2a8ca27e61b9459499eeece6"};
    private static final String[] replace = {"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f"};
    private static final char[] cs = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


    public static void main(String[] args) {
        String m = "666c61677b62616533643365303263383139346532346330303264656332633638663666387d0a0a0a0a0a0a0a0a0a0a";

        String a1 = recovery(IV_C[0], IV_C[1], "", 15, 0);
        String m1 = XOR(a1, IV_C[0]);
        String a2 = recovery(IV_C[1], IV_C[2], "", 15, 0);
        String m2 = XOR(a2, IV_C[1]);
        String m3 = paddingTrack(2, 3);
        System.out.println("m1: " + m1);
        System.out.println("m2: " + m2);
        System.out.println("m3: " + m3);
        System.out.println("m: " + m1 + m2 + m3);
    }

    private static String paddingTrack(int index1, int index2) {
        String res = null;
        char[] C2_t = IV_C[index1].toCharArray();
        for (int i = 0; i < 32; i += 2) {
            char ct = C2_t[i];
            C2_t[i] = ct >= '0' && ct <= '9' ? 'a' : '1';
            String st = String.valueOf(C2_t);
            if (!decrypt(st + IV_C[index2])) {
                StringBuilder second = new StringBuilder();
                for (int j = i; j < 32; j += 2) second.append(replace[(32 - i) >> 1]);
                String a = recovery(IV_C[index1], IV_C[index2], XOR(IV_C[index1].substring(i, 32), second.toString()), (i - 2) >> 1, 16 - (i >> 1));
                res = XOR(IV_C[index1], a);
                break;
            }
            C2_t[i] = ct;
        }
        return res;
    }

    /**
     * 恢复方法
     */
    private static String recovery(String r, String y, String a, int index, int cnt) {
        for (int i = index; i >= 0; i--) {
            System.out.println(a + " -- " + cnt);
            String r_left = r.substring(0, i << 1);
            String r_right = XOR(generate(cnt + 1).substring(2), a);
            for (String s : iterator()) {
                if (decrypt(r_left + s + r_right + y)) {
                    a = XOR(s, replace[cnt + 1]) + a;
                    cnt++;
                }
            }
        }
        return a;
    }

    /**
     * 迭代方法
     */
    private static String[] iterator() {
        String[] res = new String[256];
        int index = 0;
        StringBuilder sb = new StringBuilder();
        for (char c1 : cs) {
            sb.append(c1);
            for (char c2 : cs) {
                sb.append(c2);
                res[index++] = sb.toString();
                sb.deleteCharAt(1);
            }
            sb.deleteCharAt(0);
        }
        return res;
    }

    /**
     * 生成组合
     */
    private static String generate(int target) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < target; i++) {
            sb.append(replace[target]);
        }
        return sb.toString();
    }

    /**
     * 两个片段的异或操作
     */
    private static String XOR(String R1, String R2) {
        R1 = hexadecimalToBinary(R1);
        R2 = hexadecimalToBinary(R2);
        StringBuilder sb = new StringBuilder();
        int n = R1.length();
        for (int i = 0; i < n; i++) {
            sb.append(R1.charAt(i) == R2.charAt(i) ? 0 : 1);
        }
        return binaryToHexadecimal(sb.toString());
    }

    /**
     * 十六进制转二进制
     */
    private static String hexadecimalToBinary(String s) {
        int n = s.length();
        StringBuffer binaryData = new StringBuffer();
        for (int i = 0; i < n; i++) {
            int num = Integer.parseInt(s.substring(i, i + 1), 16);
            StringBuilder sb = new StringBuilder();
            for (int j = 3; j >= 0; j--) {
                if (((1 << j) & num) != 0) {
                    sb.append(1);
                } else {
                    sb.append(0);
                }
            }
            binaryData.append(sb);
        }
        return binaryData.toString();
    }

    /**
     * 二进制转十进制
     */
    private static String binaryToHexadecimal(String s) {
        int n = s.length();
        StringBuilder hexadecimalData = new StringBuilder();
        for (int i = 0; i < n; i += 4) {
            int num = Integer.valueOf(s.substring(i, i + 4), 2);
            if (num < 10) {
                hexadecimalData.append(num);
            } else {
                switch (num) {
                    case 10:
                        hexadecimalData.append('a');
                        break;
                    case 11:
                        hexadecimalData.append('b');
                        break;
                    case 12:
                        hexadecimalData.append('c');
                        break;
                    case 13:
                        hexadecimalData.append('d');
                        break;
                    case 14:
                        hexadecimalData.append('e');
                        break;
                    default:
                        hexadecimalData.append('f');
                        break;
                }
            }
        }
        return hexadecimalData.toString();
    }

    /**
     * 加密测试
     */
    private static String encrypt(String info) {
        // 执行exe: cmd = exe存放路径 + 空格 + 调用 exe 时需要传入的参数.
        String cmd = "D:/Users/27552/Desktop/PaddingOracleExp/12/enc_oracle.exe " + info;
        BufferedReader br = null;
        BufferedReader brError = null;
        String res = "";
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            String line = null;
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            brError = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            while ((line = br.readLine()) != null || (line = brError.readLine()) != null) {
                // System.out.println(line);
                res = line;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return res.substring(8);
    }

    /**
     * 解密测试
     */
    private static boolean decrypt(String info) {
        // 执行exe: cmd = exe存放路径 + 空格 + 调用 exe 时需要传入的参数.
        String cmd = "D:/Users/27552/Desktop/PaddingOracleExp/12/dec_oracle.exe " + info;
        BufferedReader br = null;
        BufferedReader brError = null;
        String res = "";
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            String line = null;
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            brError = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            while ((line = br.readLine()) != null || (line = brError.readLine()) != null) {
                res = line;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return "HTTP 200.".equals(res);
    }
}
