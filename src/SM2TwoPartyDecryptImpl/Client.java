package SM2TwoPartyDecryptImpl;

import java.io.OutputStream;
import java.net.Socket;

public class Client {
    public static void main(String args[]) throws Exception {
        // 要连接的服务端IP地址和端口
        String host = "127.0.0.1";
        int port = 55533;
        // 与服务端建立连接
        Socket socket = new Socket(host, port);
        // 建立连接后获得输出流
        OutputStream outputStream = socket.getOutputStream();
        String message = "11111111";
        // 首先需要计算得知消息的长度
        byte[] sendBytes = message.getBytes("UTF-8");
        // 然后将消息的长度优先发送出去
        outputStream.write(sendBytes.length >> 8);
        outputStream.write(sendBytes.length);
        // 然后将消息再次发送出去
        outputStream.write(sendBytes);
        outputStream.flush();

        message = "12345678";
        sendBytes = message.getBytes("UTF-8");
        outputStream.write(sendBytes.length >> 8);
        outputStream.write(sendBytes.length);
        outputStream.write(sendBytes);
        outputStream.flush();

        message = "fghjykuj";
        sendBytes = message.getBytes("UTF-8");
        outputStream.write(sendBytes.length >> 8);
        outputStream.write(sendBytes.length);
        outputStream.write(sendBytes);

        outputStream.close();
        socket.close();
    }

}
