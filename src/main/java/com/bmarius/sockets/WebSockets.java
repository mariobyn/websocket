package com.bmarius.sockets;


import com.bmarius.utils.StaticValues;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * WebSocktes protocol implementation in Java.
 * Running in another thread
 */

public class WebSockets implements Runnable{

    private static DataOutputStream out;
    private static DataInputStream in;
    private static ServerSocket serverSocket;

    public Logger logger = Logger.getLogger(this.getClass().getName());


    public WebSockets() {
    }

    public void run() {
        try {
            //listen in 8112
            serverSocket = new ServerSocket(StaticValues.port);
            System.out.println("Server Started");
            while(true) {
                Socket socket = serverSocket.accept();

                //oppening channel for output stream
                out = new DataOutputStream(socket.getOutputStream());
                //get input channel
                InputStream in = socket.getInputStream();

                BufferedReader br = new BufferedReader( new InputStreamReader(in));
                String line;
                String key = null;
                String origin = "unavailable";
                int test = 0;
                while(!(line = br.readLine()).isEmpty()){

                    /**
                     *  split header line
                     */
                    if(line.contains(": ")){
                        /**
                         * if connection is websocket
                         */
                        String[] items = line.split(": ");
                        if(items[0].toLowerCase().trim().equals("upgrade")){
                            if(items[1].toLowerCase().trim().equals("websocket"))
                                test++;
                        }

                        /**
                         * if origin is server value from StaticValues
                         */
                        if(items[0].toLowerCase().trim().equals("origin")){
                            if(origin.contains(StaticValues.server))
                                test++;
                        }

                        /**
                         * retaining host value
                         */
                        if(items[0].toLowerCase().trim().equals("host"))
                            origin = items[1];

                        /**
                         * retaining key
                         */
                        if(items[0].toLowerCase().contains("sec-websocket-key")){
                            key = line.substring(line.indexOf(":")+1).trim();
                        }
                    }
                }

                /**
                 * if tests failed then close everything and throw UnauthorizedAccess
                 */
                if(test != 2){
                    out.close();
                    socket.close();
                    throw new UnauthorizedAccess("Unauthorized Access");
                }
                logger.log(Level.INFO,"Server accepted connection from " + origin);


                /**
                 * Encrypt key
                 */
                String accept = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

                //sha1
                byte[] digest = MessageDigest.getInstance("SHA-1")
                        .digest(accept.getBytes("UTF8"));
                //base64
                accept = DatatypeConverter.printBase64Binary(digest);

                /**
                 * Build header for response
                 */
                String handshake = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" +
                        "Upgrade: WebSocket\r\n" +
                        "Connection: Upgrade\r\n" +
                        "WebSocket-Origin: http://"+ StaticValues.server+"/\r\n" +
                        "WebSocket-Location: ws://"+ StaticValues.server+":8112/\r\n" +
                        "Sec-WebSocket-Accept: " + accept + "\r\n" +
                        "WebSocket-Protocol: sample\r\n\r\n";
                /**
                 * Send handshake response
                 */
                out.write(handshake.getBytes("UTF8"));

                logger.log(Level.INFO, "Handshake response sent!");
            }
        } catch(Exception e) {
            logger.log(Level.SEVERE, e.getMessage());
        }
    }


    /**
     *
     * @param message to send
     * @throws java.io.IOException
     */
    public static void send(String message) throws IOException {
        /**
         * get message bytes
         */

        System.out.println(out);
        byte[] utf = message.getBytes("UTF8");

        /**
         * write 129 bytes
         */
        out.write(129);

        /**
         * writing message length
         */
        if(utf.length > 65535) {
            out.write(127);
            out.write(utf.length >> 16);
            out.write(utf.length >> 8);
            out.write(utf.length);
        }
        else if(utf.length>125) {
            out.write(126);
            out.write(utf.length >> 8);
            out.write(utf.length);
        }
        else {
            out.write(utf.length);
        }

        out.write(utf);

    }

    private void readFully(byte[] b) throws IOException {

        int readen = 0;
        while(readen<b.length)
        {
            int r = in.read(b, readen, b.length-readen);
            if(r==-1)
                break;
            readen+=r;
        }
    }

    public String read() throws IOException {

        int opcode = in.read();
        //boolean whole = (opcode & 0b10000000) !=0;
        opcode = opcode & 0xF;

        if(opcode!=1)
            throw new IOException("Wrong opcode: " + opcode);

        int len = in.read();
        boolean encoded = (len >= 128);

        if(encoded)
            len -= 128;

        if(len == 127) {
            len = (in.read() << 16) | (in.read() << 8) | in.read();
        }
        else if(len == 126) {
            len = (in.read() << 8) | in.read();
        }

        byte[] key = null;

        if(encoded) {
            key = new byte[4];
            readFully(key);
        }

        byte[] frame = new byte[len];

        readFully(frame);

        if(encoded) {
            for(int i=0; i<frame.length; i++) {
                frame[i] = (byte) (frame[i] ^ key[i%4]);
            }
        }

        return new String(frame, "UTF8");
    }

    public void close() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            System.err.println(e);
        }
    }
}
