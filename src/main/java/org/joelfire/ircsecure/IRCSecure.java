// Copyright (c) 2013 Joel Firehammer

/**
 * This is a very simple IRC encryptor. It differs from SSL in that is actually
 * encrypts the content of message posted in channels. So anyone who is not 
 * running this will see gibberish. 
 * 
 * Caveat: I wrote this years ago, and am posting this more as a way to evaluate github.
 * It works, but a lot of basic functionality (like reading a key from a file, 
 * public/private crypt, etc.) is not there. Or put another way, do not judge please.
 * 
 */

package org.joelfire.ircsecure;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class IRCSecure {
    private static final int PORT_DEFAULT = 6667;
    private static final String KEY_DEFAULT = "hxAAN5Rpopi5/MWpt5rATQ==";
    private static final String ALGORITHM_DEFAULT = "AES";
    private static final int KEYSIZE_DEFAULT = 128;
    private static final boolean DEBUG = true;

    private static Logger log = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME); 

    private SecretKey key;
    private AlgorithmParameterSpec spec = new IvParameterSpec(new byte[16]);
    
    enum State {
        PLAINTEXT,
        EXPECT_PRIVMSG,
        EXPECT_COLON,
        EXPECT_MESSAGE,
        CRYPT
    }

    public static void main(String args[]) {
        if (args.length == 0) {
            usage();
            System.exit(1);
        }
        if (args[0].equals("-k")) {
            String s = keyToString(generateKey(ALGORITHM_DEFAULT));
            System.err.println(s);
            System.exit(0);
        }
        String addr = args[0];
        int port = PORT_DEFAULT;
        int remotePort = PORT_DEFAULT;
        try {
            if (args.length > 1) {
                remotePort = Integer.parseInt(args[1]);
            }
            if (args.length > 2) {
                port = Integer.parseInt(args[2]);
            }
        } catch (NumberFormatException nfe) {
            System.out.println(nfe);
            usage();
            System.exit(2);
        }
        new IRCSecure().runServer(port, addr, remotePort);
    }
    
    private static void usage() {
        System.out.println("Usage: ");
        System.out.println("java -jar [this.jar] [-k] server_host [server_port] [local_port] ");
        System.out.println("    -k generate key and quit");
        System.out.println("    server_host     IRC server host");
        System.out.println("    [server_port]   IRC server port, default: " + PORT_DEFAULT);
        System.out.println("    [local_port]    local port, default: " + PORT_DEFAULT);
    }
        
    private void runServer(int localPort, String serverAddress, int remotePort) {
        key = stringToKey(KEY_DEFAULT, ALGORITHM_DEFAULT);
        log.info("Listening on port " + localPort + " to " + serverAddress);
        do {
            try {
                readWrite(localPort, serverAddress, remotePort);
            } catch (IOException e) {
                log.log(Level.WARNING, "Error listening to socket, will restart", e);
            } catch (InterruptedException e) {
                log.log(Level.WARNING, "Unexpected interruption, will exit");
                break;
            }
        } while (true);
    }
    
    private void readWrite(int localPort, String addr, int remotePort) throws IOException, InterruptedException  {
        ServerSocket ss = new ServerSocket(localPort);
        try {
            ss.setReuseAddress(true);
            
            final Object o = new Object();
            final Socket irc = new Socket(addr, remotePort);
            final Socket s = ss.accept();
            Thread t = new Thread(new Runnable() {
    
                public void run() {
                    try {
                        BufferedOutputStream bos = new BufferedOutputStream(irc.getOutputStream());
                        copy(s.getInputStream(), bos, true);
                    } catch (IOException e) {
                        log.log(Level.WARNING, "Error copying input to client", e);
                        try {
                            s.close();
                        } catch (IOException e1) {
                            log.log(Level.WARNING, "Error closing", e1);
                        }
                        try {
                            irc.close();
                        } catch (IOException e1) {
                            log.log(Level.WARNING, "Error closing", e1);
                        }
                        synchronized (o) {
                            o.notify();
                        }
                    }
                }
    
            });
            t.start();
            t = new Thread(new Runnable() {
    
                public void run() {
                    try {
                        BufferedOutputStream bos = new BufferedOutputStream(s.getOutputStream());
                        copy(irc.getInputStream(), bos, false);
                    } catch (IOException e) {
                        log.log(Level.WARNING, "Error copying output to server", e);
                        try {
                            irc.close();
                        } catch (IOException e1) {
                            log.log(Level.WARNING, "Error closing", e1);
                        }
                        try {
                            s.close();
                        } catch (IOException e1) {
                            log.log(Level.WARNING, "Error closing", e1);
                        }
                        synchronized (o) {
                            o.notify();
                        }
                    }
                }
    
            });
            t.start();
            synchronized (o) {
                o.wait();
            }
        } finally {
            ss.close();
        }
    }

    private StringBuffer pushBuffer(StringBuffer data, boolean direction, OutputStream os) throws IOException {
        if (data != null) {
            String s = data.toString();
            byte ba[] = encode(s, direction).getBytes();
            os.write(ba);
        }
        return null;
    }
    
    private void copy(InputStream is, OutputStream os, boolean direction) throws IOException {
        int i = 0;
        StringBuffer cmdBuffer = new StringBuffer();
        StringBuffer cryptData = null;
        State state = State.PLAINTEXT;
        while ((i = is.read()) >= 0) {
            if (i == '\n' || i == '\r') {
                cryptData = pushBuffer(cryptData, direction, os);
                os.write(i);
                os.flush();
                cmdBuffer = new StringBuffer();
                state = State.PLAINTEXT;
                if (DEBUG) {
                    System.out.print((char) i);
                }
                continue;
            } 
            
            boolean write = true;
            switch (state) {
            case PLAINTEXT: 
                if (i == 'P') {
                    state = State.EXPECT_PRIVMSG;
                    cmdBuffer.append((char) i);
                }
                break;

            case EXPECT_PRIVMSG: 
                cmdBuffer.append((char) i);
                if (cmdBuffer.length() == "PRIVMSG".length()) {
                    if (cmdBuffer.toString().equals("PRIVMSG")) {
                        state = State.EXPECT_COLON;
                    } else {
                        state = State.PLAINTEXT;
                    }
                }
                break;

            case EXPECT_COLON: 
                if (i == ':') {
                    state = State.EXPECT_MESSAGE;
                    cryptData = new StringBuffer();
                }
                break;

            case EXPECT_MESSAGE: 
                if (direction) {                 // encrypt
                    if (i == '*') {
                        state = State.PLAINTEXT;
                    } else if (i != 1) {         // TODO: can't recall what the 1 check was for
                        os.write('!');           // indicate crypt start
                        state = State.CRYPT;
                        write = false;
                        cryptData = new StringBuffer();
                        cryptData.append((char) i);
                    }
                } else if (i == '!') {           // decrypt start
                    state = State.CRYPT;
                    write = false;
                    cryptData = new StringBuffer();
                } else if (i != 1) {             // TODO: can't recall what the 1 check was for
                    // also not sure about this.
                    if (i == '-') {
                        write = false;
                    } else {
                        if (i != 1) {
                            os.write('&');
                        }
                        state = State.PLAINTEXT;
                    }
                }
                break;

            case CRYPT: 
                if (i == 1) {                   // TODO: can't recall what the 1 check was for
                    cryptData = pushBuffer(cryptData, direction, os);
                    state = State.PLAINTEXT;
                } else {
                    write = false;
                    cryptData.append((char) i);
                }
                break;
            }
            if (DEBUG) {
                System.out.print((char) i);
            }
            if (write) {
                os.write(i);
            }
        }
    }

    private String encode(String input, boolean dir) {
        if (dir) {
            String s = encryptPlainToBase64(input);
            s = s.replaceAll("\n", "");
            s = s.replaceAll("\r", "");
            return s;
        } else {
            String dec = input;
            return decryptBase64ToPlain(dec);
        }
    }

    private byte[] encrypt(byte ba[])  {
        if (key == null) {
            return ba;
        } else {
            try {
                Cipher c = Cipher.getInstance(key.getAlgorithm() + "/CBC/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, key, spec);
                return c.doFinal(ba);
            } catch (GeneralSecurityException gse) {
                throw new Error(gse.getMessage(), gse);
            }
        }
    }

    private byte[] decrypt(byte ba[]) {
        if (key == null) {
            return ba;
        } else {
            try {
                Cipher c = Cipher.getInstance(key.getAlgorithm() + "/CBC/PKCS5Padding");
                c.init(Cipher.DECRYPT_MODE, key, spec);
                return c.doFinal(ba);
            } catch (GeneralSecurityException gse) {
                throw new Error(gse.getMessage(), gse);
            }
        }
    }

    private String encryptPlainToBase64(String plain)  {
        return encodeBase64(encrypt(plain.getBytes()));
    }

    private String decryptBase64ToPlain(String cryptText) {
        return new String(decrypt(decodeBase64(cryptText)));
    }

    private static byte[] decodeBase64(String text)  {
        if (text == null) {
            return null;
        } else {
            BASE64Decoder decoder = new BASE64Decoder();
            try {
                return decoder.decodeBuffer(text);
            } catch (IOException e) {
                throw new Error(e.getMessage(), e);
            }
        }
    }

    private static String encodeBase64(byte bytes[]) {
        if (bytes == null) {
            return null;
        } else {
            BASE64Encoder encoder = new BASE64Encoder();
            return encoder.encode(bytes);
        }
    }

    private static SecretKey generateKey(String algo) {
        try {
            KeyGenerator instance = KeyGenerator.getInstance(algo);
            instance.init(KEYSIZE_DEFAULT);
            return instance.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e.getMessage(), e);
        }
    }
    
    private static String keyToString(SecretKey key) {
        return encodeBase64(key.getEncoded());
    }
    
    private static SecretKey stringToKey(String skey, String algo) {
        byte[] bkey = decodeBase64(skey);
        return new SecretKeySpec(bkey, 0, bkey.length, algo);
    }

}
