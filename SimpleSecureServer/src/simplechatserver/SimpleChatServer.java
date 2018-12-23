package simplechatserver;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author skiser
 */
public class SimpleChatServer {

    public void run() throws BadPaddingException, NoSuchPaddingException, UnrecoverableEntryException, InvalidKeyException {

        System.out.println("Simple Chat Server started");

        try {

            // Single ServerSocketChannel is created and bound to port 8000
            ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.bind(new InetSocketAddress(8000));

            // Start the server's life cycle
            while (true) {
                System.out.println("Waiting for a client request ...");

                // accept() is a blocking call waiting for a client to connect
                SocketChannel socketChannel = serverSocketChannel.accept();

                System.out.println("Connected to client.");

                // Enter into the client/server conversation
                Scanner scanner = new Scanner(System.in);
                while (true) {

                    // Prompts the user for a message to send
                    System.out.print("> ");
                    String message = scanner.nextLine();
                    String encrypted = encrypt(message, getSecretKey());

                    // Checks for the terminating message
                    if (message.equalsIgnoreCase("ciao")) {
                        sendMessage(socketChannel, "Server terminating ...");
                        break;
                    } else {
                        // If the message is not the terminating message - sent it to the server
                        sendMessage(socketChannel, encrypted);

                        // Waits for a response from the server and display the response
                        System.out.println("Waiting for message from client ...");
                        String received = receiveMessage(socketChannel);
                        String decrypt = decrypt(received, getSecretKey());
                        System.out.println("Message encrypted: " + received);
                        System.out.println("Message decrypted: " + decrypt);
                    }
                }
                break;
            }
        } catch (IOException ex) {
            System.err.println(ex);
        }
    }

    /**
     * Writes a variable length message to to the underlying channel
     *
     * @param socketChannel: A selectable channel for stream-oriented connecting
     * sockets
     * @param message: Message to be sent to this channel
     */
    public void sendMessage(SocketChannel socketChannel, String message) {
        try {
            // Allocate enough space to handle message argument
            ByteBuffer buffer = ByteBuffer.allocate(message.length() + 1);
            buffer.put(message.getBytes());
            buffer.put((byte) 0x00);
            buffer.flip();

            // Writes a sequence of bytes to this channel from the given buffer
            while (buffer.hasRemaining()) {
                socketChannel.write(buffer);
            }

            System.out.println("Sent: " + message);
        } catch (IOException ex) {
            System.err.println(ex);
        }
    }

    /**
     * Receives a variable length message from the channel
     *
     * @param socketChannel: A selectable channel for stream-oriented connecting
     * sockets
     * @return Message containing the sequence of bytes from this channel
     */
    public String receiveMessage(SocketChannel socketChannel) {
        try {
            // Allocate 8 bytes buffer
            ByteBuffer byteBuffer = ByteBuffer.allocate(8);
            String message = "";

            // Reads the sequence of bytes from this channel into the given buffer
            // read returns the number of bytes read, or -1 if the channel has
            // reached end-of-stream
            while (socketChannel.read(byteBuffer) > 0) {
                char byteRead = 0x00;
                byteBuffer.flip();
                while (byteBuffer.hasRemaining()) {
                    byteRead = (char) byteBuffer.get();
                    // 0x00 is the terminating character
                    if (byteRead == 0x00) {
                        break;
                    }
                    message += byteRead;
                }
                if (byteRead == 0x00) {
                    break;
                }
                byteBuffer.clear();
            }
            return message;
        } catch (IOException ex) {
            System.err.println(ex);
        }
        return "";
    }
    
    public static String encrypt(String plainText, SecretKey secretKey) throws BadPaddingException, NoSuchPaddingException {
        try {
            // Cipher object that implements Advanced Encryption Standard
            Cipher cipher = Cipher.getInstance("AES");

            // Sequence of bytes from the plain text
            byte[] plainTextBytes = plainText.getBytes();

            // Initializes the cipher to encrypt with the provided key
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Encryption - using a base 64 encoder
            byte[] encryptedBytes = cipher.doFinal(plainTextBytes);
            Base64.Encoder encoder = Base64.getEncoder();
            String encryptedText = encoder.encodeToString(encryptedBytes);
            return encryptedText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException ex) {
        }
        return null;
    }

    public static String decrypt(String encryptedText, SecretKey secretKey) throws InvalidKeyException {
        try {
            // Cipher object that implements Advanced Encryption Standard
            Cipher cipher = Cipher.getInstance("AES");

            // We are using a Base64 decoder
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] encryptedBytes = decoder.decode(encryptedText);

            // Initializes the cipher to decrypt with the provided key
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Decrypt
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decryptedText = new String(decryptedBytes);
            return decryptedText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static SecretKey getSecretKey() throws UnrecoverableEntryException {
        SecretKey secretKey = null;
        try {
            // symmetric key
            File file = new File("symmetrickey.jks");

            // JCEKS stands for Java Cryptography Extension KeyStore
            final KeyStore keyStore = KeyStore.getInstance("JCEKS");

            // Loads this KeyStore from the given input stream.
            // a password is given to unlock the keystore
            keyStore.load(new FileInputStream(file),
                    "keystorepassword".toCharArray());

            // Creates a password parameter
            KeyStore.PasswordProtection keyPassword
                    = new KeyStore.PasswordProtection("password".toCharArray());

            // Gets a keystore Entry for the specified alias with the specified protection parameter
            KeyStore.Entry entry = keyStore.getEntry("alias", keyPassword);

            // Gets the SecretKey from this entry.
            secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        } catch (KeyStoreException | IOException
                | NoSuchAlgorithmException | CertificateException ex) {
            ex.printStackTrace();
        } catch (UnrecoverableEntryException ex) {
            ex.printStackTrace();;
        }
        return secretKey;
    }

}
    