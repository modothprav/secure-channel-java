package Part1;

import java.net.*;
import java.io.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private final String CIPHER = "RSA/ECB/PKCS1Padding";
    private final String HASH_ALGORITHM = "SHA256withRSA";
    private final String ALGORITHM = "RSA";

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            byte[] data = new byte[8];
            int numBytes;
            while ((numBytes = in.read(data)) != -1) {
                // decrypt data
                String msg = new String(data, "UTF-8");
                System.out.println("Server received cleartext "+msg);
                // encrypt response (this is just the decrypted data re-encrypted)
                System.out.println("Server sending ciphertext "+Util.bytesToHex(data));
                out.write(data);
                out.flush();
            }
            stop();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    private KeyPair generateKeys() throws NoSuchAlgorithmException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        kpg.initialize(2048);
        return kpg.genKeyPair();
    }

    private PublicKey getPublicKey(byte[] publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void main(String[] args) throws Exception{
        EchoServer server = new EchoServer();

        // Generate Client Keypair and print public key
        KeyPair keyPair = server.generateKeys();
        byte[] serverPublicKey = keyPair.getPublic().getEncoded();
        System.out.println("\n<-------------------------------------->");
        System.out.println("Server Public Key: " +Base64.getEncoder().encodeToString(serverPublicKey));
        System.out.println("<-------------------------------------->\n");

        // Get Server Public Key
        System.out.println("<-------------------------------------->");
        System.out.println("Enter Destination Public Key: ");
        Scanner sc = new Scanner(System.in);
        String key = sc.next();
        sc.close();
        PublicKey clientPublicKey = null;
        try {
            byte[] publicKey = Base64.getDecoder().decode(key.getBytes());
            clientPublicKey = server.getPublicKey(publicKey);
        } catch (Exception e) {
            throw new Exception("Invalid Public Key specified");
        }
        System.out.println("<-------------------------------------->\n");

        server.start(4444);
    }

}



