package Part1;

import java.io.*;
import java.net.*;
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

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private final String CIPHER = "RSA/ECB/PKCS1Padding";
    private final String HASH_ALGORITHM = "SHA256withRSA";
    private final String ALGORITHM = "RSA";

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg, PublicKey destinationKey, PrivateKey sourceKey) {
        try {
            System.out.println("Client sending cleartext "+msg);
            byte[] data = msg.getBytes("UTF-8");
            
            // encrypt data
        

            System.out.println("Client sending ciphertext "+Util.bytesToHex(data));
            out.write(data);
            out.flush();
            in.read(data);
            
            // decrypt data


            String reply = new String(data, "UTF-8");
            System.out.println("Server returned cleartext "+reply);
            return reply;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
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

    public static void main(String[] args) throws Exception {
        EchoClient client = new EchoClient();

        // Generate Client Keypair and print public key
        KeyPair keyPair = client.generateKeys();
        byte[] clientPublicKey = keyPair.getPublic().getEncoded();
        System.out.println("\n<-------------------------------------->");
        System.out.println("Client Public Key: " +Base64.getEncoder().encodeToString(clientPublicKey));
        System.out.println("<-------------------------------------->\n");

        // Get Server Public Key
        System.out.println("<-------------------------------------->");
        System.out.println("Enter Destination Public Key: ");
        Scanner sc = new Scanner(System.in);
        String key = sc.next();
        sc.close();
        PublicKey serverPublicKey = null;
        try {
            byte[] publicKey = Base64.getDecoder().decode(key.getBytes());
            serverPublicKey = client.getPublicKey(publicKey);
        } catch (Exception e) {
            throw new Exception("Invalid Public Key specified");
        }

        System.out.println("<-------------------------------------->\n");

        client.startConnection("127.0.0.1", 4444);

        client.sendMessage("12345678", serverPublicKey, keyPair.getPrivate());
        client.sendMessage("ABCDEFGH", serverPublicKey, keyPair.getPrivate());
        client.sendMessage("87654321", serverPublicKey, keyPair.getPrivate());
        client.sendMessage("HGFEDCBA", serverPublicKey, keyPair.getPrivate());
        client.stopConnection();
    }
}
