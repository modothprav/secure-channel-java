package Part1;

import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

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
            //System.out.println("Client sending cleartext "+msg);
            byte[] data = msg.getBytes("UTF-8");
            
            // encrypt data
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, destinationKey);
            cipher.update(data);
            byte[] encrypted = cipher.doFinal();
            
            // Sign the encrypted text for authentication
            Signature sig = Signature.getInstance(HASH_ALGORITHM);
            sig.initSign(sourceKey);
            sig.update(encrypted);
            byte [] signatureBytes = sig.sign();

            // Send Message
            out.write(encrypted);
            out.write(signatureBytes);
            out.flush();

            // Read Response message
            byte[] resData = new byte[256], signature = new byte[256];
            in.read(resData);
            in.read(signature);

            // Authenticate
            sig.initVerify(destinationKey);
            sig.update(resData);
            if (!sig.verify(signature)) {
                throw new SecurityException("Authentication failed Signature does not match");
            }
            
            // decrypt data
            cipher.init(Cipher.DECRYPT_MODE, sourceKey);
            byte[] decrypted = cipher.doFinal(resData);

            String reply = new String(decrypted, "UTF-8");

            this.outputToConsole(encrypted, signature, msg);

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

    private void outputToConsole(byte[] ciphertext, byte[] signature, String plaintext) {
        System.out.println("\n###############################################");
        System.out.println("\n<-------------------------------------->");
        System.out.println("Client sending ciphertext: "+Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("\n<-------------------------------------->");
        System.out.println("Client sending signature: "+Base64.getEncoder().encodeToString(signature));
        System.out.println("\n<-------------------------------------->");
        System.out.println("Response received");
        System.out.println("Authentication Successful");
        System.out.println("Server returned cleartext: "+plaintext);
        System.out.println("\n###############################################");
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

        System.out.println("<-------------------------------------->");

        client.startConnection("127.0.0.1", 4444);

        client.sendMessage("12345678", serverPublicKey, keyPair.getPrivate());
        client.sendMessage("ABCDEFGH", serverPublicKey, keyPair.getPrivate());
        client.sendMessage("87654321", serverPublicKey, keyPair.getPrivate());
        client.sendMessage("HGFEDCBA", serverPublicKey, keyPair.getPrivate());
        client.stopConnection();
    }
}
