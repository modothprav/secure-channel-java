package Part3;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private final String CIPHER = "RSA/ECB/PKCS1Padding";
    private final String HASH_ALGORITHM = "SHA256withRSA";
    private final static String ERROR_MSG = "Valid command: java Part2.EchoClient <Store password> <Key password>";

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     * @throws IOException
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
    public String sendMasterKey(byte[] data, PublicKey destinationKey, PrivateKey sourceKey) {
        try {
            //System.out.println("Client sending cleartext "+msg);
            //byte[] data = msg.getBytes("UTF-8");
            
            // encrypt and sign encrypted data
            byte[] encrypted = Util.encrypt(data, destinationKey, CIPHER);
            byte [] signatureBytes = Util.sign(encrypted, sourceKey, HASH_ALGORITHM);

            // Create request data and send to server
            byte[] reqData = Util.mergeArrays(encrypted, signatureBytes);
            out.write(reqData);
            out.flush();

            // Read Response message and extract ciphertext and signature
            byte[] resData = new byte[512]; in.read(resData);
            int dataSize = resData.length;
            byte [] ciphertext = Arrays.copyOfRange(resData, 0, (dataSize + 1) / 2);
            byte [] signature = Arrays.copyOfRange(resData, (dataSize + 1) / 2, dataSize);

            // Authenticate then decrypt ciphertext
            if (!Util.verify(ciphertext, signature, destinationKey, HASH_ALGORITHM)) {
                throw new SecurityException("Authentication FAILED - Signature does not match");
            }
            byte[] decrypted = Util.decrypt(ciphertext, sourceKey, CIPHER);
            
            // TO DO: Verify if the received message is also the master key
            if (!Arrays.equals(decrypted, data)) { 
                System.out.println("SESSION KEYS DO NOT MATCH, please try again");
                return null;
            }

            String reply = new String(decrypted, "UTF-8");

            this.outputToConsole(reqData, Base64.getEncoder().encodeToString(data));

            SecretKey masterKey = new SecretKeySpec(data, "AES");
            State state = Util.initChannel(masterKey, "client");

            String plaintext = "HELLO THERE WORLD!";
            byte[] message = Util.sendMessage(state, plaintext, "");
            System.out.println("\nSending plaintext: " + plaintext);
            System.out.println("Sending cipher Text: " + Base64.getEncoder().encodeToString(message));
            
            out.write(message);
            out.flush();

            byte[] receivedMessage = new byte[512];
            int size = in.read(receivedMessage);
            ciphertext = Arrays.copyOfRange(receivedMessage, 0, size);

            System.out.println("\nReceived Ciphertext: " + Base64.getEncoder().encodeToString(ciphertext));

            decrypted = Util.receiveMessage(state, ciphertext, "");
                
            System.out.println("Received Server message: " + new String(decrypted, "UTF-8"));

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
        } catch (NullPointerException e) {
            System.out.println("Connection ERROR - Check if Server is listening for connections");
        }
    }

    /**
     * Outputs the request which is sent to the server and the response
     * received back from the server. Also informs that authentication 
     * was successful. Sent messages are displayed as ciphertext while
     * received messages are displayed as plaintext.
     * @param message The message being sent to the server (ciphertext)
     * @param plaintext The message received from the server
     */
    private void outputToConsole(byte[] message, String plaintext) {
        System.out.println("\n###############################################");
        System.out.println("\n<-------------------------------------->");
        System.out.println("Client sending ciphertext: "+Base64.getEncoder().encodeToString(message));
        System.out.println("\n<-------------------------------------->");
        System.out.println("Response received");
        System.out.println("Authentication Successful");
        System.out.println("Server returned cleartext: "+plaintext);
        System.out.println("\n###############################################");
    }

    public static void main(String[] args) throws Exception {

        if (args.length < 2) { throw new IllegalArgumentException("Not enough arguments specified\n" + ERROR_MSG); }

        char[] storePass = args[0].toCharArray();
        char[] keyPass = args[1].toCharArray();
        Arrays.fill(args, null);

        EchoClient client = new EchoClient();

        // Get Client Keypair from Keystore
        KeyPair keyPair = Util.getKeyPairFromStore("client", storePass, keyPass);

        // Clear key password
        Arrays.fill(keyPass, '\0'); keyPass = null;

        // Get Server Public Key
        PublicKey serverPublicKey = Util.getPublicKeyFromStore("server", storePass);

        // Clear store password
        Arrays.fill(storePass, '\0'); storePass = null;

        SecretKey masterKey = Util.genMasterKey("AES");

        try {
            client.startConnection("127.0.0.1", 4444);
            client.sendMasterKey(masterKey.getEncoded(), serverPublicKey, keyPair.getPrivate());

            

            //client.sendMessage("ABCDEFGH", serverPublicKey, keyPair.getPrivate());
            //client.sendMessage("87654321", serverPublicKey, keyPair.getPrivate());
            //client.sendMessage("HGFEDCBA", serverPublicKey, keyPair.getPrivate());
            client.stopConnection();
        } catch (NullPointerException e) {
            throw new IOException("Connection ERROR - Check if Server running and the connection to Server");
        }
        
    }
}
