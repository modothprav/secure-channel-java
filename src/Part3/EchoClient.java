package Part3;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
    public State sendMessage(byte[] data, PublicKey destinationKey, PrivateKey sourceKey, State state) {
        try {

            if (state == null) {
                return this.negotiateKeys(in, out, sourceKey, destinationKey, data);
            }

            if (data.length > 32) { throw new IllegalArgumentException("Invalid input: Messages needs to be between 1 and 32 characters");}

            byte[] message = Util.sendMessage(state, new String(data, "UTF-8"), "");
            System.out.println("\nSending plaintext: " + new String(data, "UTF-8"));
            System.out.println("Sending cipher Text: " + Base64.getEncoder().encodeToString(message));
            
            out.write(message);
            out.flush();

            byte[] receivedMessage = new byte[512];
            int size = in.read(receivedMessage);
            byte[] ciphertext = Arrays.copyOfRange(receivedMessage, 0, size);

            System.out.println("\nReceived Ciphertext: " + Base64.getEncoder().encodeToString(ciphertext));

            byte [] decrypted = Util.receiveMessage(state, ciphertext, "");
                
            System.out.println("Received Server message: " + new String(decrypted, "UTF-8"));

            return state;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    private State negotiateKeys(DataInputStream in, DataOutputStream out, PrivateKey privateKey, PublicKey publicKey, byte[] data) throws 
    IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, 
    SignatureException, SecurityException {
        // encrypt and sign encrypted data
        byte[] encrypted = Util.encrypt(data, publicKey, CIPHER);
        byte [] signatureBytes = Util.sign(encrypted, privateKey, HASH_ALGORITHM);

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
        if (!Util.verify(ciphertext, signature, publicKey, HASH_ALGORITHM)) {
            throw new SecurityException("Authentication FAILED - Signature does not match");
        }
        byte[] decrypted = Util.decrypt(ciphertext, privateKey, CIPHER);
        
        // TO DO: Verify if the received message is also the master key
        if (!Arrays.equals(decrypted, data)) { 
            throw new IOException("SESSION KEYS DO NOT MATCH, please try again");
        }

        this.outputToConsole(reqData, Base64.getEncoder().encodeToString(data));

        SecretKey masterKey = new SecretKeySpec(data, "AES");
        return Util.initChannel(masterKey, "client");

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
        System.out.println("Client sending ciphertext: " + Base64.getEncoder().encodeToString(message));
        System.out.println("\n<-------------------------------------->");
        System.out.println("Key received");
        System.out.println("Authentication Successful");
        System.out.println("Server CONFIRMED Master Key: " + plaintext);
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
            State state = null;
            state = client.sendMessage(masterKey.getEncoded(), serverPublicKey, keyPair.getPrivate(), state);
            state = client.sendMessage("Hello World".getBytes(), serverPublicKey, keyPair.getPrivate(), state);
            state = client.sendMessage("HELLO WORLD".getBytes(), serverPublicKey, keyPair.getPrivate(), state);

            state = client.sendMessage("HELLO THEREdsjfdsfjdsfdsfsdfdsfdsfdsfdsfdsfdsfdsfdsfds".getBytes(), serverPublicKey, keyPair.getPrivate(), state);

            state = client.sendMessage("HELLO THERE".getBytes(), serverPublicKey, keyPair.getPrivate(), state);
            
            

            //client.sendMessage("ABCDEFGH", serverPublicKey, keyPair.getPrivate());
            //client.sendMessage("87654321", serverPublicKey, keyPair.getPrivate());
            //client.sendMessage("HGFEDCBA", serverPublicKey, keyPair.getPrivate());
            client.stopConnection();
        } catch (NullPointerException e) {
            throw new IOException("Connection ERROR - Check if Server running and the connection to Server");
        }
        
    }
}
