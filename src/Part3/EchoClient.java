package Part3;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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

    // test replay attack
    //private byte[] sessionKey;

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
            // Perform Key negotiation if State has been reset
            if (state == null) { 
                state = this.negotiateKeys(in, out, sourceKey, destinationKey, Util.genMasterKey("AES").getEncoded());

                // Test replay attack
                // state = this.negotiateKeys(in, out, sourceKey, destinationKey, this.sessionKey);
            }

            if (data.length > 32 || data.length < 1) { 
                throw new IllegalArgumentException("Invalid input: Messages needs to be between 1 and 32 characters");
            }

            // Construct encrypted message and send over channel
            byte[] encrypted = Util.sendMessage(state, new String(data, "UTF-8"), "");
            out.write(encrypted);
            out.flush();

            // Read cipher text from channel
            byte[] receivedMessage = new byte[512];
            int size = in.read(receivedMessage);

            // Decrypt received ciphertext
            byte[] ciphertext = Arrays.copyOfRange(receivedMessage, 0, size);
            byte [] decrypted = Util.receiveMessage(state, ciphertext, "");

            this.outputComms(encrypted, decrypted);

            // Reset session if max messages reached
            if (state.getMaxMsgCount() <= state.getSentCount()) { return null; }

            return state;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    private State negotiateKeys(DataInputStream in, DataOutputStream out, PrivateKey privateKey, PublicKey publicKey, byte[] masterKey) throws 
    IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, 
    SignatureException, SecurityException {
        // encrypt and sign encrypted data
        byte[] encrypted = Util.encrypt(masterKey, publicKey, CIPHER);
        byte [] signatureBytes = Util.sign(encrypted, privateKey, HASH_ALGORITHM);

        // Create request data and send to server
        byte[] reqData = Util.mergeArrays(encrypted, signatureBytes);
        out.write(reqData);
        out.flush();

        // Read Response message and extract ciphertext and signature
        byte[] resData = new byte[513]; in.read(resData);
        int dataSize = resData.length;
        byte [] ciphertext = Arrays.copyOfRange(resData, 0, 256);
        byte [] signature = Arrays.copyOfRange(resData, 256, 512);
        int maxMessage = resData[512];

        // Authenticate then decrypt ciphertext
        if (!Util.verify(ciphertext, signature, publicKey, HASH_ALGORITHM)) {
            throw new SecurityException("Authentication FAILED - Signature does not match");
        }
        byte[] decrypted = Util.decrypt(ciphertext, privateKey, CIPHER);
        
        // Verify if the received message is also the master key
        if (!Arrays.equals(decrypted, masterKey)) { 
            throw new IOException("SESSION KEYS DO NOT MATCH, please try again");
        }

        this.outputRequest(reqData, masterKey);

        SecretKey sessionKey = new SecretKeySpec(masterKey, "AES");
        return Util.initChannel(sessionKey, "client", maxMessage);

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
     * 
     * @param message The message being sent to the server (ciphertext)
     * @param plaintext The message received from the server
     */
    private void outputRequest(byte[] sentMessage, byte[] receivedMessage) {
        System.out.println("\n############## KEY NEGOTIATION ################");
        System.out.println("\n<-------------------------------------->");
        System.out.println("Client sending ciphertext: " + Base64.getEncoder().encodeToString(sentMessage));
        System.out.println("\n<-------------------------------------->");
        System.out.println("Key received");
        System.out.println("Authentication Successful");
        System.out.println("Server CONFIRMED Master Key: " + Base64.getEncoder().encodeToString(receivedMessage));
        System.out.println("\n###############################################");
    }

    private void outputComms(byte[] ciphertext, byte[] plaintext) throws UnsupportedEncodingException {
        System.out.println("\n################ ECHO-REQUEST #################");
        System.out.println("\n<-------------------------------------->");
        System.out.println("Client Sending Ciphertext: " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("<-------------------------------------->");
        System.out.println("Message Received");
        System.out.println("Authentication successful");
        System.out.println("Server Returned Plaintext: " + new String(plaintext, "UTF-8"));
        System.out.println("<-------------------------------------->");
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

        try {
            client.startConnection("127.0.0.1", 4444);
            State state = client.negotiateKeys(client.in, client.out, keyPair.getPrivate(), serverPublicKey, Util.genMasterKey("AES").getEncoded());
            //state = client.sendMessage(null, serverPublicKey, keyPair.getPrivate(), state); // Initialize 
            state = client.sendMessage("FIRST Message".getBytes(), serverPublicKey, keyPair.getPrivate(), state);
            state = client.sendMessage("SECOND Message".getBytes(), serverPublicKey, keyPair.getPrivate(), state);
            state = client.sendMessage("THIRD Message".getBytes(), serverPublicKey, keyPair.getPrivate(), state);
            state = client.sendMessage("FOURTH Message".getBytes(), serverPublicKey, keyPair.getPrivate(), state);
            
            

            //client.sendMessage("ABCDEFGH", serverPublicKey, keyPair.getPrivate());
            //client.sendMessage("87654321", serverPublicKey, keyPair.getPrivate());
            //client.sendMessage("HGFEDCBA", serverPublicKey, keyPair.getPrivate());
            client.stopConnection();
        } catch (NullPointerException e) {
            throw new IOException("Connection ERROR - Check if Server running and the connection to Server");
        }
        
    }
}
