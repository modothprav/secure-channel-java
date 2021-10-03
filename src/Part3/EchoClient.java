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
     * Sends a message to the server. If a null state is passed in will perform 
     * key negotiation again with a new session key and return a new state before 
     * sending the message to the server. Can only send messages between 1 and 32
     * characters long. After response is recieved back from the client checks if 
     * the max message count has been reached if so will return back a null State.
     * Other wise will return the update State.
     * @param msg The message to be sent to server
     * @param destinationKey Server public key
     * @param sourceKey Client private key
     * @param state The State of the session
     * @return The updated or a null state
     */
    public State sendMessage(String msg, PublicKey destinationKey, PrivateKey sourceKey, State state) {
        try {
            // Perform Key negotiation if State has been reset
            if (state == null) { 
                state = this.negotiateKeys(in, out, sourceKey, destinationKey, Util.genMasterKey("AES").getEncoded());

                // Test replay attack
                // state = this.negotiateKeys(in, out, sourceKey, destinationKey, this.sessionKey);
            }

            if (msg.length() > 32 || msg.length() < 1) { 
                System.out.println("Invalid input: Messages needs to be between 1 and 32 characters");
                System.exit(0);
            }

            // Construct encrypted message and send over channel
            byte[] encrypted = Util.sendMessage(state, msg);
            out.write(encrypted);
            out.flush();

            // Read cipher text from channel
            byte[] receivedMessage = new byte[512];
            int size = in.read(receivedMessage);

            // Decrypt received ciphertext
            byte[] ciphertext = Arrays.copyOfRange(receivedMessage, 0, size);
            byte [] decrypted = Util.receiveMessage(state, ciphertext);

            this.outputComms(encrypted, decrypted);

            // Reset session if max messages reached
            if (state.getMaxMsgCount() <= state.getSentCount()) { return null; }

            return state;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    /**
     * Perform Key negotation with the server by send a master key and confirming if the received
     * message matches the originally sent master key. Perform RSA encryption, decryption with 
     * siging and verification of master keys received.Splits the received message into its 
     * individual components (ciphertext, signature and max msg) to get it ready for verification 
     * and decryption. Once verified and decrypted initialises a State for the client with the 
     * specified max message number and returns it. 
     * @param in The DataInputStream where the confirmation is received back from server
     * @param out The DataOutputStream where the message is sent to the server
     * @param privateKey The private key of the client or source key
     * @param publicKey The public key of the server or the destination key
     * @param masterKey The session key which will be encrypted and sent to server
     * @return An initialized State
     * @throws IOException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws SignatureException
     * @throws SecurityException
     */
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

        // Read Response message and extract ciphertext, signature and maxMessage number
        byte[] resData = new byte[513]; in.read(resData);
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
     * Outputs the messages sent and received during the key negotiation process
     * @param sentMessage The message sent to server
     * @param receivedMessage The message received from the server
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

    /**
     * Outputs the messages sent and recieved by the server on the console
     * @param ciphertext The ciphertext message sent to server
     * @param plaintext The plaintext message received from the server
     */
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

        // Get Server Public Key and client private key
        PublicKey publicKey = Util.getPublicKeyFromStore("server", storePass);
        PrivateKey privateKey = keyPair.getPrivate();

        // Clear store password
        Arrays.fill(storePass, '\0'); storePass = null;

        try {
            client.startConnection("127.0.0.1", 4444);
            // Init state and channel
            //client.sessionKey = Util.genMasterKey("AES").getEncoded();
            State state = client.negotiateKeys(client.in, client.out, privateKey, publicKey, Util.genMasterKey("AES").getEncoded());
            
            state = client.sendMessage("FRIST Message", publicKey, privateKey, state);
            state = client.sendMessage("SECOND Message", publicKey, privateKey, state);
            state = client.sendMessage("THIRD Message", publicKey, privateKey, state);
            state = client.sendMessage("FOURTH Message", publicKey, privateKey, state);
            state = client.sendMessage("FIFTH Message", publicKey, privateKey, state);
            state = client.sendMessage("SIXTH Message", publicKey, privateKey, state);
            
            client.stopConnection();
        } catch (NullPointerException e) {
            throw new IOException("Connection ERROR - Check if Server running and the connection to Server");
        }
        
    }
}
