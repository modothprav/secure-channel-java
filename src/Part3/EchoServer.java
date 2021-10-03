package Part3;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private final String CIPHER = "RSA/ECB/PKCS1Padding";
    private final String HASH_ALGORITHM = "SHA256withRSA";
    private static final String ERROR_MSG = "Valid command: java Part2.EchoServer <store password> <keypassword> <max messages>";
    private ArrayList<byte[]> sessionKeys = new ArrayList<>(); // stores session keys to check for replay attacks
    private static final int MAX_MESSAGES = 5; // Default max messages set to 5

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws SignatureException
     * @throws InvalidAlgorithmParameterException
     */
    public void start(int port, PublicKey destinationKey, PrivateKey sourceKey, int maxMsgs) throws
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException, SignatureException, InvalidAlgorithmParameterException {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            State state = null; // state always starts off as null so it gets initialized first
            byte[] data = new byte[512];
            int numBytes;
            
            while ((numBytes = in.read(data)) != -1) {

                // Perform Key negotiation if State is reset or initialized
                if (state == null) {
                    byte[] key = this.negotiateKeys(in, out, sourceKey, destinationKey, data, maxMsgs);
                    SecretKey masterKey = new SecretKeySpec(key, "AES");
                    state = Util.initChannel(masterKey, "server", maxMsgs);
                    continue;
                }

                // Decrypt Received message
                byte[] ciphertext = Arrays.copyOfRange(data, 0, numBytes);
                byte[] decrypted = Util.receiveMessage(state, ciphertext);

                // Echo back received message after encrypting
                byte[] encrypted = Util.sendMessage(state, new String(decrypted, "UTF-8"));
                out.write(encrypted);
                out.flush();

                this.outputComms(encrypted, decrypted);

                // If max message count is reached then reset state to gen new session key
                if (state.getMaxMsgCount() <= state.getReceiveCount()) { state = null; }

            }
            stop();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    /**
     * Negotiatie a master key with the client. Perform asymmetric encryption when communicating the keys
     * Once the received message has been verified and decrypted, check if the given master key has already
     * been used in a session if so then throw an error. If not then send by the master key with the signature
     * maximum messages per session count.
     * @param in The DataInputStream where messages are received from the client
     * @param out The DataOutputStram where messages are sent to the client
     * @param privateKey The server private key
     * @param publicKey The client public key
     * @param data The data received by the client
     * @param maxMsgs The maximum number of messages per session
     * @return The master key sent by the client
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws SecurityException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws IOException
     */
    private byte[] negotiateKeys(DataInputStream in, DataOutputStream out, PrivateKey privateKey, PublicKey publicKey, byte[] data, int maxMsgs) throws 
    InvalidKeyException, NoSuchAlgorithmException, SignatureException, SecurityException, IllegalBlockSizeException, BadPaddingException, 
    NoSuchPaddingException, IOException {
        // Split content into signature and ciphertext
        int dataSize = data.length;
        byte [] ciphertext = Arrays.copyOfRange(data, 0, (dataSize + 1) / 2);
        byte [] signatureBytes = Arrays.copyOfRange(data, (dataSize + 1) / 2, dataSize);

        // Authenticate then if passed decrypt data
        if (!Util.verify(ciphertext, signatureBytes, publicKey, HASH_ALGORITHM)) {
            throw new SecurityException("Authentication FAILED - Signature does not match");
        }
        byte[] masterKey = Util.decrypt(ciphertext, privateKey, CIPHER);
        
        // If the same session key is used throw an error
        for (int i = 0; i < this.sessionKeys.size(); i++) {
            if (Arrays.equals(this.sessionKeys.get(i), masterKey)) { throw new SecurityException("REPLAY ATTACK DETECTED"); }
        }

        this.sessionKeys.add(masterKey); // add key for future checks

        String msg = Base64.getEncoder().encodeToString(masterKey);

        // Build the components required for the response message
        byte[] encrypted = Util.encrypt(masterKey, publicKey, CIPHER);
        byte[] signature = Util.sign(encrypted, privateKey, HASH_ALGORITHM);
        byte[] maxMessage = new byte[1]; maxMessage[0] = (byte) maxMsgs;

        // Send encrypted Master key with signature back to confirm
        byte[] resData = Util.mergeArrays(encrypted, signature, maxMessage);
        out.write(resData);
        out.flush();

        this.outputRequest(resData, msg);

        return masterKey; 
    } 

    /**
     * Outputs the messages sent and received during the key negotiation process
     * @param message The message received from the client
     * @param plaintext The message sent back to the client
     */
    private void outputRequest(byte[] message, String plaintext) {
        System.out.println("\n############## KEY NEGOTIATION ################");
        System.out.println("\n<-------------------------------------->");
        System.out.println("Negotiation Request received");
        System.out.println("Authentication Successful");
        System.out.println("Server received Master Key: "+plaintext);
        System.out.println("\n<-------------------------------------->");
        System.out.println("Server sending ciphertext: "+Base64.getEncoder().encodeToString(message));
        System.out.println("\n###############################################");
    }

    /**
     * Outputs the messages received and sent during symmetric communication 
     * between client and server
     * @param ciphertext The message being sent
     * @param plaintext The received message
     * @throws UnsupportedEncodingException
     */
    private void outputComms(byte[] ciphertext, byte[] plaintext) throws UnsupportedEncodingException {
        System.out.println("\n############### ECHO-RESPONSE #################");
        System.out.println("\n<-------------------------------------->");
        System.out.println("Message Received");
        System.out.println("Authentication successful");
        System.out.println("Server Received Plaintext: " + new String(plaintext, "UTF-8"));
        System.out.println("<-------------------------------------->");
        System.out.println("Server Sending Ciphertext: " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("<-------------------------------------->");
        System.out.println("\n###############################################");
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
        if (args.length < 2) { throw new IllegalArgumentException("Not enough arguments specified\n" + ERROR_MSG); }

        int maxMessages = MAX_MESSAGES;
        
        if (args.length > 2) { 
            maxMessages = Integer.parseInt(args[2]);
            if (maxMessages == 0) { throw new IllegalArgumentException("Max Messages must be greater than 0"); }
        } 

        char[] storePass = args[0].toCharArray();
        char[] keyPass = args[1].toCharArray();
        Arrays.fill(args, null);
        
        EchoServer server = new EchoServer();

        // Get Server Keypair from keystore
        KeyPair keyPair = Util.getKeyPairFromStore("server", storePass, keyPass);

        // clear key password
        Arrays.fill(keyPass, '\0'); keyPass = null;

        // Get the client public key from the keystore
        PublicKey clientPublicKey = Util.getPublicKeyFromStore("client", storePass);

        // clear store password
        Arrays.fill(storePass, '\0'); storePass = null;

        server.start(4444, clientPublicKey, keyPair.getPrivate(), maxMessages);
    }

}