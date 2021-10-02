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
    private static final String ERROR_MSG = "Valid command: java Part2.EchoServer <store password> <keypassword>";

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
    public void start(int port, PublicKey destinationKey, PrivateKey sourceKey) throws
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException, SignatureException, InvalidAlgorithmParameterException {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            State state = null;
            byte[] data = new byte[512];
            int numBytes;
            while ((numBytes = in.read(data)) != -1) {

                // Perform Key negotiation if State is reset or initialized
                if (state == null) {
                    byte[] key = this.negotiateKeys(in, out, sourceKey, destinationKey, data);

                    SecretKey masterKey = new SecretKeySpec(key, "AES");
                    state = Util.initChannel(masterKey, "server");
                    continue;
                }

                // Decrypt Received message
                byte[] ciphertext = Arrays.copyOfRange(data, 0, numBytes);
                byte[] decrypted = Util.receiveMessage(state, ciphertext, "");

                // Echo back received message after encrypting
                byte[] encrypted = Util.sendMessage(state, new String(decrypted, "UTF-8"), "");
                out.write(encrypted);
                out.flush();

                this.outputComms(encrypted, decrypted);

                if (state.getMaxMsgCount() <= state.getReceiveCount()) { state = null; }
            }
            stop();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    private byte[] negotiateKeys(DataInputStream in, DataOutputStream out, PrivateKey privateKey, PublicKey publicKey, byte[] data) throws 
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

        String msg = Base64.getEncoder().encodeToString(masterKey);

        // Build the components required for the response message
        byte[] encrypted = Util.encrypt(masterKey, publicKey, CIPHER);
        byte[] signature = Util.sign(encrypted, privateKey, HASH_ALGORITHM);

        // Send encrypted Master key with signature back to confirm
        byte[] resData = Util.mergeArrays(encrypted, signature);
        out.write(resData);
        out.flush();

        this.outputRequest(resData, msg);

        return masterKey; 
    } 

    /**
     * 
     * @param message The message that is being sent to the client (ciphertext)
     * @param plaintext The decrypted message received by the client
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

        server.start(4444, clientPublicKey, keyPair.getPrivate());
    }

}