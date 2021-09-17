package Part1;

import java.net.*;
import java.io.*;
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
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws SignatureException
     */
    public void start(int port, PublicKey destinationKey, PrivateKey sourceKey) throws
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException, SignatureException {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            byte[] data = new byte[512];
            int numBytes;
            while ((numBytes = in.read(data)) != -1) {

                // Split content into signature and ciphertext
                int dataSize = data.length;
                byte [] ciphertext = Arrays.copyOfRange(data, 0, (dataSize + 1) / 2);
                byte [] signatureBytes = Arrays.copyOfRange(data, (dataSize + 1) / 2, dataSize);

                // Authenticate then if passed decrypt data
                if (!Util.verify(ciphertext, signatureBytes, destinationKey, HASH_ALGORITHM)) {
                    throw new SecurityException("Authentication FAILED - Signature does not match");
                }
                byte[] decrypted = Util.decrypt(ciphertext, sourceKey, CIPHER);
                String msg = new String(decrypted, "UTF-8");

                // Ecnrypt message and sign the ciphertext
                byte[] encrypted = Util.encrypt(msg.getBytes(), destinationKey, CIPHER);
                byte[] signature = Util.sign(encrypted, sourceKey, HASH_ALGORITHM);

                // Create response message and send back to client
                byte[] resData = Util.mergeArrays(encrypted, signature);
                out.write(resData);
                out.flush();

                this.outputToConsole(resData, msg);
            }
            stop();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    /**
     * Outputs the request received from the client and the response sent by the 
     * server on the console. Also informs that authentication was successful.
     * Sent messages are displayed as ciphertext whilereceived messages are 
     * displayed as plaintext.
     * @param message The message that is being sent to the client (ciphertext)
     * @param plaintext The decrypted message received by the client
     */
    private void outputToConsole(byte[] message, String plaintext) {
        System.out.println("\n###############################################");
        System.out.println("\n<-------------------------------------->");
        System.out.println("Request received");
        System.out.println("Authentication Successful");
        System.out.println("Server received cleartext: "+plaintext);
        System.out.println("\n<-------------------------------------->");
        System.out.println("Server sending ciphertext: "+Base64.getEncoder().encodeToString(message));
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
        EchoServer server = new EchoServer();

        // Generate Client Keypair and print public key
        KeyPair keyPair = Util.generateKeys(server.ALGORITHM);
        Util.outputPublicKey(keyPair.getPublic(), "Server");

        // Prompts the user to enter a public key
        PublicKey clientPublicKey = Util.getPublicKey(server.ALGORITHM);

        server.start(4444, clientPublicKey, keyPair.getPrivate());
    }

}



