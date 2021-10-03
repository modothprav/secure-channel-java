package Part3;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * Originally by Erik Costlow, extended by Ian Welch
 */
public class Util {

    /**
     * Just for nice printing.
     *
     * @param bytes
     * @return A nicely formatted byte string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /**
     * Convert a string as hex.
     *
     * @param s the string to be decoded as UTF-8
     */
    public static String strToHex(String s) {
        s = "failed decoding";
        try  {
            s = Util.bytesToHex(s.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            System.out.println("Unsupported Encoding Exception");
        }
        return s;
    }

    /**
     * Returns a Keypair object conatinig the public and private keys
     * from the cybr372.jks keystore. Obtains the public key by first
     * obtaining the certificate and retrieveing it from there.
     * @param alias The alias the Keypair is registered under
     * @param password The password for the keystore
     * @return The KeyPair object
     * @throws FileNotFoundException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableEntryException
     */
    public static KeyPair getKeyPairFromStore(String alias, char[] storePass, char[] keyPass) throws 
    FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, 
    CertificateException, UnrecoverableEntryException{
        InputStream ins = new FileInputStream("Part2/cybr372.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, storePass);
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(keyPass);
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        try {
            privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, keyPassword);
        } catch (UnrecoverableKeyException e) {
            throw new UnrecoverableKeyException("Invaild password specified");
        }
        
        Certificate cert = keyStore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Returns the public key of the alias specified from the keystore file
     * @param alias The alias the public key is registered under
     * @param password The keystore password
     * @return The Public Key object
     * @throws FileNotFoundException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static PublicKey getPublicKeyFromStore(String alias, char[] password) throws 
    FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, 
    CertificateException {
        InputStream ins = new FileInputStream("Part2/cybr372.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, password);
        
        Certificate cert = keyStore.getCertificate(alias);
        return cert.getPublicKey();

    }

    public static SecretKey genMasterKey(String alg) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, secureRandom);
        return keyGen.generateKey();
    }

    public static SecretKey genSymmetricKey(String phrase, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        byte[] keyBytes = mac.doFinal(phrase.getBytes());
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static State initChannel(SecretKey masterKey, String role, int maxMsgs) throws InvalidKeyException, NoSuchAlgorithmException {
        if (!role.equals("client") && !role.equals("server")) { throw new IllegalArgumentException("Invalid Role specified, must be 'client' or 'server'"); }
        // Generate Send and receive keys
        SecretKey keySendEnc = genSymmetricKey("Client to Server", masterKey);
        SecretKey keyReceiveEnc = genSymmetricKey("Server to Client", masterKey);

        // Swap send and receive keys if role is server
        if (role.equals("client")) {
            return new State(keySendEnc, keyReceiveEnc, maxMsgs);
        } else {
            return new State(keyReceiveEnc, keySendEnc, maxMsgs);
        }
        
    }

    public static byte[] sendMessage(State state, String message) throws InvalidKeyException, 
    InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, 
    BadPaddingException, IOException {
        // Update and save message sent count
        state.msgSent();
        
        // Out of order test
        //state.msgReceived();

        byte[] sentCount = new byte[1];
        sentCount[0] = (byte) state.getSentCount();

        // Create and fill IV
        SecureRandom secRandom = new SecureRandom();
        byte[] iv = new byte[12]; secRandom.nextBytes(iv);

        // Init Cipher
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); 
        cipher.init(Cipher.ENCRYPT_MODE, state.getSendKey(), parameterSpec);

        cipher.updateAAD(sentCount);
        cipher.updateAAD(iv); 
        byte[] ciphertext = cipher.doFinal(message.getBytes("UTF-8"));

        return mergeArrays(sentCount, iv, ciphertext);
    }

    public static byte[] receiveMessage(State state, byte[] ciphertext) throws 
    NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, 
    IllegalBlockSizeException, BadPaddingException, IOException {

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Get IV from message
        byte[] sentCount = Arrays.copyOfRange(ciphertext, 0, 1);
        byte[] gcmIV = Arrays.copyOfRange(ciphertext, 1, 13);
        byte[] encrypted = Arrays.copyOfRange(ciphertext, 13, ciphertext.length);

        // Out of Order test 
        //state.msgReceived();

        // Check if received message is out of order
        if ((int) sentCount[0] <= state.getReceiveCount()) {
            System.out.println("\nERROR - Message Out Of Order");
            System.exit(0);
        }

        state.setMsgReceived(sentCount[0]); // Update receive count

        AlgorithmParameterSpec iv = new GCMParameterSpec(128, gcmIV);  
        
        cipher.init(Cipher.DECRYPT_MODE, state.getReceiveKey(), iv);

        cipher.updateAAD(sentCount);;
        cipher.updateAAD(gcmIV);
        return cipher.doFinal(encrypted);
    }

    /**
     * Performs asymmetric encryption, by using the given public key to encrypt 
     * the data in conjunction with the given cipher value. If successful will 
     * return a byte array which is the encrypted version of data argument.
     * @param data The data that needs to get encrypted
     * @param publicKey The public key which will be used for encryption
     * @param cipherString The Cipher which will be used for encryption
     * @return The encrypted version of the passed in data argument
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey, String cipherString) throws 
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(cipherString);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * Performs asymmetric decryption, by using the given private key to decrypt
     * the data in conjunciton with the given cipher value. If successful will
     * return a byte array which is the decrypted version of the data argument.
     * @param data The data that will get decrypted
     * @param privateKey The Private key used for decryption
     * @param cipherString The Cipher used for decryption
     * @return The decrypted version of the passed in data argument
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] decrypt(byte[] data, PrivateKey privateKey, String cipherString) throws
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(cipherString);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * If successful will return a byte array which contians the signature 
     * of the given data, that is generated by the supplied private key and 
     * hash algorithm.
     * @param data The data which the signature will be created for
     * @param privateKey The private key ued to sign the data
     * @param algorithm The algorithm used to perform the signing
     * @return The byte array containing the signature hash
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey, String algorithm) throws 
    NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    /**
     * Verifies whether the supplied data produces the given signature.
     * The verification is conducted using the given public key and hash
     * algorithm. 
     * @param data The data that needs to be verified
     * @param signature The signature which the data will verified against
     * @param publicKey The public key used to perform the verification
     * @param algorithm The hash algorithm used to perform the verification
     * @return True if verification was successful False otherwise
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws SecurityException
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey, String algorithm) throws
    NoSuchAlgorithmException, InvalidKeyException, SignatureException, SecurityException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    /**
     * 
     * @param data
     * @return
     * @throws IOException
     */
    public static byte[] mergeArrays(byte[]... data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] array : data) {
            out.write(array);
        }
        return out.toByteArray();
    }
  
}

class State {
    private final SecretKey keySendEnc;
    private final SecretKey keyReceiveEnc;
    private final int maxMessages;
    private int receiveCount;
    private int sentCount;

    public State(SecretKey keySendEnc, SecretKey keyReceiveEnc, int maxMessages) {
        this.keySendEnc = keySendEnc;
        this.keyReceiveEnc = keyReceiveEnc;
        this.receiveCount = 0;
        this.sentCount = 0;
        this.maxMessages = maxMessages;
    }

    /**
     * Incremebt Message received count by 1
     */
    public void msgReceived() {
        this.receiveCount++;
    }

    /**
     * Incremebt Message sent count by 1
     */
    public void msgSent() {
        this.sentCount++;
    }

    // getters and setters

    public SecretKey getSendKey() {
        return this.keySendEnc;
    }

    public SecretKey getReceiveKey() {
        return this.keyReceiveEnc;
    }

    public int getMaxMsgCount() {
        return this.maxMessages;
    }

    public int getReceiveCount() {
        return this.receiveCount;
    }

    public int getSentCount() {
        return this.sentCount;
    }

    public void setMsgReceived(int n) {
        this.receiveCount = n;
    }

    
}
