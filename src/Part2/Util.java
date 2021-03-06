package Part2;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
     * Merges two byte arrays into one, by appending the second array
     * to the first one. Used to merge the ciphertext and singature 
     * to generate the message which will be sent over the connection.
     * @param ciphertext The first byte array
     * @param signature The second byte array
     * @return The combined byte array of the given two arguments
     * @throws IOException
     */
    public static byte[] mergeArrays(byte[] ciphertext, byte[] signature) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(ciphertext);
        out.write(signature);
        return out.toByteArray();
    }
  
}

