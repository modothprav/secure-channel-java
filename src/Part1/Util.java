package Part1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

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

    public static byte[] encrypt(byte[] data, PublicKey publicKey, String cipherString) throws 
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(cipherString);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey, String cipherString) throws
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, 
    NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(cipherString);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static byte[] sign(byte[] ciphertext, PrivateKey privateKey, String algorithm) throws 
    NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initSign(privateKey);
        sig.update(ciphertext);
        return sig.sign();
    }

    public static boolean verify(byte[] ciphertext, byte[] signature, PublicKey publicKey, String algorithm) throws
    NoSuchAlgorithmException, InvalidKeyException, SignatureException, SecurityException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(publicKey);
        sig.update(ciphertext);
        return sig.verify(signature);
    }


    public static byte[] mergeArrays(byte[] ciphertext, byte[] signature) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(ciphertext);
        out.write(signature);
        return out.toByteArray();
    }

    public static KeyPair generateKeys(String algorithm) throws NoSuchAlgorithmException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        kpg.initialize(2048);
        return kpg.genKeyPair();
    }

    public static PublicKey genPublicKey(byte[] publicKey, String algorithm) throws InvalidKeySpecException, NoSuchAlgorithmException {
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static void outputPublicKey(PublicKey publicKey, String owner) {
        System.out.println("\n<-------------------------------------->");
        System.out.println(owner + " Public Key: " +Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("<-------------------------------------->\n");
    }

    public static PublicKey getPublicKey(String algorithm) throws InvalidKeyException {
        System.out.println("<-------------------------------------->");
        System.out.println("Enter Destination Public Key: ");
        Scanner sc = new Scanner(System.in);
        String key = sc.next();
        sc.close();
        PublicKey publicKey = null;
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(key.getBytes());
            publicKey = genPublicKey(publicKeyBytes, algorithm);
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid Public Key specified");
        }
        System.out.println("<-------------------------------------->\n");
        return publicKey;
    }
}
