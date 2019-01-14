package asymmetric;

import javax.crypto.Cipher;
import java.security.*;

public class AsymmerticEncryptionUtil {
    private static final String RSA = "RSA";

    public static KeyPair generateRSAKeyPair() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);

        keyPairGenerator.initialize(4096, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Asymmetric encryption works both ways,
     * you can encrypt with either and decrypt with
     * the other value
     */
    public static byte[] performRSAEncryption(String plainText, PrivateKey privateKey) throws Exception {
        //No padding or CBC because it's not a block cipher
        Cipher cipher = Cipher.getInstance(RSA);

        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plainText.getBytes());

    }

    public static String performRSADecryption(byte[] cipherText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }
}
