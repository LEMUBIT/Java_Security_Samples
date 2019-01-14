package symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author Lemuel Ogbunude
 */
public class SymmetricEncryptionUtil {
    private static final String AES = "AES";
    /*CBC -we are using block cipher*/
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    public static SecretKey createAESKey() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }

    /**
     * Needed for the block cipher
     * <p>
     * Getting random set of bytes
     */
    public static byte[] createInitializationVector() {
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    public static byte[] performAESEncryption(String plainText, SecretKey secretKey, byte[] initializationVector) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        //IvParameterSpec: Wrapper you use for your initialization vector
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String performAESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }


}
