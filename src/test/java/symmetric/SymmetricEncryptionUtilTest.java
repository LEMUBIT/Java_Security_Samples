package symmetric;

import org.junit.Test;

import javax.crypto.SecretKey;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SymmetricEncryptionUtilTest {
    @Test
    public void createAESKey() throws Exception {
        SecretKey key = SymmetricEncryptionUtil.createAESKey();
        assertNotNull(key);
        System.out.println(Arrays.toString(key.getEncoded()));
    }

    @Test
    public void testAESCryptoRoutine() throws Exception {
        SecretKey key = SymmetricEncryptionUtil.createAESKey();
        byte[] initializationVector = SymmetricEncryptionUtil.createInitializationVector();
        String plainText = "Text to hide";
        byte[] cipherText = SymmetricEncryptionUtil.performAESEncryption(plainText, key, initializationVector);
        assertNotNull(cipherText);
        System.out.println(cipherText.toString());

        String decryptedText = SymmetricEncryptionUtil.performAESDecryption(cipherText, key, initializationVector);
        assertEquals(plainText, decryptedText);
    }
}