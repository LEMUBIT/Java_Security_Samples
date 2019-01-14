package asymmetric;

import org.junit.Test;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AsymmerticEncryptionUtilTest {

    @Test
    public void generateRSAKeyPair() throws Exception {
        KeyPair keyPair = AsymmerticEncryptionUtil.generateRSAKeyPair();
        assertNotNull(keyPair);
        System.out.println("Private key: " + Arrays.toString(keyPair.getPrivate().getEncoded()));
        System.out.println("Public key: " + Arrays.toString(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void testRSACryptoRoutine() throws Exception {
        KeyPair keyPair = AsymmerticEncryptionUtil.generateRSAKeyPair();
        String plainText = "Text to hide";
        byte[] cipherText = AsymmerticEncryptionUtil.performRSAEncryption(plainText, keyPair.getPrivate());

        assertNotNull(cipherText);
        System.out.println(Arrays.toString(cipherText));

        String decryptedText = AsymmerticEncryptionUtil.performRSADecryption(cipherText, keyPair.getPublic());
        assertEquals(plainText, decryptedText);
    }
}