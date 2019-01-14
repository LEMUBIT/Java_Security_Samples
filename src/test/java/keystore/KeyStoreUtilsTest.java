package keystore;

import org.junit.Test;
import symmetric.SymmetricEncryptionUtil;

import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class KeyStoreUtilsTest {

    @Test
    public void createPrivateKeyJavaKeyStore() throws Exception {
        SecretKey secretKey = SymmetricEncryptionUtil.createAESKey();
        String secretKeyHex = Arrays.toString(secretKey.getEncoded());
        KeyStore keyStore = KeyStoreUtils.createPrivateKeyJavaKeyStore("password", "foo", secretKey, "keyPassword");
        assertNotNull(keyStore);

        keyStore.load(null, "password".toCharArray());
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection("keyPassword".toCharArray());
        KeyStore.SecretKeyEntry resultEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("foo", entryPassword);
        SecretKey result = resultEntry.getSecretKey();
        String resultKeyHex = Arrays.toString(result.getEncoded());
        assertEquals(secretKeyHex, resultKeyHex);
    }
}