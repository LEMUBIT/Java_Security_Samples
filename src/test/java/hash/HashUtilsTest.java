package hash;

import org.junit.Test;

import java.util.Arrays;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class HashUtilsTest {

    @Test
    public void generateRandomSalt() {
        byte[] salt = HashUtils.generateRandomSalt();
        assertNotNull(salt);
        System.out.println(Arrays.toString(salt));
    }

    @Test
    public void createSHA2Hash() throws Exception {
        byte[] salt = HashUtils.generateRandomSalt();
        String valueToHash = UUID.randomUUID().toString();
        byte[] hash = HashUtils.createSHA2Hash(valueToHash, salt);

        assertNotNull(hash);

        /* Just to confirm that if we have the
         same salt and valueToHas we have the same result
        */
        byte[] hash2 = HashUtils.createSHA2Hash(valueToHash, salt);
        assertEquals(Arrays.toString(hash), Arrays.toString(hash2));
    }

    @Test
    public void testPasswordRoutine()
    {
        String secretePhrase="This is my password";
        String passwordHash=HashUtils.hashPassword(secretePhrase);
        System.out.println(passwordHash);
        assertTrue(HashUtils.verifyPassword(secretePhrase,passwordHash));

    }
}