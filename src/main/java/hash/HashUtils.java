package hash;

import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * @author Lemuel Ogbunude
 */
public class HashUtils {
    private static final String SHA2_ALGORITHM = "SHA-256";


    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] createSHA2Hash(String input, byte[] salt) throws Exception {
        /*trick to copy two sets of byte to one*/
        /*how salt value gets added to input in order to do hashing*/
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(salt);
        byteArrayOutputStream.write(input.getBytes());
        byte[] valueToHash = byteArrayOutputStream.toByteArray();

        MessageDigest messageDigest = MessageDigest.getInstance(SHA2_ALGORITHM);
        return messageDigest.digest(valueToHash);
    }

    /**
     * Using BCrypt to hash a password
     * BCrypt is a password hashing function
     */
    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());

    }

    /**
     * Checks if password is verified
     * For example you get a user record from database and get
     * the password string that is hashed, you would then need
     * to compare the hashed password against the hash of the password
     * just typed.
     */

    public static boolean verifyPassword(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }
}
