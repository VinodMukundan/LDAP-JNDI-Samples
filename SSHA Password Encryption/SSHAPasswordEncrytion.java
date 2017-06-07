
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;


public class SSHAPasswordEncrytion {

    /**Converts the provided password to salted SHA. 
     * @param password
     * @return
     * @throws Exception
     */
    private String hashPassword(String password) throws Exception {
        // You can use the length of your own preference, as sample am using it as 4.
        byte[] salt = getSalt(4);
        if (password == null || password.trim().isEmpty()) {
            throw new RuntimeException("Password can not be null or empty.");
        }
        // Initialize message digest with password and salt.
        MessageDigest messageDigest = MessageDigest.getInstance("SHA");
        messageDigest.update(password.getBytes());
        messageDigest.update(salt);
        byte[] hash = messageDigest.digest();

        // Concat hash and salt into one byte array.
        byte[] hashAndSalt = new byte[hash.length + salt.length];
        System.arraycopy(hash, 0, hashAndSalt, 0, hash.length);
        System.arraycopy(salt, 0, hashAndSalt, hash.length, salt.length);

        return "{SSHA}".concat(Base64.encodeBase64String(hashAndSalt));
    }

    /**
     * Generates a random salt.
     * @param length , required length of the salt.
     * @return byte[]
     */
    private byte[] getSalt(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[length];
        secureRandom.nextBytes(salt);
        // Can return the salt byte[], as a precaution just encoding it again.
        return Base64.encodeBase64(salt);
    }
}
