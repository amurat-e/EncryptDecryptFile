import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Key Derivation Module for Encryption/Decryption
 * 
 * This class provides key derivation functionality using PBKDF2-HMAC-SHA256
 * for AES encryption operations.
 */
public class KeyDerivation {
    // Class constants
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final int KEY_LENGTH = 256;  // 256 bits for AES-256
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * Derive AES key from password and salt using PBKDF2-HMAC-SHA256.
     * 
     * Static method for deriving keys. Can be used without instantiation.
     * 
     * @param password Password for key derivation
     * @param salt 16-byte salt value
     * @return 32-byte derived key (256 bits) or null if an error occurs
     */
    public static byte[] deriveKey(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                PBKDF2_ITERATIONS,
                KEY_LENGTH
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
            byte[] key = factory.generateSecret(spec).getEncoded();
            return key;
        } catch (Exception e) {
            System.err.println("Error deriving key: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get PBKDF2 iterations count
     * @return Number of iterations
     */
    public static int getIterations() {
        return PBKDF2_ITERATIONS;
    }

    /**
     * Get key length in bits
     * @return Key length
     */
    public static int getKeyLength() {
        return KEY_LENGTH;
    }
}
