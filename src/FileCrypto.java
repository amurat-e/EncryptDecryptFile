import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * File Cryptography Module for Encryption/Decryption
 * 
 * This class provides file encryption and decryption functionality using AES-256-CBC
 * with password-based key derivation.
 */
public class FileCrypto {
    // Class constants
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Encrypt a file using password-based AES-256-CBC encryption.
     * 
     * Reads the file, derives a key from the password using PBKDF2,
     * encrypts the content, and saves the encrypted data with salt and IV prepended.
     * 
     * @param filePath Absolute path of file to encrypt
     * @param password Password for encryption
     * @return Path to encrypted file (.enc) or error message starting with "Error:"
     */
    public static String encryptFile(String filePath, String password) {
        try {
            byte[] plaintext = Files.readAllBytes(Paths.get(filePath));

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALT_LENGTH];
            random.nextBytes(salt);

            byte[] key = KeyDerivation.deriveKey(password, salt);
            if (key == null) {
                return "Error: Key derivation failed";
            }

            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);

            SecretKeySpec keySpec = new SecretKeySpec(key, 0, key.length, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            String encryptedFilePath = filePath + ".enc";
            FileOutputStream fos = new FileOutputStream(encryptedFilePath);
            fos.write(salt);
            fos.write(iv);
            fos.write(ciphertext);
            fos.close();

            return encryptedFilePath;
        } catch (FileNotFoundException e) {
            return "Error: File not found: " + filePath;
        } catch (FileAlreadyExistsException e) {
            return "Error: Encrypted file already exists: " + filePath + ".enc";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Decrypt an encrypted file using password-based AES-256-CBC decryption.
     * 
     * Reads the encrypted file, extracts salt and IV, derives the key from password,
     * decrypts the content, and saves the decrypted file (removing the .enc extension).
     * The original encrypted file is deleted after successful decryption.
     * 
     * @param filePath Absolute path of encrypted file
     * @param password Password for decryption
     * @return Path to decrypted file or error message starting with "Error:"
     */
    public static String decryptFile(String filePath, String password) {
        try {
            byte[] data = Files.readAllBytes(Paths.get(filePath));

            if (data.length < 32) {
                return "Error: Invalid encrypted file: file too small.";
            }

            byte[] salt = Arrays.copyOfRange(data, 0, 16);
            byte[] iv = Arrays.copyOfRange(data, 16, 32);
            byte[] ciphertext = Arrays.copyOfRange(data, 32, data.length);

            byte[] key = KeyDerivation.deriveKey(password, salt);
            if (key == null) {
                return "Error: Key derivation failed";
            }

            SecretKeySpec keySpec = new SecretKeySpec(key, 0, key.length, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] plaintext = cipher.doFinal(ciphertext);

            // Remove .enc extension
            String outPath = filePath.endsWith(".enc") 
                ? filePath.substring(0, filePath.length() - 4) 
                : filePath + ".dec";
            Files.write(Paths.get(outPath), plaintext);

            // Delete encrypted file
            Files.delete(Paths.get(filePath));

            return outPath;
        } catch (FileNotFoundException e) {
            return "Error: File not found: " + filePath;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get salt length in bytes
     * @return Salt length
     */
    public static int getSaltLength() {
        return SALT_LENGTH;
    }

    /**
     * Get IV length in bytes
     * @return IV length
     */
    public static int getIVLength() {
        return IV_LENGTH;
    }
}
