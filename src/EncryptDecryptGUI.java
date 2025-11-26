import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Encrypt/Decrypt File GUI Application
 * Provides a graphical interface for encrypting and decrypting files using AES-256-CBC
 * with password-based key derivation using PBKDF2-SHA256.
 * 
 * Uses modular architecture:
 * - KeyDerivation: Handles PBKDF2 key derivation
 * - FileCrypto: Handles file encryption/decryption operations
 * - EncryptDecryptGUI: Provides the GUI interface
 */
public class EncryptDecryptGUI {
    private static final String PASSWORD_FILE = System.getProperty("user.home") + "/.encryptsrv_passwords_java";

    private JFrame frame;
    private JLabel fileLabel;
    private JTextField passwordEntry;
    private JButton encryptButton;
    private JButton decryptButton;
    private String selectedFileForEncrypt;
    private String selectedFileForDecrypt;

    public EncryptDecryptGUI() {
        initializeGUI();
    }

    /**
     * Initialize the GUI components
     */
    private void initializeGUI() {
        frame = new JFrame("🔐 Encrypt 🔓 Decrypt File");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 250);
        frame.setResizable(false);
        frame.setLocationRelativeTo(null);

        JPanel panel = new JPanel(null);
        panel.setBackground(new Color(240, 240, 240));
        frame.add(panel);

        // Password Label and Entry
        JLabel passwordLabel = new JLabel("Password:");
        passwordLabel.setBounds(10, 10, 380, 20);
        panel.add(passwordLabel);

        passwordEntry = new JTextField();
        passwordEntry.setBounds(10, 35, 380, 30);
        passwordEntry.setFont(new Font("Arial", Font.PLAIN, 14));
        panel.add(passwordEntry);

        // File Label
        fileLabel = new JLabel("No file selected");
        fileLabel.setBounds(10, 75, 380, 20);
        fileLabel.setForeground(new Color(64, 64, 64));
        panel.add(fileLabel);

        // Select File for Encryption Button
        JButton fileDialogEncrypt = new JButton("📂 Select File");
        fileDialogEncrypt.setBounds(50, 110, 140, 40);
        fileDialogEncrypt.addActionListener(e -> chooseFileEncrypt());
        panel.add(fileDialogEncrypt);

        // Encrypt Button
        encryptButton = new JButton("🔑 Encrypt Now");
        encryptButton.setBounds(50, 160, 140, 40);
        encryptButton.setEnabled(false);
        encryptButton.addActionListener(e -> runEncrypt());
        panel.add(encryptButton);

        // Select Encrypted File Button
        JButton fileDialogDecrypt = new JButton("🔐 Select Enc File");
        fileDialogDecrypt.setBounds(210, 110, 140, 40);
        fileDialogDecrypt.addActionListener(e -> chooseFileDecrypt());
        panel.add(fileDialogDecrypt);

        // Decrypt Button
        decryptButton = new JButton("🔓 Decrypt Now");
        decryptButton.setBounds(210, 160, 140, 40);
        decryptButton.setEnabled(false);
        decryptButton.addActionListener(e -> runDecrypt());
        panel.add(decryptButton);

        frame.setVisible(true);
    }

    /**
     * Open file dialog for selecting file to encrypt
     */
    private void chooseFileEncrypt() {
        JFileChooser fileChooser = new JFileChooser(System.getProperty("user.home"));
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.setAcceptAllFileFilterUsed(true);

        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            selectedFileForEncrypt = fileChooser.getSelectedFile().getAbsolutePath();
            fileLabel.setText("Selected: " + fileChooser.getSelectedFile().getName());
            encryptButton.setEnabled(true);
            decryptButton.setEnabled(false);
            selectedFileForDecrypt = null;
        }
    }

    /**
     * Open file dialog for selecting encrypted file to decrypt
     */
    private void chooseFileDecrypt() {
        JFileChooser fileChooser = new JFileChooser(System.getProperty("user.home"));
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Encrypted files (*.enc)", "enc");
        fileChooser.setFileFilter(filter);
        fileChooser.setAcceptAllFileFilterUsed(false);

        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            selectedFileForDecrypt = fileChooser.getSelectedFile().getAbsolutePath();
            fileLabel.setText("Selected: " + fileChooser.getSelectedFile().getName());
            decryptButton.setEnabled(true);
            encryptButton.setEnabled(false);
            selectedFileForEncrypt = null;
        }
    }

    /**
     * Run encryption process
     */
    private void runEncrypt() {
        String password = passwordEntry.getText();
        if (password.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "Please enter the password.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (selectedFileForEncrypt == null) {
            JOptionPane.showMessageDialog(frame, "Please select a file to encrypt.", "No File Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String result = FileCrypto.encryptFile(selectedFileForEncrypt, password);
        if (result.startsWith("Error:")) {
            JOptionPane.showMessageDialog(frame, result, "Encryption Failed", JOptionPane.ERROR_MESSAGE);
        } else {
            String encryptedFilename = new File(result).getName();
            if (!savePasswordHash(encryptedFilename, password)) {
                JOptionPane.showMessageDialog(frame, "Failed to save password hash.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            JOptionPane.showMessageDialog(frame, "Encrypted to:\n" + result, "Success", JOptionPane.INFORMATION_MESSAGE);
            passwordEntry.setText("");
            fileLabel.setText("No file selected");
            encryptButton.setEnabled(false);
            selectedFileForEncrypt = null;
        }
    }

    /**
     * Run decryption process
     */
    private void runDecrypt() {
        String password = passwordEntry.getText();
        if (password.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "Please enter the password.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (selectedFileForDecrypt == null) {
            JOptionPane.showMessageDialog(frame, "Please select a file to decrypt.", "No File Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String encryptedFilename = new File(selectedFileForDecrypt).getName();

        if (!verifyPassword(encryptedFilename, password)) {
            JOptionPane.showMessageDialog(frame, "The password you entered is incorrect for this file.", "Wrong Password", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String result = FileCrypto.decryptFile(selectedFileForDecrypt, password);
        if (result.startsWith("Error:")) {
            JOptionPane.showMessageDialog(frame, result, "Decryption Failed", JOptionPane.ERROR_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(frame, "Decrypted to:\n" + result, "Success", JOptionPane.INFORMATION_MESSAGE);
            passwordEntry.setText("");
            fileLabel.setText("No file selected");
            decryptButton.setEnabled(false);
            selectedFileForDecrypt = null;
        }
    }

    /**
     * Generate MD5 hash of password
     * @param password Plain text password
     * @return MD5 hash of password
     */
    private static String getPasswordHash(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : messageDigest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            System.err.println("Error generating password hash: " + e.getMessage());
            return "";
        }
    }

    /**
     * Save password hash for specific encrypted file in .htpasswd format
     * Format: filename.enc:md5_hash
     * @param encryptedFilename Name of the encrypted file (with .enc extension)
     * @param password Plain text password
     * @return True if successful, False otherwise
     */
    private static boolean savePasswordHash(String encryptedFilename, String password) {
        try {
            String passwordHash = getPasswordHash(password);
            Path passwordPath = Paths.get(PASSWORD_FILE);

            // Read existing entries
            Map<String, String> entries = new HashMap<>();
            if (Files.exists(passwordPath) && Files.size(passwordPath) > 0) {
                List<String> lines = Files.readAllLines(passwordPath);
                for (String line : lines) {
                    if (line.contains(":")) {
                        String[] parts = line.split(":", 2);
                        entries.put(parts[0], parts[1]);
                    }
                }
            }

            // Update or add new entry
            entries.put(encryptedFilename, passwordHash);

            // Write back to file
            StringBuilder content = new StringBuilder();
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                content.append(entry.getKey()).append(":").append(entry.getValue()).append("\n");
            }
            Files.write(passwordPath, content.toString().getBytes(), StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);

            return true;
        } catch (Exception e) {
            System.err.println("Error saving password: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verify if entered password matches stored MD5 hash for specific file
     * @param encryptedFilename Name of the encrypted file (with .enc extension)
     * @param password Plain text password to verify
     * @return True if password is correct, False otherwise
     */
    private static boolean verifyPassword(String encryptedFilename, String password) {
        try {
            Path passwordPath = Paths.get(PASSWORD_FILE);
            if (!Files.exists(passwordPath)) {
                return false;
            }

            List<String> lines = Files.readAllLines(passwordPath);
            for (String line : lines) {
                if (line.contains(":")) {
                    String[] parts = line.split(":", 2);
                    if (parts[0].equals(encryptedFilename)) {
                        String enteredHash = getPasswordHash(password);
                        return enteredHash.equals(parts[1]);
                    }
                }
            }
            return false;
        } catch (Exception e) {
            System.err.println("Error verifying password: " + e.getMessage());
            return false;
        }
    }

    /**
     * Main method - entry point for the application
     */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(EncryptDecryptGUI::new);
    }
}
