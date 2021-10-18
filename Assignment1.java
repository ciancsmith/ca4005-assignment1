import java.math.BigInteger;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.Base64;
import java.io.FileOutputStream;


/** Resources
 * https://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha256-in-java
 * 
 */

public class Assignment1 implements Assignment1Interface
{    
    // Init logger
    private final static Logger logger = Logger.getLogger(Assignment1.class.getName());
    /* Method generateKey returns the key as an array of bytes and is generated from the given password and salt. */
    
	public byte[] generateKey(byte[] password, byte[] salt)
    {
        byte [] key = new byte[password.length + salt.length];
        System.arraycopy(password, 0, key, 0, password.length);
        System.arraycopy(salt, 0, key, password.length, salt.length);
        
        //hash the key 200 times
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < 200; i++) 
            {
                key = digest.digest(key);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.info("Invalid hash algorithm");
        }
        return key;
    }
	
    /* Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key */
       
	public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key)
    {
        try 
        {
            /**
            - add padding if necessary
            - encrypt file
            - save to file */
            IvParameterSpec IV = new IvParameterSpec(iv);
            SecretKeySpec AESkey = new SecretKeySpec(key, "AES");
            Cipher encryptor = Cipher.getInstance("AES/CBC/NoPadding");
            encryptor.init(Cipher.ENCRYPT_MODE, AESkey, IV);

            //take care of padding
            int padding = 16 - (plaintext.length % 16);
            byte[] paddedFileToEncrypt = new byte[plaintext.length + padding];
		    System.arraycopy(plaintext, 0, paddedFileToEncrypt, 0, plaintext.length);		
		
            // set leftmost bit to 1, then all zeros: 128 = 1000 0000
		    paddedFileToEncrypt[plaintext.length] = (byte) 128;
		    for (int i = plaintext.length + 1; i < paddedFileToEncrypt.length; i++) 
            {
			    paddedFileToEncrypt[i] = (byte) 0;
		    }
    
            byte[] cipherBytes = encryptor.doFinal(paddedFileToEncrypt);
        
            return cipherBytes;
        }
        catch(Exception e)
        {
            logger.info("There was an error with encrypting your file.");
            System.out.println(e);
            return plaintext;
        }
    }
	
    /* Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */
    
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) 
    {
        try 
            {
                IvParameterSpec IV = new IvParameterSpec(iv);
                SecretKeySpec AESkey = new SecretKeySpec(key, "AES");
                Cipher decryptor = Cipher.getInstance("AES/CBC/NoPadding");
                decryptor.init(Cipher.DECRYPT_MODE, AESkey, IV);
    
                byte[] plaintextBytes = decryptor.doFinal(ciphertext);
        
                return plaintextBytes;
            }
        catch(Exception e)
        {
            logger.info("There was an error with decrypting your file.");
            System.out.println(e);
            return ciphertext;
        }
    }
			
    /* Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus */
    
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus) 
    {
        return plaintext;
    }
	
    /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus */
    
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) 
    {
        return base;
    }
    private static byte[] generateSalt()
    {
        byte [] _16byteValue = new byte[16]; //16 bytes converts to 128 bits
        Random rnd = new SecureRandom();
        rnd.nextBytes(_16byteValue);
        return _16byteValue;
    }

    private static byte[] generateIV()
    {
        byte [] IVbytes = new byte[16]; //16 bytes converts to 128 bits
        Random rnd = new SecureRandom();
        rnd.nextBytes(IVbytes);
        
        return IVbytes;
    }

    private static byte[] convertPassword(String password) throws UnsupportedEncodingException
    {
        byte[] passwordBytes = password.getBytes("UTF-8");
        return passwordBytes;
    }
    public static void main(String[] args) throws GeneralSecurityException, IOException 
    {
        // Initialization stage create cipher instance, password, encrypt the password and generate the salt.
        Assignment1 cipher = new Assignment1();
        String filename = args[0];
        String password = "<y_R9g&cRg7CMm~=";
        byte[] IV = generateIV();
        byte[] encryptedPassword = convertPassword(password);
        byte[] salt = generateSalt();
        
        //generate encryption key
        byte [] encryptionKey = cipher.generateKey(encryptedPassword, salt); //length 32 bytes == 256 bits

        try 
        {
            Path path = Paths.get(System.getProperty("user.dir") + "/" + filename);
            byte[] fileBytes = Files.readAllBytes(path);
            byte[] encryptedText = cipher.encryptAES(fileBytes, IV, encryptionKey);
            // for testing purposes I have commented out decrypting method below
            byte [] decryptedText = cipher.decryptAES(encryptedText, IV, encryptionKey);
            OutputStream outputDecrypted = new FileOutputStream("decrypted.txt");
            OutputStream outputEncrypted = new FileOutputStream("encrypted.txt");
            for (byte fileByte : decryptedText) 
            {
                outputDecrypted.write(fileByte);
            }
            outputDecrypted.close();
            for (byte fileByte : encryptedText) 
            {
                outputEncrypted.write(fileByte);
            }
            outputEncrypted.close();

            
            
        } catch (Exception e) {
            logger.info("Error with reading file");
        }
        
        
    }
    
}
