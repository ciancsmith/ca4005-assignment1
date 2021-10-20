import java.math.BigInteger;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.*;
import java.util.Random;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.Logger;



/** Resources
 * https://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha256-in-java
 * https://www.geeksforgeeks.org/java-program-to-convert-byte-array-to-hex-string/
 * https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
 * https://stackoverflow.com/questions/4407779/biginteger-to-byte I was looking for a way to not use the toByteArray function as the 2's compliment would be a problem
 * https://www.geeksforgeeks.org/biginteger-compareto-method-in-java/
 */

public class Assignment1 implements Assignment1Interface
{    
    // Init logger
    private final static Logger logger = Logger.getLogger(Assignment1.class.getName());
    private static final BigInteger publicModulus = new BigInteger("c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9", 16);
    
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
            /*
            - add padding if necessary
            - encrypt file
            - save to file 
            */

            IvParameterSpec IV = new IvParameterSpec(iv);
            SecretKeySpec AESkey = new SecretKeySpec(key, "AES");
            Cipher encryptor = Cipher.getInstance("AES/CBC/NoPadding");
            encryptor.init(Cipher.ENCRYPT_MODE, AESkey, IV);

            //take care of padding for encryption
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
			
    /* Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus

        how the encryption works:
        we take the password p and the exponent e with the modulus N and we perform the calculation p^e(mod N) --notes
    */
    
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus) 
    {
        byte[] encryptedRSA = null;
        BigInteger base = new BigInteger(plaintext);
        BigInteger modEXP = modExp(base, exponent, modulus);
        encryptedRSA = modEXP.toByteArray();
        
        return encryptedRSA;
    }
	
    /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus 
       pseudocode for square and multiply algorithm for my peace of mind so I didnt have to go back and forth from the notes
       this is the right to left variant.
        y = 1
        for i = 0 to k-1 do 
	        if xi = 1 then y = (y*a) mod n end if
	        a = (a*a) mod n
        end for
    
    
    */
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) 
    {
        BigInteger y = new BigInteger("1");
        while(exponent.compareTo(BigInteger.ZERO) > 0) 
        {
            /*
            Need to check
            - Check for oddness in exponent
            - if odd multiply the result is multipled by the base or in this case the password
            - Iterate through digits
            */

            if(exponent.testBit(0)) y = (y.multiply(base).mod(modulus));

            exponent = exponent.shiftRight(1);
            base = (base.multiply(base).mod(modulus));
        }

        return y.mod(modulus);
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

    private static String convertByteToHexadecimal(byte[] byteArray)
    {
        String hex = "";
  
        // Iterating through each byte in the array
        for (byte i : byteArray) {
            hex += String.format("%02X", i);
        }
        return hex;
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException 
    {
        // Initialization stage create cipher instance, password, encrypt the password and generate the salt.
        Assignment1 cipher = new Assignment1();
        BigInteger exponent = new BigInteger("65537");
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
            // byte [] decryptedText = cipher.decryptAES(encryptedText, IV, encryptionKey);
            // String decryptedTextHex = convertByteToHexadecimal(decryptedText);
            String encryptedTextHex = convertByteToHexadecimal(encryptedText);

            BufferedWriter outputIV = new BufferedWriter(new FileWriter ("IV.txt"));
            BufferedWriter outputSalt = new BufferedWriter(new FileWriter ("Salt.txt"));
            BufferedWriter outputPassword = new BufferedWriter(new FileWriter ("Password.txt"));
            
            System.out.println(encryptedTextHex);            
            
            outputIV.write(convertByteToHexadecimal(IV));
            outputIV.close();

            outputSalt.write(convertByteToHexadecimal(salt));
            outputSalt.close();

            byte[] encryptedRSA = cipher.encryptRSA(encryptedPassword,exponent,publicModulus);
            String encryptedRSAhex = convertByteToHexadecimal(encryptedRSA);

            outputPassword.write(encryptedRSAhex);
            outputPassword.close();

        } catch (Exception e) {
            logger.info("Error with reading file");
        }
        
        
    }
    
}