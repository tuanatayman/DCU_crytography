import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SymEncrypt implements Assignment1Interface{
    public static void main(String[] args) throws IOException{
        SymEncrypt symEncrypt = new SymEncrypt(); 
        
        // create password and encryp it using UTF-8 and put in Password.txt
        String password = "SD5ByZQ67ut2CWAf";
        byte[] password_bytes = password.getBytes(StandardCharsets.UTF_8);
        writeToFile(new String(password_bytes),"Password.txt");

        byte[] salt_bytes = random128();
        byte[] iv_bytes = random128();
        writeToFile(bytesToString(salt_bytes),"Salt.txt");
        
        // create key using p&s
        byte[] aes_key = symEncrypt.generateKey(password_bytes, salt_bytes);
        
        //input binary file is SymEncrypt.class
        byte[] input_bytes = inputToByteArray("SymEncrypt.class");
        
        
        //encrypt the binary input file
        byte[] input_encryptAES = symEncrypt.encryptAES(input_bytes, iv_bytes, aes_key);

        //encrypt p with encryption exponent & decoders public modulus(N)
        BigInteger exponent = new BigInteger("65537");
        String modulus_str =  "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
        BigInteger modulus = new BigInteger(modulus_str,16);
   
        
        //decryption
        //System.out.println(input_encryptAES.length);
        byte[] decrypted = symEncrypt.decryptAES(input_encryptAES, iv_bytes, aes_key);
        FileOutputStream fos = new FileOutputStream("Decrypted.class");
        //System.out.println(decrypted);
        
        fos.write(decrypted);
        fos.close();

    }

	public byte[] generateKey(byte[] password, byte[] salt){
        /* Method generateKey returns the key as an array of bytes and is generated from the given password and salt. */
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        try {
            outputStream.write(password);
            outputStream.write(salt);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            //first hash needs to be converted to ByteArray from ByteArrayOutputStream
            byte[] encodedhash = digest.digest(outputStream.toByteArray());
            //hash 999 times with SHA-256
            for(int i=0;i<999;i++){
                encodedhash = digest.digest(encodedhash);
            }
            return encodedhash;

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
		
           
	public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key) {
        /* Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key */
        //CBC mode uses an Initialization Vector (IV) to augment the encryption
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        //divide tewt into 16byte blocks
        int len = plaintext.length;
        int last_bytes = len%16;
        int empty_bytes = 16-last_bytes;
    
        if(last_bytes != 0){
            byte[] padding = new byte[empty_bytes-1];
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            
            try {
                outputStream.write(plaintext);
                outputStream.write((byte)1);
                outputStream.write(padding);
            } catch (IOException e) {
                e.printStackTrace();
            }
            plaintext = outputStream.toByteArray();
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(plaintext);
            return encrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException 
                    | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
		
        
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key){
        /* Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);

            for (int c = ciphertext.length - 1 ; c >= 0; c-- ) {
                if (decrypted[c] == (byte) 1) {
                    byte[] textDecrypted = Arrays.copyOfRange(decrypted, 0, c);
                    return textDecrypted;
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
				
        
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus){
        /* Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus */
        BigInteger base = new BigInteger(plaintext);
        BigInteger p_encrypt = modExp(base,exponent,modulus);
        return p_encrypt.toByteArray();
    }
	 
        
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus){
        /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus */
        BigInteger result = base.mod(modulus); //just to initialise, changes every iteration
        BigInteger modulo = base.mod(modulus); //fixed value

        //if power 0, than mod(n)=1
        if(exponent.compareTo(BigInteger.ZERO)==0){
            System.out.println("in e compare to");
            return BigInteger.ONE;
        }
        //iteratif method, not fast :(
        while(exponent.compareTo(BigInteger.ZERO)>1){
            if(result.compareTo(BigInteger.ONE)==0){
                System.out.println("in result compare to");
                return BigInteger.ONE;
            }else if(result.compareTo(BigInteger.ZERO)==0){
                return BigInteger.ZERO;
            }
            result = modulo.multiply(result).mod(modulus);
            exponent = exponent.shiftRight(1);
        }
        return result;
    }

    public static String bytesToString(byte[] bytes){
        return ((new BigInteger(bytes)).toString());
    }
      
    public static void writeToFile(String s, String filename){
        BufferedWriter writer;
        try {
            writer = new BufferedWriter(new FileWriter(filename));
            writer.write(s);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static byte[] random128(){
        // use SecureRandom API to create a random 128-bit value  and put it in Salt.
        SecureRandom rng = new SecureRandom();
        byte bytes[] = new byte[16]; // 128 bits are converted to 16 bytes;
        rng.nextBytes(bytes);
        return bytes;
    }

    public static byte[] inputToByteArray(String filename){
        File file=new File(filename);   
        byte[] input_bytes = new byte[(int) file.length()];
        try {
            FileInputStream fis = new FileInputStream(file);
            input_bytes= fis.readAllBytes();
            fis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        };
        return input_bytes;
    }

    public String inputToString(String filename){
        File file=new File(filename);   
        String str="";
        try {
            FileInputStream fis = new FileInputStream(file);
            int ch;
            while ((ch = fis.read()) != -1) {
                str=str+Integer.toString(ch);
            }
            fis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        };
        System.out.println(str);
        return str;
    }

    public String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /* static BigInteger modulo(BigInteger bi, BigInteger n){
        BigInteger q = bi.divide(n);
        BigInteger a = q.multiply(n);
        BigInteger r = bi.subtract(a);
        System.out.println(r);
        return  r;
    } */
    
}
