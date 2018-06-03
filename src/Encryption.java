import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Encryption {
    private Cipher cipher = null;
    private SecretKeySpec secret;
    private String defaultPass = "PasswordForSTIP3";
    public Base64.Encoder encoder=null;
    public Base64.Decoder decoder=null;
    static KeyGenerator keyGen;


    public Encryption()
    {
        //LocalDate theDate = timePoint.toLocalDate();
        //System.out.println("Date = " + theDate);
        KeyPairGenerator keyPairGen;
        KeyPair pair;
        byte[] key = defaultPass.getBytes();
        secret = new SecretKeySpec(key, "AES");

        encoder = Base64.getEncoder();
        decoder = Base64.getDecoder();
        try {

            keyPairGen = KeyPairGenerator.getInstance("DSA", "SUN");
            keyPairGen.initialize(1024);
            pair = keyPairGen.generateKeyPair();
            //privateKey = pair.getPrivate();
            //publicKey = pair.getPublic();
            //System.out.println("Private key: " + privateKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public static SecretKey getSecret(){
        try{
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
        }

        catch(Exception exp)
        {
            System.out.println(" Exception inside constructor " +exp);
        }

        SecretKey secretKey = keyGen.generateKey();


        return secretKey;
    }

    public String encrypt(String plainText, PublicKey secretKey, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //System.out.println("Entrei encrypt ");
        //SecretKeySpec secKey = new SecretKeySpec(secretKey, algorithm);

        cipher = Cipher.getInstance(algorithm);
      //  System.out.println("Length data encrypt = " + plainText.length());
        //System.out.println("Length key encrypt = " + secretKey.getEncoded().length);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] newData = cipher.doFinal(plainText.getBytes());

        return encoder.encodeToString(newData);
    }

    public String decrypt(String encryptedText, Key secretKey, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        //SecretKeySpec secKey = new SecretKeySpec(secretKey, algorithm);
        System.out.println("Length data decrypt = " + encryptedText.length());
        System.out.println("Length key decrypt = " + secretKey.getEncoded().length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] newData = cipher.doFinal(encryptedText.getBytes());
        return new String(newData);
    }

    public byte[] encrypt2(byte[] plainText, Key secretKey2, String algorithm) throws UnsupportedEncodingException {
        String text = new String(plainText);
        //System.out.println("Valor de plaintext = " + encoder.encodeToString(plainText));    // byte -> string
        //System.out.println("Valor de key = " + encoder.encodeToString(secretKey.getEncoded()));     //key -> string
        byte[] encryptedByte = new byte[200];
     //   System.out.println("Length data encrypt = " + plainText.length);
       // System.out.println("Length key encrypt = " + secretKey2.getEncoded().length);

        try {
            cipher = Cipher.getInstance(algorithm);
            if(algorithm.equals("AES")){
                cipher.init(Cipher.ENCRYPT_MODE, secretKey2, cipher.getParameters());
            }
            else if (algorithm.equals("RSA/ECB/NoPadding")) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey2);
            }
            //System.out.println(plainText.length);
            encryptedByte = cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        //String encryptedText = encoder.encodeToString(encryptedByte);

        return encryptedByte;
    }

    public byte[] decrypt2(byte[] encryptedText, Key secretKey, String algorithm) {
        //String s = new String(encryptedText,StandardCharsets.UTF_8);
        //System.out.println("Valor de encryptedText = " + encoder.encodeToString(encryptedText));
       // System.out.println("Length data decrypt = " + encryptedText.length);
        //System.out.println("Length key decrypt = " + secretKey.getEncoded().length);
        byte[] decryptedByte = new byte[200];
        try{
           cipher = Cipher.getInstance(algorithm);
            if(algorithm.equals("AES")){
                cipher.init(Cipher.DECRYPT_MODE,secretKey,cipher.getParameters());
            }
            else if(algorithm.equals("RSA/ECB/NoPadding")){
                cipher.init(Cipher.DECRYPT_MODE,secretKey);
            }

            decryptedByte =cipher.doFinal(encryptedText);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR : DECRYPTION:"+e);

        } catch (InvalidKeyException e) {
            System.out.println("ERROR : DECRYPTION:"+e);
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("ERROR : DECRYPTION:"+e);
        } catch (NoSuchPaddingException e) {
            System.out.println("ERROR : DECRYPTION:"+e);
        } catch (BadPaddingException e) {
            System.out.println("ERROR : DECRYPTION:"+e);
        } catch (IllegalBlockSizeException e) {
            System.out.println("ERROR : DECRYPTION:"+e);
        }

        return decryptedByte;
    }

    public String encodeBase64(byte[] data){
        return encoder.encodeToString(data);
    }

    public byte[] decodeBase64(String data){
        return decoder.decode(data);
    }

}
