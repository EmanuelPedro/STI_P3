import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.util.Base64;

public class Encryption {
    private Cipher cipher = null;
    private SecretKeySpec secret;
    private String defaultPass = "PasswordForSTIP3";
    public Base64.Encoder encoder;
    public Base64.Decoder decoder;
    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;
    //LocalDateTime timePoint = LocalDateTime.now();
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
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
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

    public SecretKeySpec setSecretKeySpec()
    {
        byte[] key = defaultPass.getBytes();
        secret = new SecretKeySpec(key, "AES");

        return secret;
    }

    public String encrypt(String plainText) throws Exception {
        //System.out.println("Entrei encrypt ");
        byte[] plainTextByte = plainText.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        String encryptedText = encoder.encodeToString(encryptedByte);
        return encryptedText;
    }

    public byte[] encrypt2(byte[] plainText, Key secretKey, String algorithm) {
        //System.out.println("Entrei encrypt ");
        byte[] encryptedByte = new byte[200];

        try {
            cipher = Cipher.getInstance("AES");
            if(algorithm.equals("AES")){
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, cipher.getParameters());
            }
            else if (algorithm.equals("RSA/ECB/PKCS1Padding")) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }
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

    public String decrypt(String encryptedText) throws Exception {
        //System.out.println("Entrei decrypt ");
        //System.out.println("Encrypt text= " + encryptedText);
        //System.out.println("Private key sign = " + privateKey);
        //System.out.println("Secretkey = " + secret);

        byte[] encryptedTextByte =decoder.decode(encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secret);
        //System.out.println("Length = " + cipher.doFinal(encryptedTextByte).length);
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
        String decryptedText = new String(decryptedByte);
        return decryptedText;
    }

    public byte[] decrypt2(byte[] encryptedText, Key secretKey) throws Exception {
        //System.out.println("Entrei decrypt ");
        //System.out.println("Encrypt text= " + encryptedText);
        //System.out.println("Private key sign = " + privateKey);
        //System.out.println("Secretkey = " + secret);

        //byte[] encryptedTextByte =decoder.decode(encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        //System.out.println("Length = " + cipher.doFinal(encryptedTextByte).length);
        byte[] decryptedByte = cipher.doFinal(encryptedText);
        //String decryptedText = new String(decryptedByte);
        return decryptedByte;
    }

    public String signMessage(String plainText) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] TextSigned, data = decoder.decode(plainText);
        System.out.println("Private key: " + privateKey);
        Signature sign = Signature.getInstance("SHA1withDSA","SUN");
        sign.initSign(privateKey);
        sign.update(data,0,data.length);
        TextSigned = sign.sign();
        return encoder.encodeToString(TextSigned);
    }

    public boolean isSigned(PublicKey pubKey, String signature, String plainText) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA1withDSA","SUN");
        byte[] message = decoder.decode(plainText), signatureEncoded = decoder.decode(signature);
        boolean signed = false;
        dsa.initVerify(pubKey);
        dsa.update(message, 0 , message.length);
        signed = dsa.verify(signatureEncoded);
        return signed;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PublicKey getSendedPublicKey(String pubKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] pubKeyEncoded = decoder.decode(pubKey);
        X509EncodedKeySpec pubKeySpec;
        KeyFactory keyFactory;
        pubKeySpec = new X509EncodedKeySpec(pubKeyEncoded);
        keyFactory = KeyFactory.getInstance("DSA", "SUN");
        return keyFactory.generatePublic(pubKeySpec);
    }

    public void escreveFicheiro(String fileName) throws IOException {
        String str = "127.0.0.1\nclient4\nclient5";

        BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
        writer.write(str);

        writer.close();
    }

    /*public KeyStore loadKeystore(String pathToKeyStore, String password){
        FileInputStream is = null;
        try {
            is = new FileInputStream(pathToKeyStore);
        } catch (FileNotFoundException e) {
            System.out.println("Keystore not found");
            System.exit(0);
        }
        System.out.println("keystorefilename = " + pathToKeyStore);
        System.out.println("keystorepass = " + password);
        KeyStore keystore = null;
        try {
            System.out.println("entrei no try ");
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, password.toCharArray());
            return keystore;
        } catch (Exception e) {
            System.out.println("Error loading keystore (invalid password?)");
            System.exit(0);
            return null;
        }
    }*/


}
