import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Encryption {
    private Cipher cipher = null;
    private SecretKeySpec secret;
    private String defaultPass = "PasswordForSTIP3";
    public Base64.Encoder encoder;
    public Base64.Decoder decoder;
    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;

    public Encryption()
    {
        KeyPairGenerator keyGen;
        KeyPair pair;
        SecureRandom secureRandom;
        byte[] key = defaultPass.getBytes();
        secret = new SecretKeySpec(key, "AES");
        encoder = Base64.getEncoder();
        decoder = Base64.getDecoder();
        try {
            cipher = Cipher.getInstance("AES");
            keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
            secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, secureRandom);
            pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            //System.out.println("Private key = " + privateKey);
            publicKey = pair.getPublic();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String plainText) throws Exception {
        //System.out.println("Entrei encrypt ");
        byte[] plainTextByte = plainText.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        String encryptedText = encoder.encodeToString(encryptedByte);
        return encryptedText;
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

    public String signMessage(String plainText) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] TextSigned, data = decoder.decode(plainText);
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
}
