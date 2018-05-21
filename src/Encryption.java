import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Encryption {
    private Base64.Encoder Base64encoder = null;
    private String ECipherText = "";
    private String DCipherText = "";

    public String encrypt(String message, Key secretKey)
    {
        try {
            System.out.println("entrei encrypt");
            Cipher c = Cipher.getInstance("AES");

            c.init(Cipher.ENCRYPT_MODE,secretKey,c.getParameters());

            byte[] output = c.doFinal(message.getBytes());

            ECipherText = Base64encoder.encodeToString(output);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return ECipherText;
    }

    public String decrypt(String message, Key secretKey)
    {
        Cipher c = null;
        try {
            c = Cipher.getInstance("AES");

            c.init(Cipher.DECRYPT_MODE,secretKey,c.getParameters());

            byte[] output = c.doFinal(message.getBytes());

            DCipherText = new String(output);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return DCipherText;
    }
}
