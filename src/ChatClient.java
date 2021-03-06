
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;


public class ChatClient implements Runnable
{
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;
    private X509Certificate myCertificate;
    private X509Certificate serverCertificate;
    private KeyStore keystore;
    private String myCertificateText;       //contem os detalhes do certificado gerado
    SecretKey clientSecretKey = null;
    String keyPass = null;
    String keyAlias = null;

    public ChatClient(String serverName, int serverPort, String certname, String servercertname, String keystorename, String keystorepass, String keystorealias) {
        System.out.println("Establishing connection to server...");

        try {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);

            myCertificate = loadCert(certname, true);

            serverCertificate = loadCert(servercertname, false);

            keystore = loadKeystore(keystorename, keystorepass);
            System.out.println("Loaded KeyStore");

            keyPass = keystorepass;
            keyAlias = keystorealias;

            start();
        } catch (UnknownHostException uhe) {
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage());
        } catch (IOException ioexception) {
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage());
        }

    }

    public X509Certificate loadCert(String pathToCert, boolean update){
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
            FileInputStream finStream = null;
            try {
                finStream = new FileInputStream(pathToCert);
            } catch (FileNotFoundException e) {
                System.out.println("File not found.");
                System.exit(0);
            }
            if (update){
                StringBuilder builder = new StringBuilder();
                int ch;
                try {
                    while((ch = finStream.read()) != -1){
                        builder.append((char)ch);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                myCertificateText = builder.toString();
                try {
                    finStream.close();
                    finStream = new FileInputStream(pathToCert);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            X509Certificate loadedCertificate = (X509Certificate)cf.generateCertificate(finStream);
            return loadedCertificate;
        } catch (CertificateException e) {
            System.out.println("Certificate error on " + pathToCert);
            System.exit(0);
            return null;
        }
    }

    private KeyStore loadKeystore(String pathToKeyStore, String password){
        FileInputStream is = null;
        try {
            is = new FileInputStream(pathToKeyStore);
        } catch (FileNotFoundException e) {
            System.out.println("Keystore not found");
            System.exit(0);
        }
        //System.out.println("keystorefilename = " + pathToKeyStore);
        //System.out.println("keystorepass = " + password);
        KeyStore keystore = null;
        try {
            //System.out.println("entrei no try ");
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, password.toCharArray());
            return keystore;
        } catch (Exception e) {
            System.out.println("Error loading keystore (invalid password?)");
            System.exit(0);
            return null;
        }
    }
    public void sendSignature(String message,Encryption encryption) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, SignatureException {
        // 3. manda assinatura
        //String signMessage = null;
        //String signMessage = encryption.signMessage(clientSecretKey, (PrivateKey)keystore.getKey(keyAlias, keyPass.toCharArray()));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign((PrivateKey)keystore.getKey(keyAlias, keyPass.toCharArray()));
        signature.update(clientSecretKey.getEncoded());
        byte[] TextSigned = signature.sign();
        byte[] encryptMessage = encryption.encrypt2(TextSigned, clientSecretKey, "AES");

        String encryptMessageText =Base64.getEncoder().encodeToString(encryptMessage);
        //String encryptMessageText =encryptMessage.toString();
        //System.out.println(">>>>>>>>>SENDSIGNATURE"+new String(Base64.getDecoder().decode(encryptMessageText),StandardCharsets.UTF_16));
        //System.out.println(">>>>>>>>>SENDSIGNATURE"+(Base64.getDecoder().decode(encryptMessageText)));
        //System.out.println("1>>>"+encryptMessage);
        //System.out.println("2>>>"+encryptMessageText);
        streamOut.writeUTF(encryptMessageText);
//        streamOut.flush();
        readEncrMessage(message,encryption);
    }
    public void readEncrMessage(String message,Encryption encryption) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, SignatureException {
        // 4. lê e envia mensagem encryptado
        message = console.readLine();
        byte[] encryptMessage2 = encryption.encrypt2(message.getBytes(), clientSecretKey, "AES");
        String encryptMessageText2 = Base64.getEncoder().encodeToString(encryptMessage2);

        // generate hash message, messageDigest para textos longos
        MessageDigest digest = MessageDigest.getInstance("MD5");
        digest.update(message.getBytes());
        byte hashedBytes[] = digest.digest();

        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < hashedBytes.length; i++) {
            stringBuffer.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        String finalMessage = message + "|" + stringBuffer.toString();

        streamOut.writeUTF(encryptMessageText2);
        //streamOut.writeUTF(message);

        streamOut.flush();
    }
    public void sendSimmetricKeys(String message,Encryption encryption) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, SignatureException {
        // 2. envia chave simetrica encriptada com chave publica do servidor
        //SecretKey secret = Encryption.getSecret();
        clientSecretKey =  Encryption.getSecret();
        byte[] encryptPublicKey = encryption.encrypt2(clientSecretKey.getEncoded(), serverCertificate.getPublicKey(), "RSA/ECB/NoPadding");
        String clientSecretKeyText = Base64.getEncoder().encodeToString(clientSecretKey.getEncoded());

        streamOut.writeUTF(clientSecretKeyText);
        //System.out.println("Symetric Key sent! ");
        ////// TEST encrypt using String
        // String encryptPublicKeyText = encryption.encrypt(Base64.getEncoder().encodeToString(secret.getEncoded()), serverCertificate.getPublicKey(), "AES");
        // System.out.println("\n ==> encryptPublicKeyText = " + encryptPublicKeyText);
        //////////////////////////////////////////

        sendSignature(message,encryption);

    }

    public void run()
    {
        String message = null;

        while (thread != null)
        {

            try {
                Encryption encryption = new Encryption();
                // 1. manda certificado para server (myCertificateText)
                streamOut.writeUTF(myCertificateText);
                //System.out.println("\nCertificate sent! ");
                sendSimmetricKeys(message,encryption);

            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        }
    }

    public void handle(String certificate, String publicKey, String signature, String message)
    {
        try {

            if (message.indexOf("|") == -1)
                System.out.println(message);
            else
            {
                String sendedMessageID = message.substring(0, message.indexOf("|"));
                String sendedMessage = sendedMessageID.substring(sendedMessageID.indexOf(":")+2);
                String hashedMessage = message.substring(message.indexOf("|")+1);

                MessageDigest digest = MessageDigest.getInstance("MD5");
                digest.update(sendedMessage.getBytes());
                byte hashedBytes[] = digest.digest();

                StringBuffer stringBuffer = new StringBuffer();
                for (int i = 0; i < hashedBytes.length; i++) {
                    stringBuffer.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
                }

                if (stringBuffer.toString().equals(hashedMessage)) {
                    // Receives message from server
                    if (sendedMessage.equals(".quit")) {
                        // Leaving, quit command
                        System.out.println("Exiting...Please press RETURN to exit ...");
                        stop();
                    }

                    else
                        System.out.println(sendedMessageID);
                } else {
                    System.out.println("Message not valid! ");
                }
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    // Inits new client thread
    public void start() throws IOException
    {
        console   = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());

        if (thread == null)
        {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    // Stops client thread
    public void stop()
    {
        if (thread != null)
        {
            thread.stop();
            thread = null;
        }
        try
        {
            if (console   != null)  console.close();
            if (streamOut != null)  streamOut.close();
            if (socket    != null)  socket.close();
        }

        catch(IOException ioe)
        {
            System.out.println("Error closing thread..."); }
        client.close();
        client.stop();
    }


    public static void main(String args[]) {
        ChatClient client = null;

        if (args.length != 7)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port username certName ServerCertName");
        else
            // Calls new client
                                //    IP   Porto   username   certName   serverCertname   keystroename   keystroepass   keystorealias
            client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2], args[3], args[4], args[5], args[6]);
    }


}

class ChatClientThread extends Thread
{
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private DataInputStream  streamIn = null;

    public ChatClientThread(ChatClient _client, Socket _socket)
    {
        client   = _client;
        socket   = _socket;
        open();
        start();
    }

    public void open()
    {
        try
        {
            streamIn  = new DataInputStream(socket.getInputStream());
        }
        catch(IOException ioe)
        {
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }

    public void close()
    {
        try
        {
            if (streamIn != null) streamIn.close();
        }

        catch(IOException ioe)
        {
            System.out.println("Error closing input stream: " + ioe);
        }
    }

    public void run()
    {
        //chama esta função ao receber resposta do server
        String message, cert, publicKey, signature;
        while (true)
        {   try
            {
                cert = streamIn.readUTF();
                publicKey = streamIn.readUTF();
                signature = streamIn.readUTF();
                message = streamIn.readUTF();

                client.handle(cert, publicKey, signature, message);
            }
            catch(IOException ioe)
            {
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
        }
    }

}

