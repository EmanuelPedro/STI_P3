
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
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
    private Encryption encryption = null;
    private String username = null;
    private String myCertificateText;       //contem os detalhes do certificado gerado
    private X509Certificate myCertificate;
    private X509Certificate serverCertificate;
    private KeyStore keystore;
    String keyPass = null;
    String keyAlias = null;
    SecretKey clientSecretKey = null;
    int Step=0;

    public ChatClient(String serverName, int serverPort, String certname, String servercertname, String keystorename, String keystorepass, String keystorealias) {
        System.out.println("Establishing connection to server...");
        //username = user;

        try {
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);

            myCertificate = loadCert(certname, true);

            serverCertificate = loadCert(servercertname, false);

            keystore = loadKeystore(keystorename, keystorepass);
            System.out.println("Loaded KeyStore");

            keyPass = keystorepass;
            keyAlias = keystorealias;

            //System.out.println("myCertificateText = " + myCertificateText);
            // Establishes connection with server (name and port)

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

    public void run() {


        String message;
        while (thread != null) {
            try {
                message = console.readLine();


                try {
                    encryption = new Encryption();
                    // Sends message from console to server
                    //    if(Step==0) {
                    // 1. manda certificado para server (myCertificateText)

                    SecretKey secret = Encryption.getSecret();
                    clientSecretKey = secret;
                  //  System.out.println(secret + "" + clientSecretKey);
                    byte[] encryptPublicKey = encryption.encrypt2(secret.getEncoded(), serverCertificate.getPublicKey(), "RSA/ECB/PKCS1Padding");
                    String encryptPublicKeyText = new String(encryptPublicKey, "UTF-8");
                    streamOut.writeUTF(message);
                    streamOut.writeUTF(myCertificateText);
                    System.out.println(">>>>>"+encryptPublicKeyText);
                    streamOut.writeUTF(encryptPublicKeyText);
                   // streamOut.flush();
                    //streamOut.write(encryptPublicKey);
                    //streamOut.flush();


                } catch (Exception e) {
                    System.out.println("Error sending string to server: " + e.getMessage());
                }

                streamOut.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        //Step++;
        //  }
        //       if(Step==1){
        // 2. manda chave secreta (clientSecretKey)

        //  Step=2;
           /*     }
                if(Step==2){
                    Step=3;
                    break;
                }
                if(Step==3){
                    break;
                }*/
        //String s = Base64.getEncoder().encodeToString(secret.getEncoded());
        //System.out.println("Secret key = " + s);
        //System.out.println("serverCertificate publickey = " + serverCertificate.getPublicKey());


        //String string_encryptPublicKey = new String(encryptPublicKey,StandardCharsets.UTF_8);
        //System.out.println("encryptPublicKey text format = " + string_encryptPublicKey);


        // 3. manda assinatura

        // 4. manda a mensagem encriptada com hash

        //message = console.readLine();
        //streamOut.writeUTF(message);



                /*message = console.readLine();
                try {
                    message = encryption.encrypt(message);
                    streamOut.writeUTF(message);
                    streamOut.writeUTF(encryption.signMessage(message));
                } catch (Exception e) {
                    e.printStackTrace();
                }

                streamOut.flush();*/


    }

    public void handle(byte[] certificate, byte[] publicKey, String message)
    {
        System.out.println("temporariamente indisponivel");
/*

        // Receives message from server
        //encryption = new Encryption();
        String decryptMessage;
        boolean msgSigned;
        //System.out.println("ClientID before decrypt = " +clientID);
        //System.out.println("Message before decrypt = " +msg);
        //System.out.println("Signature before decrypt = " +signature);
        //System.out.println("publicKey before decrypt = " +publicKey);
        try {
            //String client = encryption.decrypt(clientID);
            decryptMessage = encryption.decrypt(msg);
            //System.out.println("Client ID after decrypt = " + client);
            //System.out.println("Message after decrypt = " + decryptMessage);
            msgSigned = encryption.isSigned(encryption.getSendedPublicKey(publicKey), signature, msg);

            if (msgSigned)
                System.out.println("Message signed! ");
            else
                System.out.println("Message not signed! ");

            if (decryptMessage.equals(".quit"))
            {
                // Leaving, quit command
                System.out.println("Exiting...Please press RETURN to exit ...");
                stop();
            }
            else {
                // else, writes message received from server to console
                System.out.println(clientID + ": " + decryptMessage);
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        //System.out.println("Message decrypted: " + decryptMessage);
*/
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
        String message, clientID;
        while (true)
        {   try
            {
                int nCert, nPublicKey;
                byte[] certificate = new byte[16000];
                byte[] publicKey = new byte[1600];
                nCert = streamIn.read(certificate);
                nPublicKey = streamIn.read(publicKey);
                message = streamIn.readUTF();

                if ((nCert > 0) && (nPublicKey > 0))
                {
                    client.handle(certificate, publicKey, message);
                }
            }
            catch(IOException ioe)
            {
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
        }
    }
}

