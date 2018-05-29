
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


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


    public ChatClient(String serverName, int serverPort, String certname, String servercertname, String keystorename, String keystorepass, String keystorealias)
    {
        System.out.println("Establishing connection to server...");
        //username = user;

        try
        {
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);

            myCertificate = loadCert(certname,true);

            serverCertificate = loadCert(servercertname,false);

            keystore = loadKeystore(keystorename,keystorepass);
            System.out.println("Loaded KeyStore");

            keyPass = keystorepass;
            keyAlias = keystorealias;

            //System.out.println("myCertificateText = " + myCertificateText);
            // Establishes connection with server (name and port)

            start();
        }

        catch(UnknownHostException uhe)
        {
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage());
        }

        catch(IOException ioexception)
        {
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

    public void run()
    {
        encryption = new Encryption();
        String message;
        while (thread != null)
        {
            try
            {
                // Sends message from console to server

                // 1. manda certificado para server (myCertificateText)
                streamOut.write(myCertificateText.getBytes());

                // 2. manda chave secreta (clientSecretKey)
                SecretKey secret = Encryption.getSecret();
                clientSecretKey = secret;

                String s = new String(secret.getEncoded());
                System.out.println("Secret key = " + s);
                System.out.println("serverCertificate publickey = " + serverCertificate.getPublicKey());

                //esta a dar merda aqui. => No installed provider supports this key: sun.security.rsa.RSAPublicKeyImpl
                byte[] encryptPublicKey = encryption.encrypt2(secret.getEncoded(), serverCertificate.getPublicKey(), "RSA/ECB/PKCS1Padding");
                // ou é por causa do certificado estar mal criado e por isso "serverCertificate" tb ta mal ou então nao sei de onde vem esse erro
                // que tem a ver com o algoritmo para encyptar (AES ou RSA/ECB/PKCS1Padding)
                // entretanto isto entrou num loop sem fim sempre a repetir o que ta nesta função.
                // só alterei nesta função e no handle do chatServer. do trabalho do outro grupo, estava a testar
                // o authPhase 1 e 2 que é enviar o cert po server depois encryptar a chave simetrica do cliente com chave publica do server e enviar



                //streamOut.write(encryptPublicKey);
                streamOut.flush();
                // 3. assinar mensagem

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
            catch(IOException ioexception)
            {
                System.out.println("Error sending string to server: " + ioexception.getMessage());
                stop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


    public void handle(String msg, String clientID, String signature, String publicKey)
    {
        System.out.println("temporariamente indisponivel");

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

    }

    // Inits new client thread
    public void start() throws IOException
    {
        console   = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());
        //streamOut.writeUTF(encryption.encoder.encodeToString(encryption.getPublicKey().getEncoded()));
        streamOut.flush();

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
    //private String username = null;

    public ChatClientThread(ChatClient _client, Socket _socket)
    {
        client   = _client;
        socket   = _socket;
        //username = user;
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
        String message, signature, clientID, publicKey;
        while (true)
        {
            try {
                clientID = streamIn.readUTF();
                message = streamIn.readUTF();
                signature = streamIn.readUTF();
                publicKey = streamIn.readUTF();

                //System.out.println("ClientID before handle = " +clientID);
                //System.out.println("Message before handle = " +message);
                //System.out.println("Signature before handle = " +signature);
                //System.out.println("publicKey before handle = " +publicKey);
                client.handle(message, clientID, signature, publicKey);
            }
            catch(IOException ioe)
            {
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
        }
    }
}

