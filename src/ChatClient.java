
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.net.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;


public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;
    private String username;
    //private String secretKey;
    private Encryption encryption = null;

    public ChatClient(String serverName, int serverPort, String user) {
        System.out.println("Establishing connection to server...");
        username = user;

        try
        {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);
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
    
   public void run()
   {
       while (thread != null)
       {  
           try
           {
               String plainTextMessage = console.readLine();
                // Sends message from console to server
               try {
                   plainTextMessage = encryption.encrypt(plainTextMessage);
                   System.out.println(">> to send encrypt: " + plainTextMessage);
                   streamOut.writeUTF(plainTextMessage);
                   //streamOut.writeUTF(encryption.signMessage(plainTextMessage));
               } catch (NoSuchAlgorithmException e) {
                   e.printStackTrace();
               } catch (InvalidKeyException e) {
                   e.printStackTrace();
               } catch (SignatureException e) {
                   e.printStackTrace();
               } catch (NoSuchProviderException e) {
                   e.printStackTrace();
               } catch (Exception e) {
                   e.printStackTrace();
               }

               streamOut.flush();
           }
           catch(IOException ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           }
       }
    }
    
    
    public void handle(String msg, String clientID, String signature, String publicKey)
    {
        // Receives message from server
        String encryptedMessage = "";
        boolean isSigned;

        try {
            encryptedMessage = encryption.decrypt(clientID)+": "+ encryption.decrypt(msg);
            isSigned = encryption.isSigned(encryption.getSendedPublicKey(publicKey), signature, msg);

            if (!encryptedMessage.equals(".quit")) {
                if (isSigned)
                    System.out.println(encryptedMessage);
                else
                    System.out.println("Message not signed! ");
            }
            else
            {
                // Leaving, quit command
                System.out.println("Exiting...Please press RETURN to exit ...");
                stop();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Inits new client thread
    public void start() throws IOException
    {
        encryption = new Encryption();
        console   = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());
        streamOut.writeUTF(encryption.encoder.encodeToString(encryption.getPublicKey().getEncoded()));
        streamOut.flush();

        if (thread == null)
        {  
            client = new ChatClientThread(this, socket, username);
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

        if (args.length != 3)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port username");
        else
            // Calls new client
            client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2]);
    }
    
}

class ChatClientThread extends Thread
{  
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private DataInputStream  streamIn = null;
    private String username           = null;
    //private String secretKey          = null;

    public ChatClientThread(ChatClient _client, Socket _socket, String user)
    {  
        client   = _client;
        socket   = _socket;
        username = user;
        //this.secretKey = secret;
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
        String message, signature, clientID, publicKey;
        while (true)
        {   try
            {
                message = streamIn.readUTF();
                clientID = streamIn.readUTF();
                signature = streamIn.readUTF();
                publicKey = streamIn.readUTF();
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

