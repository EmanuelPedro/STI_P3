
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.net.*;
import java.io.*;


public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;
    private String username;
    private SecretKey secretKey;
    private Encryption encryption = null;

    public ChatClient(String serverName, int serverPort, String user) {
        KeyGenerator keyGen = null;
        System.out.println("Establishing connection to server...");
        
        try
        {
            username = user;
            // gera chave secreta que serve para identificar cada utilizador.
            try{
                keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(128);
            }

            catch(Exception exp)
            {
                System.out.println(" Exception inside constructor " +exp);
            }

            secretKey = keyGen.generateKey();

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
       String E_msg="";
       while (thread != null)
       {  
           try
           {
               E_msg = console.readLine();
               // Sends message from console to server
               System.out.println(">>> " + E_msg);
               E_msg = encryption.encrypt(E_msg, secretKey);
               streamOut.writeUTF(E_msg);
               streamOut.flush();
           }
         
           catch(IOException ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           }
       }
    }
    
    
    public void handle(String msg)
    {
        // Receives message from server
        if (msg.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else {
            // else, writes message received from server to console
            String D_msg = encryption.decrypt(msg, secretKey);

            System.out.println(D_msg);
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
   
    
    public static void main(String args[]) throws LoginException {
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
        while (true)
        {   try
            {  
                client.handle(streamIn.readUTF());
            }
            catch(IOException ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            }
        }
    }
}

