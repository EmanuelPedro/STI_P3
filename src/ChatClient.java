
import java.net.*;
import java.io.*;


public class ChatClient implements Runnable
{
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;
    private Encryption encryption = null;
    private String username = null;

    public ChatClient(String serverName, int serverPort, String user)
    {
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
        String message;
        while (thread != null)
        {
            try
            {
                // Sends message from console to server
                message = console.readLine();
                try {
                    message = encryption.encrypt(message);
                    streamOut.writeUTF(message);
                    streamOut.writeUTF(encryption.signMessage(message));
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
    private String username = null;

    public ChatClientThread(ChatClient _client, Socket _socket, String user)
    {
        client   = _client;
        socket   = _socket;
        username = user;
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

