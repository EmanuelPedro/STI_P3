
import java.net.*;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;


public class ChatServer implements Runnable
{
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private Thread thread = null;
	private int clientCount = 0;
	private Encryption encryption = null;

	public ChatServer(int port)
	{
		try
		{
			// Binds to port and starts server
			System.out.println("Binding to port " + port);
			server_socket = new ServerSocket(port);
			System.out.println("Server started: " + server_socket);
			start();
		}
		catch(IOException ioexception)
		{
			// Error binding to port
			System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
		}
	}

	public void run()
	{
		while (thread != null)
		{
			try
			{
				// Adds new thread for new client
				System.out.println("Waiting for a client ...");
				addThread(server_socket.accept());
			}
			catch(IOException ioexception)
			{
				System.out.println("Accept error: " + ioexception); stop();
			}
		}
	}

	public void start()
	{
		encryption = new Encryption();
		if (thread == null)
		{
			// Starts new thread for client
			thread = new Thread(this);
			thread.start();
		}
	}

	public void stop()
	{
		if (thread != null)
		{
			// Stops running thread for client
			thread.stop();
			thread = null;
		}
	}

	private int findClient(int ID)
	{
		// Returns client from id
		for (int i = 0; i < clientCount; i++)
			if (clients[i].getID() == ID)
				return i;
		return -1;
	}

	public synchronized void handle(int ID, String input, String signature, PublicKey publicKey) throws Exception {
		String decryptMessage = null;
		try {
			decryptMessage = encryption.decrypt(input);

			if (decryptMessage.equals(".quit")) {
				int leaving_id = findClient(ID);
				// Client exits

				clients[leaving_id].send(Integer.toString(ID));
				clients[leaving_id].send(encryption.encrypt(decryptMessage));
				clients[leaving_id].send(signature);
				clients[leaving_id].send(encryption.encoder.encodeToString(publicKey.getEncoded()));
				// Notify remaing users
				for (int i = 0; i < clientCount; i++)
					if (i != leaving_id) {
						clients[i].send(Integer.toString(ID));
						clients[i].send(encryption.encrypt("Client " + ID + " exits.."));
						clients[i].send(signature);
						clients[i].send(encryption.encoder.encodeToString(publicKey.getEncoded()));
					}
				remove(ID);
			} else {
				// Brodcast message for every other client online
				for (int i = 0; i < clientCount; i++) {
					clients[i].send(Integer.toString(ID));
					clients[i].send(encryption.encrypt(decryptMessage));
					clients[i].send(signature);
					clients[i].send(encryption.encoder.encodeToString(publicKey.getEncoded()));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public synchronized void remove(int ID)
	{
		int pos = findClient(ID);

		if (pos >= 0)
		{
			// Removes thread for exiting client
			ChatServerThread toTerminate = clients[pos];
			System.out.println("Removing client thread " + ID + " at " + pos);
			if (pos < clientCount-1)
				for (int i = pos+1; i < clientCount; i++)
					clients[i-1] = clients[i];
			clientCount--;

			try
			{
				toTerminate.close();
			}

			catch(IOException ioe)
			{
				System.out.println("Error closing thread: " + ioe);
			}

			toTerminate.stop();
		}
	}

	private void addThread(Socket socket)
	{
		if (clientCount < clients.length)
		{
			// Adds thread for new accepted client
			System.out.println("Client accepted: " + socket);
			clients[clientCount] = new ChatServerThread(this, socket);

			try
			{
				clients[clientCount].open();
				clients[clientCount].getPublicKey();
				clients[clientCount].start();
				clientCount++;
			}
			catch(IOException ioe)
			{
				System.out.println("Error opening thread: " + ioe);
			}
		}
		else
			System.out.println("Client refused: maximum " + clients.length + " reached.");
	}

	public Encryption getEncryption() {
		return encryption;
	}

	public static void main(String args[])
	{
		ChatServer server = null;

		if (args.length != 1)
			// Displays correct usage for server
			System.out.println("Usage: java ChatServer port");
		else
			// Calls new server
			server = new ChatServer(Integer.parseInt(args[0]));
	}

}

class ChatServerThread extends Thread
{
	private ChatServer       server    = null;
	private Socket           socket    = null;
	private int              ID        = -1;
	private DataInputStream  streamIn  =  null;
	private DataOutputStream streamOut = null;
	private PublicKey publicKey		   = null;


	public ChatServerThread(ChatServer _server, Socket _socket)
	{
		super();
		server = _server;
		socket = _socket;
		ID     = socket.getPort();
	}

	// Sends message to client
	public void send(String msg)
	{
		try
		{
			streamOut.writeUTF(msg);
			streamOut.flush();
		}

		catch(IOException ioexception)
		{
			System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
			server.remove(ID);
			stop();
		}
	}

	// Gets id for client
	public int getID()
	{
		return ID;
	}

	// Runs thread
	public void run()
	{
		System.out.println("Server Thread " + ID + " running.");
		String message, signature = null;

		while (true)
		{
			try
			{
				message = streamIn.readUTF();
				signature = streamIn.readUTF();

				server.handle(ID, message, signature, publicKey);
			}
			catch(IOException ioe)
			{
				System.out.println(ID + " ERROR reading: " + ioe.getMessage());
				server.remove(ID);
				stop();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public void getPublicKey()
	{
		String pubKey = null;
		try {
			pubKey = streamIn.readUTF();

			publicKey = server.getEncryption().getSendedPublicKey(pubKey);

			streamOut.flush();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}


	}

	// Opens thread
	public void open() throws IOException
	{
		streamIn = new DataInputStream(new
				BufferedInputStream(socket.getInputStream()));
		streamOut = new DataOutputStream(new
				BufferedOutputStream(socket.getOutputStream()));
	}

	// Closes thread
	public void close() throws IOException
	{
		if (socket != null)    socket.close();
		if (streamIn != null)  streamIn.close();
		if (streamOut != null) streamOut.close();
	}

}

