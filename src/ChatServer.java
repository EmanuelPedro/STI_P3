
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;


public class ChatServer implements Runnable
{
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private Thread thread = null;
	private int clientCount = 0;
	//private Encryption encryption = null;
	private X509Certificate caCertificate;
	private KeyStore keystore;
	private String servercertname;
	private String keystorealias;
	private String keystorepass;

	private X509Certificate loadCert(String pathToCert){
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
			X509Certificate loadedCertificate = (X509Certificate)cf.generateCertificate(finStream);
			return loadedCertificate;
		} catch (CertificateException e){
			System.out.println("Certificate error.");
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
		KeyStore keystore = null;
		try {
			keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(is, password.toCharArray());
			return keystore;
		} catch (Exception e) {
			System.out.println("Error loading keystore (invalid password?)");
			System.exit(0);
			return null;
		}
	}

	public boolean isValid(X509Certificate unvalidatedCertificate) {
		if (unvalidatedCertificate == null) {
			System.out.println("Null certificate");
			return false;
		}
		if (unvalidatedCertificate.equals(caCertificate)) {
			System.out.println("CA Certificate");
			return true;
		}
		try {
			unvalidatedCertificate.verify(caCertificate.getPublicKey());
			unvalidatedCertificate.checkValidity();
			return true;
		} catch(Exception e){
			System.out.println("Certificate not valid or expired.");
			return false;
		}
	}

	public ChatServer(int port, String servercertname, String keystorefilename, String keystorepassword, String keystorealias, String cacertname)
	{
		try
		{
			// Binds to port and starts server
			System.out.println("Binding to port " + port);
			server_socket = new ServerSocket(port);
			System.out.println("Server started: " + server_socket);

			caCertificate = loadCert(cacertname);
			System.out.println("Loaded CA Certificate");

			keystore = loadKeystore(keystorefilename,"sti_tp3");
			System.out.println("Loaded KeyStore");

			this.servercertname = servercertname;
			this.keystorealias = keystorealias;
			this.keystorepass = keystorepassword;

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

	public synchronized void handle(int ID, byte[] certificate, byte[] publicKey, String message) throws Exception {
		String decryptMessage = null;
		Encryption encryption = new Encryption();
		try {
			int leaving_id = findClient(ID);
			String clientCert = new String(certificate, "UTF-8");
			//System.out.println("client cert = " + clientCert);
			//System.out.println("message = " + input);
			boolean certReceived = clients[leaving_id].updateCertificate(clientCert);
			if (certReceived)
				System.out.println("cert received");
			else
				System.out.println("Cert not received");
			boolean isCertValid = isValid(clients[leaving_id].getClientCertificate());
			if (isCertValid)
				System.out.println("cert valid");
			else
				System.out.println("Cert not valid");

			byte[] decryptWithPrivateKey = new byte[0];
			//String s = new String(publicKey,StandardCharsets.UTF_8);
			//System.out.println("PUBKEY = " + s);
			decryptWithPrivateKey = encryption.decrypt2(publicKey, keystore.getKey(keystorealias, keystorepass.toCharArray()), "RSA/ECB/PKCS1Padding");

			clients[leaving_id].setClientSecretKey(decryptWithPrivateKey);

			//set client secretKey
			SecretKeySpec secretKey = new SecretKeySpec(decryptWithPrivateKey, "AES");
			clients[leaving_id].setSecretKey(secretKey);


		}
		catch (Exception e) {
			e.printStackTrace();
		}

		/*try {
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
		}*/
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

	public static void main(String args[])
	{
		ChatServer server = null;

		if (args.length != 6)
			// Displays correct usage for server
			System.out.println("Usage: java ChatServer port certname keystore_file keystore_pass keystore_keys_alias cacert");
		else
			// Calls new server
			server = new ChatServer(Integer.parseInt(args[0]), args[1], args[2], args[3], args[4], args[5]);
	}

}

class ChatServerThread extends Thread
{
	private ChatServer       server    = null;
	private Socket           socket    = null;
	private int              ID        = -1;
	private DataInputStream  streamIn  =  null;
	private DataOutputStream streamOut = null;
	//private PublicKey publicKey		   = null;
	private X509Certificate clientCertificate;
	private SecretKeySpec secretKey;
	private byte[] ClientSecretKey;


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

	public SecretKeySpec getSecretKey() { return secretKey; }

	public void setSecretKey(SecretKeySpec secretKey) { this.secretKey = secretKey; }

	public X509Certificate getClientCertificate() { return clientCertificate; }

	public byte[] getClientSecretKey() {
		return ClientSecretKey;
	}

	public void setClientSecretKey(byte[] secretKeyRAW) {
		this.ClientSecretKey = secretKeyRAW;
	}

	public boolean updateCertificate(String certificateString){
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
			InputStream finStream = null;
			finStream = new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8));
			clientCertificate = (X509Certificate)cf.generateCertificate(finStream);
			return true;
		} catch (CertificateException e){
			System.out.println("Certificate error.");
			return false;
		}
	}

	// Runs thread
	public void run()
	{
		System.out.println("Server Thread " + ID + " running.");
		String message;

		while (true)
		{
			try
			{
				int nCert, nPublicKey;
				byte[] certificate = new byte[16000];
				byte[] publicKey = new byte[1600];
				nCert = streamIn.read(certificate);
				nPublicKey = streamIn.read(publicKey);
				message = streamIn.readUTF();
				System.out.println(">>>nCert = " + nCert);
				System.out.println(">>>nPublicKey = " + nPublicKey);
				if ((nCert > 0) && (nPublicKey > 0))
				{
					server.handle(ID, certificate, publicKey, message);
				}
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

	// Opens thread
	public void open() throws IOException
	{
		streamIn = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		streamOut = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
	}

	// Closes thread
	public void close() throws IOException
	{
		if (socket != null)    socket.close();
		if (streamIn != null)  streamIn.close();
		if (streamOut != null) streamOut.close();
	}

}

