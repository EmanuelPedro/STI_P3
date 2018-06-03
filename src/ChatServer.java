import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class ChatServer implements Runnable
{
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private Thread thread = null;
	private int clientCount = 0;
	private X509Certificate caCertificate;
	private X509Certificate serverCertificate;
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
			keystore = KeyStore.getInstance("JCEKS");
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
			serverCertificate = loadCert(servercertname);

			keystore = loadKeystore(keystorefilename,keystorepassword);
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

	public synchronized void handle(int ID, String certificate,String publicKey, String signature, String message) throws Exception {
		int leaving_id = findClient(ID);
		Encryption encryption = new Encryption();

		try {
			boolean certReceived = clients[leaving_id].updateCertificate(certificate);
			if (certReceived)
				System.out.println("cert received");
			else
				System.out.println("Cert not received");

			boolean isCertValid = isValid(clients[leaving_id].getClientCertificate());
			if (isCertValid) {
				System.out.println("cert valid");
			    goToDecrypt(ID,certificate,encryption,publicKey,leaving_id,signature,message);
			    //Renovar chaves
                if (clients[leaving_id].getSentMessages()% 5 == 0){
                    String renewMessage = ".renovatingKey";
                    //clients[leaving_id].send(encryption.encrypt(renewMessage.getBytes(), clients[leaving_id].getSecretKey(), "AES"));

                }
			}
			else{
				System.out.println("Cert not valid");
			    System.exit(0);
			}
		}catch(Exception e){
            System.out.println("ERROR on Certificade validation: "+e);
        }

	}
    public synchronized void goToDecrypt(int ID, String certificate,Encryption encryption,String publicKey,int leaving_id,String signature,String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] decryptWithPrivateKey = new byte[0];

        try {
            decryptWithPrivateKey = encryption.decrypt2(Base64.getDecoder().decode(publicKey.getBytes()), keystore.getKey(keystorealias, keystorepass.toCharArray()), "RSA/ECB/NoPadding");
        } catch (Exception e) {
            System.out.println("ERROR ON DECRYPT" + e);
            clients[leaving_id].send(".quit");
            remove(ID);


        }

        clients[leaving_id].setClientSecretKey(decryptWithPrivateKey);
        //set client secretKey
        SecretKeySpec secretKey = new SecretKeySpec(decryptWithPrivateKey, "AES");
        clients[leaving_id].setSecretKey(secretKey);

        // verify signature
        //boolean isSigned = encryption.isSigned(clients[leaving_id].getClientCertificate().getPublicKey(), clients[leaving_id].getSecretKey(), signature);
        Signature myVerifySign = null;
        try {
            System.out.println("1>>Signature length = " + signature.getBytes().length);


            System.out.println("Signature = " + Base64.getDecoder().decode(signature));
            myVerifySign = Signature.getInstance("SHA256withRSA");


			System.out.println("CLIENTPUBLCKEY"+clients[leaving_id].getClientCertificate().getPublicKey());
            myVerifySign.initVerify(clients[leaving_id].getClientCertificate().getPublicKey());
			System.out.println("MYVERIFYSIGN:"+clients[leaving_id].getClientSecretKey());
            myVerifySign.update(clients[leaving_id].getSecretKey().getEncoded());
            System.out.println("SIGNSERVER:"+signature);
            boolean isSigned = myVerifySign.verify(Base64.getDecoder().decode(signature));
            if (isSigned) {
                System.out.println("Signature valid! ");
                afterSign(ID,certificate,encryption,publicKey,leaving_id,signature,message);
            } else {
                System.out.println("Signature invalid! ");
                clients[leaving_id].send(".quit");
                remove(ID);
                System.exit(0);
            }
        } catch (Exception e) {
            System.out.println("[ERROR] : Signature >> " + e);
            clients[leaving_id].send(".quit");
            remove(ID);
        }


    }
    public synchronized void afterSign(int ID, String certificate,Encryption encryption,String publicKey,int leaving_id,String signature,String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] decryptMessage, decodeMessage = Base64.getDecoder().decode(message);

        decryptMessage = encryption.decrypt2(decodeMessage, clients[leaving_id].getSecretKey(), "AES");
        String decrypMessageText = Base64.getEncoder().encodeToString(decryptMessage);
        System.out.println("Decrypted message = " + decrypMessageText);

        // verify message
        //generate hash message, messageDigest para textos longos
        String sender = message.substring(0, message.indexOf("|"));

			String sendedMessage = message.substring(0, message.indexOf("|"));
			String hashedMessage = message.substring(message.indexOf("|")+1);

			MessageDigest digest = MessageDigest.getInstance("MD5");
			digest.update(sendedMessage.getBytes());
			byte hashedBytes[] = digest.digest();

			StringBuffer stringBuffer = new StringBuffer();
			for (int i = 0; i < hashedBytes.length; i++) {
				stringBuffer.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
			}

			if (stringBuffer.toString().equals(hashedMessage))
			{
				System.out.println("Got new message = " + sendedMessage);
				if (sendedMessage.equals(".quit"))
				{
					// client quits
					clients[leaving_id].send(certificate);
					clients[leaving_id].send(publicKey);
					clients[leaving_id].send(signature);
					clients[leaving_id].send(ID + ": " + ".quit" + "|" + hashedMessage);
					// Notify remaing users
					for (int i = 0; i < clientCount; i++)
						if (i != leaving_id) {
							clients[i].send(certificate);
							clients[i].send(publicKey);
							clients[i].send(signature);
							clients[i].send("Client " + ID + " exits..");
						}
					remove(ID);
				}
				else
				{
					for (int i = 0; i < clientCount; i++) {
						clients[i].send(certificate);
						clients[i].send(publicKey);
						clients[i].send(signature);
						clients[i].send(ID + ": " + sendedMessage + "|" + hashedMessage);
					}
				}
			}
			else
			{
				System.out.println("Message not valid! ");
				clients[leaving_id].send(certificate);
				clients[leaving_id].send(publicKey);
				clients[leaving_id].send(signature);
				clients[leaving_id].send(ID + ": " + ".quit" + "|" + hashedMessage);
				remove(ID);

            }
//TODO RENEW KEY

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

	static byte[] trim(byte[] bytes)
	{
		int i = bytes.length - 1;
		while (i >= 0 && bytes[i] == 0)
		{
			--i;
		}

		return Arrays.copyOf(bytes, i + 1);
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
	private X509Certificate clientCertificate;
	private SecretKeySpec secretKey;
	private byte[] ClientSecretKey;

    public int getSentMessages() {
        return sentMessages;
    }

    public void setSentMessages(int sentMessages) {
        this.sentMessages = sentMessages;
    }

    private int sentMessages=0;

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

	public void setSecretKey(SecretKeySpec secretKey) { this.secretKey = secretKey;
        }

	public X509Certificate getClientCertificate() { return clientCertificate; }

	public byte[] getClientSecretKey() {
		return ClientSecretKey;
	}

	public void setClientSecretKey(byte[] secretKey) {
		this.ClientSecretKey = secretKey;
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
		String message, certificate, publicKey, signature;

		while (true)
		{
			try
			{
				certificate = streamIn.readUTF();
				publicKey = streamIn.readUTF();
				signature = streamIn.readUTF();

				message= streamIn.readUTF();

				server.handle(ID, certificate, publicKey, signature, message);
			}
			catch(IOException ioe)
			{
				System.out.println(ID + " ERROR reading: " + ioe.getMessage());
				server.remove(ID);
				stop();
			} catch (Exception e) {
				e.printStackTrace();
				server.remove(ID);
				stop();
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

