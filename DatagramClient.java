import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.util.Random;
import javax.crypto.Cipher;

public class DatagramClient {	
	private final static int PACKETSIZE = 256;
	private final static BigInteger gCONST = new BigInteger(100, new Random(1028477L)).nextProbablePrime();
	private final static BigInteger pCONST = new BigInteger(100, new Random(2738749L)).nextProbablePrime();
	
	
	public static void main( String args[] ) throws Exception{
		int port = 9090;
		String publicKeyFile = "public.key";
		String privateKeyFile = "private.key";
		byte cipherText[],plainText[];
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		Cipher dataCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");	
		
		//Reading Public key
		X509EncodedKeySpec publicSpecs = new X509EncodedKeySpec(readFile(new File(publicKeyFile)));
		PublicKey pubKey = rsaKeyFactory.generatePublic(publicSpecs);
		dataCipher.init(Cipher.ENCRYPT_MODE, pubKey);
		
		if( args.length != 2 ){
	         System.out.println( "usage: ChatClient server-ip port" ) ;
	         return ;
	      }
		try{
				port = Integer.parseInt(args[1]);
			}
		   	catch (NumberFormatException e){
		   		System.out.println("Error parsing Commandline Argument!") ;
		   		System.out.println( e ) ;
		   		System.exit(0);
		   	}
		try{
			InetAddress addr = InetAddress.getByName(args[0]);
			
			// Construct Scocket for UPD packets
			DatagramSocket socket = new DatagramSocket();
			
			// building & sending LOGIN message to server 
			String login = new String("LOGIN");
			DatagramPacket loginPacket = new DatagramPacket(login.getBytes(Charset.defaultCharset()), login.length(), addr, port) ;
			socket.send(loginPacket);
			
			DatagramPacket receiveData = new DatagramPacket(new byte[PACKETSIZE], PACKETSIZE);
			socket.receive(receiveData);
			System.out.println(receiveData.getLength());
			byte cookie[] = receiveData.getData();
			String cookieStr = new String (cookie);
			System.out.println("Received Cookie: ");
			System.out.println(cookieStr);
			
			//sending back coockie test
			DatagramPacket loginCookie = new DatagramPacket(receiveData.getData(), receiveData.getLength(), addr, port) ;
			socket.send(loginCookie);
			
			BigInteger a = new BigInteger(100, new Random(System.currentTimeMillis() / 1000L)); 
			a = BigInteger.probablePrime(100,new Random(System.currentTimeMillis() / 1000L)); 
			String send="";
			Integer N1 = new Random(System.currentTimeMillis() / 1000L).nextInt();
			BigInteger aSec = new BigInteger(100,new Random());
			aSec=gCONST;
			//BigInteger p = new BigInteger(100,new Random());
			aSec=a.modPow(a, pCONST);
			
			//p=pCONST;
			
			
			send = send.concat("Alice");
			send = send.concat("@");
			send = send.concat("PASSWORD");
			send = send.concat("@");
			send = send.concat(aSec.toString());
			send = send.concat("@");
			send = send.concat(N1.toString());
			System.out.println("Sent PlainText:");
			System.out.println(send);
			cipherText = dataCipher.doFinal(send.getBytes(Charset.defaultCharset()));
			System.out.println("length of cipherText: "+cipherText.length);
			
//			ByteArrayOutputStream sendPacket = new ByteArrayOutputStream();
//			
//			DataOutputStream output = new DataOutputStream(sendPacket);
//			output.writeInt(receiveData.getLength());
//			System.out.println("cookie Length: "+receiveData.getLength());
//			output.writeInt(cipherText.length);
//			System.out.println("cipher Length: "+cipherText.length); 
//			output.write(receiveData.getData());
//			//output.write(cipherText);
//			output.close();
//			
//			byte[] c = new byte[sendPacket.size() + cipherText.length];
//			System.arraycopy(sendPacket.toByteArray(), 0, c, 0, sendPacket.size());
//			System.arraycopy(cipherText, 0, c, sendPacket.size(), cipherText.length);
//			
			DatagramPacket loginMsg2 = new DatagramPacket(cipherText,cipherText.length, addr, port);
			socket.send(loginMsg2);
			//System.out.println(cookieStr.concat(cipherText.toString()));
			//-----------Next thing to receive is Byte array, g^b mod p.
			receiveData = new DatagramPacket(new byte[PACKETSIZE], PACKETSIZE);
			socket.receive(receiveData);
			
			dataCipher.init(Cipher.DECRYPT_MODE, pubKey);
			plainText = dataCipher.doFinal(receiveData.getData());
			
			BigInteger gbp = new BigInteger(plainText);
			
			BigInteger sharedKey = new BigInteger(100, new Random());
			sharedKey = gbp.modPow(a, pCONST);
			
			System.out.println(sharedKey);
		}	
	
		catch (Exception e){
			System.out.println(e);
		}
		
	}	
	// Reads a given file and returns data as array of bytes (byte[])
	public static byte[] readFile(File file) throws IOException {
		DataInputStream input = new DataInputStream(new FileInputStream(file));
		long size = file.length();
		if (size > Integer.MAX_VALUE) {
			System.out.println("File too big!.");
			return null;
		}		
		byte[] bytes = new byte[(int)size];
		input.readFully(bytes);    
		input.close();
		return bytes;
	}

}
