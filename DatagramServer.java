import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.Integer;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Random;
import java.net.InetAddress;

import javax.crypto.Cipher;

/*References:
 *http://javarevisited.blogspot.com/2012/01/java-hashtable-example-tutorial-code.html#ixzz2InCOlKML
 *http://www.heimetli.ch
 */
public class DatagramServer
{
   private final static int PACKETSIZE = 256 ;
   private final static BigInteger gCONST = new BigInteger(100, new Random(1028477L)).nextProbablePrime();
   private final static BigInteger pCONST = new BigInteger(100, new Random(2738749L)).nextProbablePrime();

   
   public static void main( String args[] )throws Exception{
		String privateKeyFile = "private.key";
		byte plainText[],cipherText[];//, plainText1[],plainText2[], toen[],piece[];
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		
		Cipher dataCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");	

	   String serverSecret = "VAtsaMAndeep";
	  // Check the arguments
	   if( args.length != 1 ){
		   System.out.println( "usage: ChatServer port" ) ;
		   return ;
	   }
	   //Hashtable<Integer, InetAddress> list = new Hashtable<Integer, InetAddress>();
	   int port=9090;
	  
	   // Convert the argument to ensure that is it valid (Integer)
	   try{
		   port = Integer.parseInt(args[0]);
	   }
	   catch (NumberFormatException e){
		   	System.out.println("Error parsing Commandline Argument!") ;
	   		System.out.println( e ) ;
	   		System.exit(0);
	   	}
	   	try{		  
	   		// Construct the socket
	   		DatagramSocket socket = new DatagramSocket( port ) ;
	   		socket.setReuseAddress(true);
	   		System.out.println( "The server is ready..." ) ;
	   		
	   		for( ;; ){
	   			// Create a packet
	   			DatagramPacket packet = new DatagramPacket( new byte[PACKETSIZE], PACKETSIZE ) ;
            
	   			// Receive a packet (blocking)
	   			socket.receive( packet );
            
	   			//if UDP packet is of type LOGIN then Complete Login process
	   			if(new String(packet.getData()).startsWith("LOGIN"))
	   				{	   					
	   					String cookie = "";
	   					Integer cPort = new Integer(packet.getPort());
	   					cookie.concat(cPort.toString());
	   					cookie.concat(packet.getAddress().toString());
	   					cookie.concat(serverSecret);

	   					MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");

	   					messageDigest.update(cookie.getBytes("UTF-16BE"));
	   					byte[] digest = messageDigest.digest();

	   					StringBuffer digestInHex = new StringBuffer();

	   					for (int i = 0, l = digest.length; i < l; i++) {
	   					    // Preserve the bit representation when casting to integer.
	   					    int intRep = digest[i] & 0xFF;
	   					    // Add leading zero if value is less than 0x10.
	   					    if (intRep < 0x10)  digestInHex.append('\u0030');
	   					    // Convert value to hex.
	   					    digestInHex.append(Integer.toHexString(intRep));
	   					}

	   					DatagramPacket toSendPacket = new DatagramPacket(digestInHex.toString().getBytes(Charset.defaultCharset()), digestInHex.toString().length(), packet.getAddress(), packet.getPort());
	   					//Integer.parseInt("9");
	   					System.out.println("Cookie Sent:");
	   					System.out.println(digestInHex.toString());	   						   					   							
	   					socket.send( toSendPacket ) ;
	   					
	   					System.out.println("Cookie which came back:");
	   					DatagramPacket receiveData = new DatagramPacket(new byte[PACKETSIZE], PACKETSIZE);
	   					socket.receive(receiveData);
	   					System.out.println(new String(receiveData.getData()));
	   					
	   					receiveData = new DatagramPacket(new byte[PACKETSIZE], PACKETSIZE);
	   					socket.receive(receiveData);
	   					byte recvBytes[] = receiveData.getData();

//	   					ByteArrayInputStream recvPacket = new ByteArrayInputStream(receiveData.getData());
//	   					DataInputStream input = new DataInputStream(recvPacket);
//	   					
//	   					byte recvCookieB[] = new byte[input.readInt()];
//	   					byte recvCipher[] = new byte[input.readInt()];	   					
//	   					input.read(recvCookieB);
//	   					//input.read(recvCipher);
//	   					input.close();
//	   					int j=0;
//	   					for(int i = 4+4+recvCookieB.length; i<recvBytes.length;)
//	   						recvCipher[j++] = recvBytes[i++];
//	   					
//	   					System.out.println("CipherText: "+recvCipher.length);
//	   					for(int i =0; i<recvCipher.length;i++)
//	   						System.out.print(recvCipher[0]);
//	   					
//	   					//System.out.println("Integetsize: "+Integer.SIZE/Byte.SIZE);
//	   					System.out.println("cookie Length: "+recvCookieB.length);
//	   					System.out.println(new String (recvCookieB));
//	   					System.out.println("cipher Length: "+recvCipher.length);
//	   					System.out.println("Recv Cipher: ");
//	   					System.out.println(recvCipher);
	   					
	   					PKCS8EncodedKeySpec privateSpecs = new PKCS8EncodedKeySpec(readFile(new File(privateKeyFile)));
	   					PrivateKey privKey = rsaKeyFactory.generatePrivate(privateSpecs);
	   					
	   					dataCipher.init(Cipher.DECRYPT_MODE, privKey);
	   					plainText = dataCipher.doFinal(recvBytes);
	   					System.out.println("Received PlainText:");
	   					System.out.println(new String (plainText));
	   					
	   					String fStr[] = new String(plainText).split("@");
	   					
	   					BigInteger gap = new BigInteger(fStr[2]);//3rd token is g^a mod P
	   					int N1 = Integer.parseInt(fStr[3]); // Nounce N1 from user
	   					
	   					BigInteger b = new BigInteger(100, new Random(System.currentTimeMillis() / 1000L)); 
	   					b = BigInteger.probablePrime(100,new Random(System.currentTimeMillis() / 1000L)); 
	   					String send="";
	   					Integer N2 = new Random(System.currentTimeMillis() / 1000L).nextInt();
	   					BigInteger bSec = new BigInteger(100,new Random());
	   					bSec=gCONST;
	   					//BigInteger p = new BigInteger(100,new Random());
	   					bSec=b.modPow(b, pCONST);
	   					
	   					dataCipher.init(Cipher.ENCRYPT_MODE, privKey);
	   					cipherText = dataCipher.doFinal(bSec.toByteArray());
	   					
	   					toSendPacket = new DatagramPacket(cipherText, cipherText.length, packet.getAddress(), packet.getPort());
	   					socket.send(toSendPacket);
	   					
	   					BigInteger sharedKey = new BigInteger(100, new Random());
	   					sharedKey = gap.modPow(b, pCONST);
	   					
	   					
	   					System.out.println(sharedKey);
	   					
	   					
	   				}
            
//	   			//if UDP packet is of type MESSAGE then server broadcasts the message 
//	   			if(new String(packet.getData()).startsWith("MESSAGE")){     
//	   				Enumeration<Integer> e = list.keys();
//	   				int clientPort;
//	   				System.out.print(".");
//	   				while(e.hasMoreElements()){
//	   					clientPort = (int) e.nextElement();
//	   					String sendStr = new String ("INCOMING "+"<From " + packet.getAddress() + ":" + packet.getPort() + ">: " + new String(packet.getData()).substring(7));
//	   					DatagramPacket toSendPacket = new DatagramPacket(sendStr.getBytes(Charset.defaultCharset()), sendStr.length(), (InetAddress)list.get(clientPort), clientPort) ;
//	   					socket.send( toSendPacket ) ;
//	   				}
//	   			}

	   		}
	   	}
	   	catch( Exception e )
	   	{
	   		System.out.println( e ) ;
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