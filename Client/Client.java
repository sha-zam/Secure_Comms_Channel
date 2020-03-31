// Name     : Jordan Jayke Sidik
// UOW ID   : 5921946
// References :
// http://www.sha1-online.com
// http://esus.com/encryptingdecrypting-using-rc4/

import java.net.*;
import java.util.*;
import java.io.*;
import java.math.*;
import java.lang.Math.*;
import javax.crypto.spec.*;
import java.security.*;
import javax.crypto.*;

//Thread Creation
class ThreadClient extends Thread
{
    private DatagramSocket socket;
    private DatagramPacket packet;
    private String sessionKey;
    private static String algorithm = "RC4";

    ThreadClient (DatagramSocket socket, String sessionKey)
    {
        this.socket = socket;
        this.sessionKey = sessionKey;
    }

    //Decryption of Ciphertext 
    public static String decrypt(byte[] toDecrypt, String key) throws Exception
    {
        //Create secret key specs
        SecretKey sk = new SecretKeySpec(key.getBytes("UTF-8"), algorithm);

        // do the decryption with that key
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, sk);
        byte[] decrypted = cipher.doFinal(toDecrypt);

        return new String(decrypted);
    }

    //SHA-1 Hashing
    public static String SHA1(String input) 
    { 
        try 
        { 
            MessageDigest mDigest = MessageDigest.getInstance("SHA1");
            byte[] result = mDigest.digest(input.getBytes());
            StringBuffer sb = new StringBuffer();

            for (int i = 0; i < result.length; i++) 
            {
                sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
            }
            
            return sb.toString();
        } 
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) 
        { 
            throw new RuntimeException(e); 
        } 
    }

    //Byte trimming to remove unnecessary extra bytes
    static byte[] trim(byte[] bytes)
	{
        int i = bytes.length - 1;
        
	    while (i >= 0 && bytes[i] == 0)
            --i;
            
	    return Arrays.copyOf(bytes, i + 1);
	}


    public void run()
    {
        try 
        {
            while (true)
            {
                packet = new DatagramPacket(new byte[512],512);
                socket.receive(packet);

                String check = new String (trim(packet.getData()));

                if (check.equals("Message Declined! Decryption Error!"))
                {
                    System.out.println("\nDecryption Error from Host!");
                    System.out.println("Exiting...");
                    System.exit(-1);
                }

                String decrypted = decrypt(trim(packet.getData()), sessionKey);

                //Separate Message and Hashing from Host
                String message = decrypted.substring(0, decrypted.length() - 40);  
                String hostHash = decrypted.substring(decrypted.length() - 40);  

                //Compute Hash to compare with Hash from Host. If does not match, reject message
                String checkHash = SHA1 (sessionKey + message);
                
                if (checkHash.equals(hostHash))
                {
                    System.out.println("\nNew Message : " + message);
                    System.out.print("\nEnter message : ");   

                    if (message.equals("exit"))
                    {
                        System.out.println("\nExiting...");
                        System.exit(0);
                    }  
                }
                else
                {
                    System.out.println("\nDecryption Error! \nExiting...");
                    String decline = "Message Declined! Decryption Error!";

                    DatagramPacket errpacket = new DatagramPacket(decline.getBytes(), decline.getBytes().length, InetAddress.getByName("127.0.0.1"), 1500);
                    socket.send(errpacket);
                    System.exit(-1);
                }

            }
              
        }
        catch (Exception e) 
        {
            System.out.println("Exception!");
			e.printStackTrace(System.out);
        }
    }
}

public class Client
{
    private static String algorithm = "RC4";

    private static DatagramPacket packet;
    private static DatagramSocket socket;
    
    //Parameters
    private static String password = "";
    private static BigInteger p = BigInteger.ZERO;
    private static BigInteger g = BigInteger.ZERO;

    //Keys
    private static int secretKey;
    private static BigInteger publicKey;
    private static String sessionKey;


    public static void initParams () throws FileNotFoundException, InterruptedException
    {
        //Obtain password
        System.out.println("\nEstablishing Password (PW)...");
        File pwFile = new File ("password.txt");
        Scanner pw = new Scanner (pwFile);

        while (pw.hasNextLine())
            password = pw.nextLine();

        Thread.sleep(1000);
        System.out.println("Password : " + password);

        //Establish modulus (p) and generator (g)
        System.out.println("\nEstablishing Common Parameters Modulus (p) and Generator (g)...");
        Scanner params = new Scanner (new File("parameters.txt"));    

        int counter = 0;

        while(params.hasNextLine())
        {
            if (counter == 0)
            {
                p = new BigInteger(params.nextLine());
                counter++;   
            }
            else
                g = new BigInteger(params.nextLine());
    
        }
        
        //Check modulus (p) and generator (g)
        Thread.sleep(1000);
        System.out.println("Modulus : " + p + ", bits : " + p.bitLength());
        System.out.println("Generator : " + g);
    }

    //Encryption using RC4
    public static byte[] encrypt(String toEncrypt, String key) throws Exception 
    {
        SecretKey sk = new SecretKeySpec(key.getBytes("UTF-8"), algorithm);
    
        // create an instance of cipher
        Cipher cipher = Cipher.getInstance(algorithm);
    
        // initialize the cipher with the key
        cipher.init(Cipher.ENCRYPT_MODE, sk);
    
        // enctypt!
        byte[] encrypted = cipher.doFinal(toEncrypt.getBytes());
    
        return encrypted;
    }

    //Decryption of ciphertext
    public static String decrypt(byte[] toDecrypt, String key) throws Exception 
    {
        //Create SecretKey Spec
        SecretKey sk = new SecretKeySpec(key.getBytes("UTF-8"), algorithm);

        // do the decryption with that key
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, sk);
        byte[] decrypted = cipher.doFinal(toDecrypt);

        return new String(decrypted);
    }

    //SHA-1 Hashing
    public static String SHA1(String input) 
    { 
        try 
        { 
            MessageDigest mDigest = MessageDigest.getInstance("SHA1");
            byte[] result = mDigest.digest(input.getBytes());
            StringBuffer sb = new StringBuffer();

            for (int i = 0; i < result.length; i++) 
            {
                sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
            }
            
            return sb.toString();
        } 
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) 
        { 
            throw new RuntimeException(e); 
        } 
    }
    
    //Byte trimming to remove unnecessary extra bytes
    static byte[] trim(byte[] bytes)
	{
	    int i = bytes.length - 1;
	    while (i >= 0 && bytes[i] == 0)
	    {
	        --i;
	    }

	    return Arrays.copyOf(bytes, i + 1);
	}

    //Key Exchange (Returns PK from Client)
    public static BigInteger keyExchange (BigInteger publicKey, String password)
    {
        BigInteger PKHost = BigInteger.ZERO;

        try
        {
            //Encrypt Public Key with RC4
            String PK = publicKey.toString();

            System.out.println("\nEncrypting PK...");
            byte[] encryptedPK = encrypt(PK, password);

            Thread.sleep(1000);
            System.out.println("Encrypted : " + encryptedPK);

            //Receiving Encrypted PK from Host (Alice)
            System.out.println("\nReceiving Encrypted PK from Host (Alice)");
            packet = new DatagramPacket(new byte[512], 512);
            socket.receive(packet);
            byte[] trimPacket = trim(packet.getData());

            //Sending Encrypted PK to Host (Alice)
            Thread.sleep(1000);
            System.out.println("\nSending Encrypted PK to Host (Alice)...");
            packet.setData(encryptedPK, 0, encryptedPK.length);
            socket.send(packet);
            
            //Decrypting PK from Host
            System.out.println("\nDecrypting PK from Host (Alice)...");
            String hostPK = decrypt(trimPacket, password);

            Thread.sleep(1000);
            System.out.println("Host's PK : " + hostPK);

            //Convert Host's PK to BigInteger
            PKHost = new BigInteger (hostPK);
        }
        catch (Exception e) 
        {
            if (e instanceof NumberFormatException)
                PKHost = new BigInteger("0");
            else
            {
                System.out.println("Exception!");
			    e.printStackTrace(System.out);
            }
            
        }

        return PKHost;

    }

    public static void main(String[] args) throws Exception
    {
        try
        {
            socket = new DatagramSocket(1400);

            Scanner input = new Scanner(System.in);
            String message = "";
    
            Random rand = new Random();

            //Read in parameters
            initParams();

            //Establish Client Secret Key
            System.out.println("\nEstablishing the Secret Key (SK)...");
            secretKey = rand.nextInt(99999) + 1;

            //Check SK
            Thread.sleep(1000);
            System.out.println("Secret Key : " + secretKey);

            //Calculate Public Key
            System.out.println("\nCalculating the Public Key (PK)...");
            publicKey = (g.pow(secretKey)).mod(p);

            //Check PK
            Thread.sleep(1000);
            System.out.println("Public Key : " + publicKey);

            //Establish Connection with Host
            System.out.println("\nSending Connection Request to Host...");
            String testConn = new String("Client Connection");
            byte[] testConnBytes = testConn.getBytes();

            packet = new DatagramPacket(testConnBytes, testConnBytes.length, InetAddress.getByName("127.0.0.1"), 1500);
            socket.send(packet);

            //Exchange Keys and Obtain PK from Host (Alice)
            BigInteger PKHost = keyExchange(publicKey, password);

            //Calculating Session Key (K)
            BigInteger keyToHash = (PKHost.pow(secretKey)).mod(p);

            //Establish Session Key using SHA-1
            System.out.println("\nEstablishing Session Key (SK)...");
            sessionKey = SHA1(keyToHash.toString());

            Thread.sleep(1000);
            System.out.println("Session Key : " + sessionKey);

            //Start Thread
            ThreadClient threadClient = new ThreadClient(socket, sessionKey);
            threadClient.start();

            //END OF STEP 1


            //Send Message
            while (!message.equals("exit"))
            {
                System.out.print("\nEnter Message : ");
                message = input.nextLine();

                //Hash Session Key with Message ->  H = Hash(K||M)
                String hash1 = SHA1(sessionKey + message);

                //Compute ciphertext -> C = EK(M||H) 
                byte[] ciphertext = encrypt((message + hash1), sessionKey);

                //Send ciphertext to Host (Alice)
                packet.setData(ciphertext, 0,  ciphertext.length);
                socket.send(packet);
            }

            System.out.println("Exiting...");
			System.exit(0);

        }
        catch (Exception e)
        {
            System.out.println("Exception!");
			e.printStackTrace(System.out);
        }

    }
}
