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
class ThreadHost extends Thread
{
    private static String algorithm = "RC4";

    private DatagramSocket socket;
    private DatagramPacket packet;

    private String sessionKey;
    

    ThreadHost (DatagramSocket socket, String sessionKey)
    {
        this.socket = socket;
        this.sessionKey = sessionKey;
    }   

    //Decryption of Ciphertext 
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
                    System.out.println("\nDecryption Error from Client!");
                    System.out.println("Exiting...");
                    System.exit(-1);
                }


                String decrypted = decrypt(trim(packet.getData()), sessionKey);

                //Separate Message and Hashing from Host
                String message = decrypted.substring(0, decrypted.length() - 40);  
                String clientHash = decrypted.substring(decrypted.length() - 40);  

                //Compute Hash to compare with Hash from Host. If does not match, reject message
                String checkHash = SHA1 (sessionKey + message);

                if (checkHash.equals(clientHash))
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

                    DatagramPacket errpacket = new DatagramPacket(decline.getBytes(), decline.getBytes().length, InetAddress.getByName("127.0.0.1"), 1400);
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

public class Host
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

    //Return a safe prime for modulus (p) and write to file
    public static void safePrime(int bitLength, String path) throws FileNotFoundException, IOException
    {
        SecureRandom random = new SecureRandom();

        PrintWriter output1 = new PrintWriter(path + "Host\\parameters.txt");
        PrintWriter output2 = new PrintWriter(path + "Client\\parameters.txt");

        BigInteger p, q;

        q = BigInteger.probablePrime(bitLength - 1, random);

        //Check Safe Prime
        p = q.add(q).add(BigInteger.ONE);
        
        while (!p.isProbablePrime(100)) 
        {
            do 
            {
                q = q.nextProbablePrime();

            } while (q.mod(BigInteger.TEN).equals(BigInteger.valueOf(7)) || 
                    !q.remainder(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)));

            p = q.add(q).add(BigInteger.ONE);

            while (p.bitLength() != bitLength) 
            {
                q = BigInteger.probablePrime(bitLength - 1, random);
                p = q.add(q).add(BigInteger.ONE);
            }
        }  

        output1.println(p);
        output2.println(p);

        output1.close();
        output2.close();

        Generator(p, path);
    }

    //Return Generator (g) of a safe prime (modulus) and write to file
    public static void Generator (BigInteger modulus, String path) throws FileNotFoundException, IOException
    {
        BigInteger g = BigInteger.ZERO;

        BufferedWriter output1 = new BufferedWriter(new FileWriter(path + "Host\\parameters.txt", true));
        BufferedWriter output2 = new BufferedWriter(new FileWriter(path + "Client\\parameters.txt", true));

        for (BigInteger i = BigInteger.valueOf(3); i.compareTo(modulus) < 0; i = i.add(BigInteger.ONE))
        {
            //Check if number is generator
            BigInteger check = i.modPow(((modulus.subtract(BigInteger.ONE)).divide(BigInteger.valueOf(2))), modulus);

            if(check.compareTo(BigInteger.ONE) != 0)
            {
                g = i;
                break;
            }    
        }

        output1.append(g.toString());
        output2.append(g.toString());

        output1.close();
        output2.close();    
    }

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
        //Create SecretKey Spec
        SecretKey sk = new SecretKeySpec(key.getBytes("UTF-8"), algorithm);
    
        // create an instance of cipher
        Cipher cipher = Cipher.getInstance(algorithm);
    
        // initialize the cipher with the key
        cipher.init(Cipher.ENCRYPT_MODE, sk);
    
        // encrypt
        byte[] encrypted = cipher.doFinal(toEncrypt.getBytes());
    
        return encrypted;
    }

    //Decryption of Ciphertext 
    public static String decrypt(byte[] toDecrypt, String key) throws Exception
    {
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
    
    //Key Exchange (Returns PK from Client)
    public static BigInteger keyExchange (BigInteger publicKey, String password)
    {
        BigInteger PKClient = BigInteger.ZERO;

        try
        {
            //Encrypt Public Key with RC4 (Testing)
            String PK = publicKey.toString();

            System.out.println("\nEncrypting PK...");
            byte[] encryptedPK = encrypt(PK, password);

            Thread.sleep(1000);
            System.out.println("Encrypted PK : " + encryptedPK);

            //Sending Encrypted PK to Client (Bob)
            System.out.println("\nSending Encrypted PK to Client (Bob)...");
            packet.setData(encryptedPK, 0, encryptedPK.length);
            socket.send(packet);
 
            //Receiving Encrypted PK from Client (Bob)
            Thread.sleep(1000);
            System.out.println("\nReceiving Encrypted PK from Client (Bob)...");
            packet = new DatagramPacket(new byte[512], 512);
            socket.receive(packet);
            byte[] trimPacket = trim(packet.getData());

            //Decrypting Client's PK
            System.out.println("\nDecrypting PK from Client (Bob)...");
            String clientPK = decrypt(trimPacket, password);

            Thread.sleep(1000);
            System.out.println("Client's PK : " + clientPK);

            //Convert Client's PK to BigInteger
            PKClient = new BigInteger(clientPK);

            
        }
        catch (Exception e) 
        {
            if (e instanceof NumberFormatException)
                PKClient = new BigInteger("1");
            else
            {
                System.out.println("Exception!");
			    e.printStackTrace(System.out);
            }
        }

        return PKClient;

    }
    
    public static void main(String[] args) throws Exception
    {
        try
        {
            socket = new DatagramSocket(1500);

            Scanner input = new Scanner(System.in);
            String message = "";

            Random rand = new Random();

            //Set path
            File file = new File("Host.java");
            String path = file.getCanonicalPath().toString();

            path = path.replace("Host.java", "");
            path = path.replace ("\\Host", "");

            //Establish modulus (p), generator (g), and parameters
            safePrime(32, path);
            initParams();  

            //Establish Host Secret Key
            System.out.println("\nEstablishing the Secret Key (SK)...");
            int secretKey = rand.nextInt(99999) + 1;

            //Check SK
            Thread.sleep(1000);
            System.out.println("Secret Key : " + secretKey);

            //Calculate Public Key
            System.out.println("\nCalculating the Public Key (PK)...");
            BigInteger publicKey = (g.pow(secretKey)).mod(p);

            //Check PK
            Thread.sleep(1000);
            System.out.println("Public Key : " + publicKey);

            //Receiving Bob's Connection Request
            System.out.println("\nWaiting for Client Request...");
			packet = new DatagramPacket(new byte[512],512);
            socket.receive(packet);

            System.out.println("\nConnection Request Received!");
             
            //Exchange Keys and Obtain PK from Client (Bob)
            BigInteger PKClient = keyExchange(publicKey, password);
            
            //Calculating Session Key (K)
            BigInteger keyToHash = (PKClient.pow(secretKey)).mod(p);

            //Establish Session Key using SHA-1
            System.out.println("\nEstablishing Session Key (SK)...");
            String sessionKey = SHA1(keyToHash.toString());

            Thread.sleep(1000);
            System.out.println("Session Key : " + sessionKey);

            //Start Thread 
            ThreadHost threadHost = new ThreadHost(socket, sessionKey);
            threadHost.start();

            //END OF STEP1

        
            //Send Message
            while (!message.equals("exit"))
            {
                System.out.print("\nEnter Message : ");
                message = input.nextLine();

                //Hash Session Key with Message ->  H = Hash(K||M)
                String hash1 = SHA1(sessionKey + message);

                //Compute ciphertext -> C = EK(M||H) 
                byte[] ciphertext = encrypt((message + hash1), sessionKey);

                //Send ciphertext to Client (Bob)
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
