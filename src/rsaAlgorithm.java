import java.math.BigInteger;
import java.util.Random;
import java.util.*;
import java.io.*;
import java.util.Scanner;
import java.io.PrintWriter;

public class rsaAlgorithm{

    // Class Variables for Encryption
    private static BigInteger p;
    private static BigInteger q;
    private static BigInteger n;
    private static BigInteger phi;
    private static BigInteger k;
    private static BigInteger d;

    // Class HashMaps for Characters
    private static Map<Character, String> mappingN = new HashMap<Character, String>();
    private static Map<Integer, Character> mappingM = new HashMap<Integer, Character>();

    // --- Generate a public and private key ---
    public static void generateKeys() {
        // Generate two random large prime numbers
        p = BigInteger.probablePrime(1024, new Random());
        q = BigInteger.probablePrime(1024, new Random());
        // Formula for N
        n = p.multiply(q);
        // Formula for Phi
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        // Formula for K
        k = BigInteger.probablePrime(512, new Random());
        // Ensure that no common denominators
        while (phi.gcd(k).compareTo(BigInteger.ONE) > 0 && k.compareTo(phi) < 0) {
            k.add(BigInteger.ONE);
        }
        // Formula for D
        d = k.modInverse(phi);
    }

    // --- Write files with generated keys ---
    public static void keysToFile(){
        Scanner in = new Scanner(System.in);
        // Take name input to write private and public keys to file
        System.out.println("Enter your name to generate keys:");
        String userName = in.nextLine();
        // Write keys to file
        try {
            PrintWriter writer = new PrintWriter(userName+"-pb.txt", "UTF-8");
            writer.println(k + " " + n);
            PrintWriter writer2 = new PrintWriter(userName+"-pv.txt", "UTF-8");
            writer2.println(d + " " + n);
            writer.close();
            writer2.close();
            writer.flush();
            writer2.flush();
        }
        catch(Exception e)
        {
            System.out.println("Error writing message to file");
        }
    }

    // --- Hashmap for Encrypting ---
    private static void map1()
    {
        int base = 100;
        int temp;
        String tempString;
        for (int i = 0; i < 127; i++)
        {
            char a = (char) i;
            temp  = base + i;
            tempString = String.valueOf(temp);
            mappingN.put(a, tempString);
        }
    }

    // --- Hashmap for Decrypting ---
    private static void map2()
    {
        int base = 100;
        int temp;
        for (int i = 0; i < 127; i++)
        {
            char a = (char) i;
            temp = base + i;
            mappingM.put(temp, a);
        }
    }

    // --- Get Encryption Code from Hashmap ---
    public static String encryptCode(String message) {
        map1();
        char tempChar;
        String newString = "";
        // Add to string each characters numeric value from Hashmap
        for (int i = 0; i < message.length(); i++) {
            tempChar = message.charAt(i);
            newString += mappingN.get(tempChar);
        }
        return newString;
    }

    // --- Get encrypted code and convert to string using public key ---
    public static BigInteger encryptString(String newString) {
        String line;
        String pubkey = "";
        Scanner in = new Scanner(System.in);
        System.out.println("Enter the file name with the public key (Without the file extension):");
        String publicKeyTxt = in.nextLine();

        try {
            FileReader fileReader = new FileReader(publicKeyTxt + ".txt");
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            while ((line = bufferedReader.readLine()) != null) {
                pubkey += line;
            }
            bufferedReader.close();
        } catch (FileNotFoundException ex) {
            System.out.println("Unable to open file '" + publicKeyTxt + "'");
        } catch (IOException ex) {
            System.out.println("Error reading file '" + publicKeyTxt + "'");
        }
        // Store each part of public key in string array
        String[] splitPubKey = pubkey.split("[\\p{Punct}\\s]+");
        BigInteger kNew = new BigInteger(splitPubKey[0]);
        BigInteger nNew = new BigInteger(splitPubKey[1]);
        // Create encrypted integer by modulus power method using values from Hashmap
        BigInteger returnInt = new BigInteger(newString).modPow(kNew, nNew);
        return returnInt;
    }

    // --- Write encrypted string to file ---
    public static void encryptToFile(BigInteger returnInt){
        Scanner in = new Scanner(System.in);
        System.out.println("Enter a name for the encrypted message file (e.g. testing).\n" +
                "The file extension will automatically be amended.");
        String encryptMessTxt = in.nextLine();

        try {
            PrintWriter writer = new PrintWriter(encryptMessTxt + ".txt", "UTF-8");
            writer.println(returnInt);
            writer.close();
        }
        catch(Exception e)
        {
            System.out.println("Error writing message to file");
        }
        return;
    }

    // --- Get string from file and convert to Big Integer ---
    public static BigInteger decryptGetMess() {
        map2();
        Scanner in = new Scanner(System.in);

        String lineOne;
        String encryptedMess = "";

        System.out.println("Enter the file name to decrypt (Without the file extension):");
        String decryptTxt = in.nextLine();
        // Read string from encrypted file
        try {
            FileReader fileReader = new FileReader(decryptTxt + ".txt");
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            while ((lineOne = bufferedReader.readLine()) != null) {
                encryptedMess += lineOne;
            }
            bufferedReader.close();
        } catch (FileNotFoundException ex) {
            System.out.println("Unable to open file '" + decryptTxt + "'");
        } catch (IOException ex) {
            System.out.println("Error reading file '" + decryptTxt + "'");
        }
        // Convert encrypted string to Big Integer
        BigInteger encryptedBigInt = new BigInteger(encryptedMess);
        return encryptedBigInt;
    }

    // --- Get private key from file ---
    public static String[] decryptGetPrivate()
    {
        String lineTwo;
        String privkey = "";
        Scanner in = new Scanner(System.in);
        System.out.println("Enter the file name with the private key (Without the file extension):");
        String publicKeyTxt = in.nextLine();
        // Read string of private key from file
        try {
            FileReader fileReader = new FileReader(publicKeyTxt + ".txt");
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            while ((lineTwo = bufferedReader.readLine()) != null) {
                privkey += lineTwo;
            }
            bufferedReader.close();
        } catch (FileNotFoundException ex) {
            System.out.println("Unable to open file '" + publicKeyTxt + "'");
        } catch (IOException ex) {
            System.out.println("Error reading file '" + publicKeyTxt + "'");
        }
        // Split each part of private string
        String[] splitPrivKey = privkey.split("[\\p{Punct}\\s]+");
        return(splitPrivKey);
    }

    // --- Decrypt encrypted Big Integer to text ---
    public static String decryptGetString (String[] splitPrivKey, BigInteger encryptedBigInt)
    {
        BigInteger dNew = new BigInteger(splitPrivKey[0]);
        BigInteger nNew = new BigInteger(splitPrivKey[1]);
        // Reverse the encryption to the Hashmap values
        BigInteger returnString = encryptedBigInt.modPow(dNew, nNew);
        String decryptMess = returnString.toString();

        String temp2;
        String newString = "";
        // Get characters for each value from encrypted big integer
        for (int i = 0; i < (decryptMess.length() - 2); i += 3) {
            temp2 = Character.toString(decryptMess.charAt(i));
            temp2 += Character.toString(decryptMess.charAt(i + 1));
            temp2 += Character.toString(decryptMess.charAt(i + 2));
            int tempInt = Integer.parseInt(temp2);
            newString += mappingM.get(tempInt);
        }
        return newString;
    }

    // --- Write decrypted message to file ---
    public static void decryptToFile(String newString)
    {
        Scanner in = new Scanner(System.in);
        System.out.println("Enter a name for the decrypted message file (e.g. testing).\n" +
                "The file extension will automatically be amended.");
        String decryptMessTxt = in.nextLine();
        // Write string to file
        try {
            PrintWriter writer = new PrintWriter(decryptMessTxt + ".txt", "UTF-8");
            writer.println(newString);
            writer.close();
        }
        catch(Exception e)
        {
            System.out.println("Error writing message to file");
        }
        return;
    }

    // --- Demo of regular use of RSA ---
    public static void regDemo()
    {
        // Generate keys
        System.out.println("This is a demonstration of how this encryption can work with Alice & Bob.");
        System.out.println("Firstly, lets generate Alice's keys.");
        generateKeys();
        BigInteger aliceK = k;
        BigInteger aliceN = n;
        BigInteger aliceD = d;
        System.out.println("Alice's private and public keys have been generated.");
        System.out.println("Secondly, lets generate Bob's keys.");
        generateKeys();
        BigInteger bobK = k;
        BigInteger bobN = n;
        BigInteger bobD = d;
        System.out.println("Bob's private and public keys have been generated.\n");
        System.out.println("\t********************\n");

        // Send message from Alice to Bob
        System.out.println("We now have Alice and Bob's private and public keys. Let's assume that they have both exchanged public keys.");
        System.out.println("Assuming Alice has Bob's public key, Alice then encrypts a message using Bob's public key. (E.g. 'Hello Bob!')");
        String message = "Hello Bob!";
        String newString = encryptCode(message);
        BigInteger returnInt = new BigInteger(newString).modPow(bobK, bobN);
        System.out.println("Alice's message has now been encrypted like so:");
        System.out.println(returnInt);
        System.out.println("Alice then sends this encrypted message to Bob. Bob can now decrypt this message using his private key.");
        String[] privKey = new String[2];
        privKey[0] = bobD.toString();
        privKey[1] = bobN.toString();
        map2();
        String deString = decryptGetString(privKey, returnInt);
        System.out.println("Bob has now decrypted Alice's message and received: " + deString);
        System.out.println("The message has now passed from Alice to Bob securely.\n");
        System.out.println("\t********************\n");

        // Send message from Bob to Alice
        System.out.println("Bob can then send a message back to Alice (E.g. 'Hello Alice!')");
        String message2 = "Hello Alice!";
        String newString2 = encryptCode(message2);
        BigInteger returnInt2 = new BigInteger(newString2).modPow(aliceK, aliceN);
        System.out.println("Bob's message has now been encrypted like so:");
        System.out.println(returnInt2);
        System.out.println("Bob then sends this encrypted message to Alice. Alice can now decrypt this message using her private key.");
        String[] privKey2 = new String[2];
        privKey2[0] = aliceD.toString();
        privKey2[1] = aliceN.toString();
        map2();
        String deString2 = decryptGetString(privKey2, returnInt2);
        System.out.println("Alice has now decrypted Bob's message and received: " + deString2);
        System.out.println("The message has now passed from Bob to Alice securely.\n");
        System.out.println("\t********************\n");
    }

    // --- Demo of Man in the Middle attack ---
    public static void atkDemo()
    {
        // Generate keys
        System.out.println("This is a demonstration of a man in the middle attack with Alice, Bob & Charlie.");
        System.out.println("Firstly, lets generate Alice's keys.");
        generateKeys();
        BigInteger aliceK = k;
        BigInteger aliceN = n;
        BigInteger aliceD = d;
        System.out.println("Alice's private and public keys have been generated.");
        System.out.println("Secondly, lets generate Bob's keys.");
        generateKeys();
        BigInteger bobK = k;
        BigInteger bobN = n;
        BigInteger bobD = d;
        System.out.println("Bob's private and public keys have been generated.");
        System.out.println("Thirdly, lets generate Charlie's keys.");
        generateKeys();
        BigInteger charlieK = k;
        BigInteger charlieN = n;
        BigInteger charlieD = d;
        System.out.println("Charlie's private and public keys have been generated.");
        System.out.println("We now have Alice, Bob and Charlie's private and public keys.\n");
        System.out.println("\t********************\n");

        // Message from Alice to Charlie
        System.out.println("Now, when Alice and Bob are exchanging public keys, if Charlie intercepts this exchange, " +
                "he can then pass his public keys to one another instead of theirs.");
        System.out.println("Alice then wants to send a message to Bob but has Charlies public key when she thinks it's Bobs.\n" +
                "She then sends the message 'Hello Bob!' and encrypts it using Charlies public key.");
        String message = "Hello Bob!";
        String newString = encryptCode(message);
        BigInteger returnInt = new BigInteger(newString).modPow(charlieK, charlieN);
        System.out.println("Alice's message has now been encrypted like so:");
        System.out.println(returnInt);
        System.out.println("Alice then sends this encrypted message and Charlie receives it. Charlie can now decrypt this message using his private key.");
        String[] privKey = new String[2];
        privKey[0] = charlieD.toString();
        privKey[1] = charlieN.toString();
        map2();
        String deString = decryptGetString(privKey, returnInt);
        System.out.println("Charlie has now decrypted Alice's message and received: " + deString);
        System.out.println("The message has now passed from Alice to Charlie.\n");
                System.out.println("\t********************\n");

        // Message from Charlie to Bob
        System.out.println("Charlie then re-encrypts it using Bob's public key and makes a change in the message.");
        String message2 = "I hate you Bob!";
        String newString2 = encryptCode(message2);
        BigInteger returnInt2 = new BigInteger(newString2).modPow(bobK, bobN);
        System.out.println("Alice's message has now been encrypted like so:");
        System.out.println(returnInt2);
        System.out.println("Charlie then sends this encrypted message and Bob receives it. Bob can now decrypt this message using his private key.");
        String[] privKey2 = new String[2];
        privKey2[0] = bobD.toString();
        privKey2[1] = bobN.toString();
        String deString2 = decryptGetString(privKey2, returnInt2);
        System.out.println("Bob has now decrypted Charlie's message thinking it was from Alice and received: " + deString2);
        System.out.println("The message now passed from Alice to Charlie to Bob.\n");
        System.out.println("\t********************\n");

        // Message from Bob to Charlie
        System.out.println("Bob then wants to send a message back to Alice but also has Charlies public key when he think's it's Charlie's.\n" +
                "He then sends the message 'Have I upset you?' and encrypts it using Charlies public key.");
        String message3 = "Have I upset you?";
        String newString3 = encryptCode(message3);
        BigInteger returnInt3 = new BigInteger(newString3).modPow(charlieK, charlieN);
        System.out.println("Bob's message has now been encrypted like so:");
        System.out.println(returnInt);
        System.out.println("Bob then sends this encrypted message and Charlie receives it. Charlie can now decrypt this message using his private key.");
        String[] privKey3 = new String[2];
        privKey3[0] = charlieD.toString();
        privKey3[1] = charlieN.toString();
        String deString3 = decryptGetString(privKey3, returnInt3);
        System.out.println("Charlie has now decrypted Bob's message and received: " + deString3);
        System.out.println("The message has now passed from Bob to Charlie.\n");
        System.out.println("\t********************\n");

        // Message from Charlie to Alice
         System.out.println("Charlie then re-encrypts it using Alice's public key and makes a change in the message.");
        String message4 = "I hate you too Alice!";
        String newString4 = encryptCode(message4);
        BigInteger returnInt4 = new BigInteger(newString4).modPow(aliceK, aliceN);
        System.out.println("Charlie's new message has now been encrypted like so:");
        System.out.println(returnInt4);
        System.out.println("Charlie then sends this encrypted message and Alice receives it. Alice can now decrypt this message using her private key.");
        String[] privKey4 = new String[2];
        privKey4[0] = aliceD.toString();
        privKey4[1] = aliceN.toString();
        String deString4 = decryptGetString(privKey4, returnInt4);
        System.out.println("Alice has now decrypted Charlie's message thinking it was from Bob and received: " + deString4);
        System.out.println("The message has now passed from Bob to Charlie to Alice.\n");
        System.out.println("\t********************\n");
    }
}