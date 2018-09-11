import java.math.BigInteger;
import java.util.Scanner;

public class rsa {

    public static void rsaOptions()
    {
        Scanner in = new Scanner(System.in);
        System.out.println("Would you like to generate keys, encrypt a message, decrypt a message or view a demo?\n");
        System.out.println("\t********************");
        System.out.println("\t1. Generate keys.");
        System.out.println("\t2. Encrypt a message.");
        System.out.println("\t3. Decrypt a message.");
        System.out.println("\t4. Regular demo between two people.");
        System.out.println("\t5. Man in the middle Demo.");
        System.out.println("\t0. Exit.");
        System.out.println("\t********************\n");
        System.out.println("Please input a single digit (0-5):\n\n");
        String answer = in.nextLine();
        String tempstring;

        if(answer.equals("1"))
        {
            rsaAlgorithm.generateKeys();
            rsaAlgorithm.keysToFile();
        }
        else if(answer.equals("2"))
        {
            System.out.println("Enter the plain text:");
            tempstring = in.nextLine();
            String newString = rsaAlgorithm.encryptCode(tempstring);
            BigInteger returnInt = rsaAlgorithm.encryptString(newString);
            rsaAlgorithm.encryptToFile(returnInt);
        }
        else if(answer.equals("3"))
        {
            BigInteger encryptBigInt = rsaAlgorithm.decryptGetMess();
            String[] splitKey = rsaAlgorithm.decryptGetPrivate();
            String newString = rsaAlgorithm.decryptGetString(splitKey, encryptBigInt);
            rsaAlgorithm.decryptToFile(newString);
        }
        else if(answer.equals("4"))
        {
            rsaAlgorithm.regDemo();
        }
        else if(answer.equals("5"))
        {
            rsaAlgorithm.atkDemo();
        }
        else if(answer.equals("0"))
        {
            System.exit(0);
        }
        else
        {
            System.out.println("Invalid Option");
        }
    }
}
