import java.util.Scanner;

public class menu {

    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        String TITLE =
                "\n2910326 Computer Security Coursework\n"+
                        "by Jordan-Brannan & Nauman Iqbal\n\n"+
                "\t********************\n"+
                "\t1. Q1 (Rivest, Shamir, and Adelman) \n" +
                "\t2. Q2 (Needham-Schroeder Protocol)\n"+
                "\t0. Exit \n"+
                "\t********************\n\n"+
                "Please input a single digit (0-2):\n\n";
        System.out.println(TITLE);
        String answer = in.nextLine();
        if (answer.equals("1"))
        {
           rsa.rsaOptions();
        }
        else if (answer.equals("2"))
        {
            try{
                NSP.run();
            }
            catch(Exception e)
            {
                System.out.println("An error occurred.");
            }
        }
        else if (answer.equals("0"))
        {
            System.exit(0);
        }
    }
}
