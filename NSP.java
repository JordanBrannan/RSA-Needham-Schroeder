// package computersecurity;

import java.security.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import javax.crypto.*;
import java.util.Base64;
import java.util.Date;


//  NEEDHAM-SCHROEDER PROTOCOL
//      A -> S: A, B
//      S -> A: (Kb, B)Ks
//      A -> B: (nA, A)Kb
//      B -> S: B, A
//      S -> B: (Ka, A)Ks
//      B -> A: (nA, nB, B)Ka
//      A -> B: {nB}Kb
//
//  Verification Method
public class NSP {

    private static final String ALGORITHM = "RSA";
    private static final int KEYSIZE = 512;

    public static void keyPairGen(ArrayList<Key> keys) throws NoSuchAlgorithmException {

        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom pseudoRandom = new SecureRandom();
        pairGenerator.initialize(KEYSIZE, pseudoRandom);
        KeyPair keyPair = pairGenerator.generateKeyPair();
        Key publicKey  = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();

        keys.add(publicKey);
        keys.add(privateKey);
    }

    //Encrypt with RSA public key
    public static String encrypt(String message, Key publicKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        String cipherText = null;

        try {
            cipherText = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            System.exit(1);
        } catch (BadPaddingException e) {
            e.printStackTrace();
            System.exit(1);
        }

        return cipherText;

    }

    //Decrypt with RSA private key
    public static String decrypt(String cipherText, Key privateKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{

        byte[] decryptedMessage = new byte[cipherText.length()];

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        try {
            decryptedMessage = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return new String(decryptedMessage);


    }

    public static void run() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, SignatureException {

        ArrayList<Key> keys = new ArrayList<Key>();
        //  keys[0] : S public key
        //  keys[1] : S private key
        //  keys[2] : A public key
        //  keys[3] : A private key
        //  keys[4] : B public key
        //  keys[5] : B private key

        keyPairGen(keys);   //S (Server) : public - private
        keyPairGen(keys);   //A (Alice)  : public - private
        keyPairGen(keys);   //B (Bob)    : public - private

        System.out.println();
        String cipherText;
        String decryptedText;
        String[] source = {"Server", "Alice", "Bob"};

        //hypothetically this communication goes through an actual TCP/IP connection

        //STEP 1
        // A -> S: A, B
        System.out.println("A: Dear S, I would like to communicate with Bob");


        //STEP 2
        // S -> A: (Kb, B)Ks

        //Server signs a digital signature on cipherText
        Signature signature = Signature.getInstance("SHA256withRSA");

        PrivateKey serverPrivateKey = (PrivateKey) keys.get(1);
        signature.initSign(serverPrivateKey); //digital verification by Server

        //update digital signature with Bob's public key
        //sending Alice Bob's public key with digital signature (signed by Server)

        //Bob's public key
        byte[] bobPublicKey = keys.get(4).getEncoded();

        //read into update byte by byte
        int len = 0;
        while(len < bobPublicKey.length) {
            signature.update(bobPublicKey, 0, len);
            len++;
        }
        byte[] byteS_A = signature.sign();  //signed message send by S to A
        System.out.println("\nS: Here is B’s public key signed by me");


        //STEP 3
        // A -> B: (nA, A)Kb

//        //decrypt S_A
//        decryptedText = decrypt(S_A, keys.get(3));

        //VERIFICATION NEEDED THAT IT CAME FROM SERVER S
        //Server's public key is used by Alice to verify the digital signature
        PublicKey serverPublicKey = (PublicKey) keys.get(0);
        signature.initVerify(serverPublicKey);

        //read into update byte by byte
        len = 0;
        while(len < bobPublicKey.length) {
            signature.update(bobPublicKey, 0, len);
            len++;
        }

        System.out.println();
        System.out.println(signature.verify(byteS_A) ? "Verification: OK" : "Verification: NOT OK");
        //VERIFICATION ENDS

        //nA
        String ts = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        String nA = "Alice:" + ts;

        //Alice encrypts nA using Bob's public key
        cipherText = encrypt(nA, keys.get(4));

        System.out.println("A: Dear B, I have sent you a nonce only you can read");


        //STEP 4
        // B -> S: B, A
        decryptedText = decrypt(cipherText, keys.get(5));

        System.out.println();
        System.out.println(decryptedText);

        //Now Bob knows Alice is trying to communicate
        //So Bob requests Server for Alice's public key

        System.out.println("B: Dear S, I would like to get A’s public key");


        //STEP 5
        // S -> B: (Ka, A)Ks

        //Server signs a digital signature on cipherText
//        Signature signature = Signature.getInstance("SHA256withRSA");
//        PrivateKey serverPrivateKey = (PrivateKey) keys.get(1);

        signature.initSign(serverPrivateKey); //digital verification by Server

        //update digital signature with Alice's public key
        //sending Bob Alice's public key with digital signature (signed by Server)

        //Alice's public key
        byte[] alicePublicKey = keys.get(2).getEncoded();

        //read into update byte by byte
        len = 0;
        while(len < alicePublicKey.length) {
            signature.update(alicePublicKey, 0, len);
            len++;
        }
        byte[] byteS_B = signature.sign();  //signed message send by S to A
        System.out.println("\nS: Here is A’s public key signed by me");


        //STEP 6
        // B -> A: (nA, nB, B)Ka

        //Bob sends Alice nA (same as generated by Alice earlier), nB + B encrypted by Alice's public key

        //VERIFICATION NEEDED THAT IT CAME FROM SERVER S
        //Server's public key is used by Alice to verify the digital signature
        serverPublicKey = (PublicKey) keys.get(0);
        signature.initVerify(serverPublicKey);

        //read into update byte by byte
        len = 0;
        while(len < alicePublicKey.length) {
            signature.update(alicePublicKey, 0, len);
            len++;
        }

        System.out.println();
        System.out.println(signature.verify(byteS_B) ? "Verification: OK" : "Verification: NOT OK");
        //VERIFICATION ENDS

        //nB
        ts = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        String nB = "Bob:" + ts;

        //encrypt nB using Alice's public key
        cipherText = encrypt(nB, keys.get(2));

        //nA (plain) + cipherText (encrypted nB + B) is send to Alice
        System.out.println("B: Here is my nonce and yours, proving I decrypted it");


        //STEP 7
        // A -> B: {nB}Kb
        // A confirms nB to B, proving her ability to decrypt

        //Alice decrypts using her private key
        decryptedText = decrypt(cipherText, keys.get(3));

        System.out.println();
        System.out.println(decryptedText);

        System.out.println("A: Here is your nonce proving I decrypted it");

    }


}
