package hk.chriz;
import java.util.ArrayList;

public class Main {

    public static void main (String [] args) throws Exception {

        // Attribute Based Signature Instance:
        ABS abs = new ABS();

        // Attributes:
        //String [] attrs = { "apple" };
        //String [] attrs = { "apple", "orange" };
        String [] attrs = { "apple", "orange", "peach" };

        // Message:
        String message = "Hello World";
        System.out.println(message);

        // Initialise:
        abs.setup();
        abs.printParameters();
        System.out.println("=== Setup Completed ===\n");

        // Extract Private Key:
        ArrayList<ABSPrivKeyComp> privKey = abs.extract(attrs);
        System.out.println("=== Private Key Extracted ===\n");

        // Generate Signature based on message:
        ABSSignatureComp signature = abs.sign(message, privKey);
        System.out.println("=== Signature Generated ===\n");

        // Verify signature based on attributes and message:
        abs.verify(message, attrs, signature);
        System.out.println("=== Signature Verified ===\n");

    }
}
