package hk.chriz;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Main {

    private Pairing pairing;
    private Field G1, G2, Gt, Zr;
    private Element x;              // master key
    private Element g, g1, g2, Z;   // public elements
    private int d;                  // (d-1) polynomial degree (d attributes)

    BigInteger r = new BigInteger("730750818665451621361119245571504901405976559617");

    // ====================== Initialise ======================
    public void setup() {

        // Initialise Pairing and its Parameters
        pairing = PairingFactory.getPairing("a.properties"); // read parameters from file
        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        // just for convenience:
        G1 = pairing.getG1();
        G2 = pairing.getG2();
        Gt = pairing.getGT();
        Zr = pairing.getZr();

        // Set g = random generator:
        g = G1.newRandomElement();

        // Set x = random with Z*r (elements co-prime with n):
        do {
            x = Zr.newRandomElement();
            System.out.println("Calculating x.gcd(r) = "+x.toBigInteger().gcd(r));
        } while (x.toBigInteger().gcd(r).compareTo(BigInteger.ONE) != 0);

        // Set g1 = g^x:
        g1 = g.duplicate();
        g1.powZn(x);

        // Set g2 = random:
        g2 = G1.newRandomElement();

        // Set Z = e(g1, g2):
        Z = pairing.pairing(g1, g2);

    }

    // ============================ Keygen ============================
    private static void elementFromString(Element h, String s)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

    public void keygen(String [] attrs) throws NoSuchAlgorithmException {
        extract(attrs);
    }

    public void extract(String [] attrs) throws NoSuchAlgorithmException {
        ArrayList<ABSPrivKeyComp> comps = new ArrayList<>();

        for (int i=0; i<attrs.length; i++)
        {
            ABSPrivKeyComp comp = new ABSPrivKeyComp();
            Element hashed = G2.newElement();
            Element ri = Zr.newRandomElement();

            // Set q(0) = x, q(i) to random:
            comp.qi = Zr.newElement();
            if (i == 0) comp.qi.set(x);
            else comp.qi.setToRandom();

            // Save attr for future reference:
            comp.attr = attrs[i];

            // Set di0 = g2^(q(i))*(H(i))^(ri), where ri is random:
            comp.di0 = G2.newElement();
            comp.di0.set(g2);
            comp.di0.powZn(comp.qi);
            elementFromString(hashed, attrs[i]);
            hashed.powZn(ri);
            comp.di0.mul(hashed);

            // Set di1 = g^ri, where ri is random:
            comp.di1 = G1.newElement();
            comp.di1.set(g);
            comp.di1.powZn(ri);

        }

    }

    public static void main (String args[]) throws Exception {
        System.out.println("Hello World");

        Main object = new Main();
        object.setup();
        System.out.println(object.x.toBigInteger());

        object.d = 2;
        String [] attrs = { "one", "two" };
        object.extract(attrs);
    }
}
