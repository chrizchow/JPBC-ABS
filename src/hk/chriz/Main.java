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

    private Element sigma0, h2ms, sigma_prime;    // signature
    ArrayList<Element> sigma_is;                  // signature

    // Private Key for testing:
    private int d = 3;              // (d-1) polynomial degree (d attributes)
    String [] attrs = { "one", "two", "three" };
    private ArrayList<ABSPrivKeyComp> privKey;

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
            System.out.println("qi = "+comp.qi);

            // Save attr for future reference:
            comp.attr = attrs[i];

            // Set di0 = g2^(q(i))*(H(i))^(ri), where ri is random:
            comp.di0 = G2.newElement();
            comp.di0.set(g2);
            comp.di0.powZn(comp.qi);
            elementFromString(hashed, attrs[i]);
            hashed.powZn(ri);
            comp.di0.mul(hashed);
            System.out.println("di0 = "+comp.di0);

            // Set di1 = g^ri, where ri is random:
            comp.di1 = G1.newElement();
            comp.di1.set(g);
            comp.di1.powZn(ri);
            comps.add(comp);
            System.out.println("di1 = "+comp.di1+"\n");
        }
        privKey = comps;
    }

    public void sign(String message, ArrayList<ABSPrivKeyComp> privKey) throws NoSuchAlgorithmException {

        // Proposition:
        // To prove having at least k attributes among n-elements.
        // since we want to make sure all attributes (d-1) are there,
        // we set threshold (k = d - 1) and (n = d - 1).

        // omega prime = ( d - k ) = ( d - k + 1 ) = 1
        // choose ( n + d - k ) = n + 1 = d random values

        // calculate first part of σ0:
        Element pi_di0_pow_delta = G2.newElement(1);
        ArrayList<BigInteger> deltas = new ArrayList<>();
        for (int i=0; i<privKey.size(); i++)
        {
            // calculate delta (Lagrange coefficient):
            BigInteger delta_iS0 = BigInteger.ONE;
            for (int eta=0; eta<privKey.size(); eta++)
            {
                if (i != eta){    // make sure eta element is not j
                    BigInteger etaValue = privKey.get(eta).qi.toBigInteger();
                    BigInteger numerator = BigInteger.ZERO.subtract(etaValue);
                    BigInteger denominator = privKey.get(i).qi.toBigInteger().subtract(etaValue);
                    delta_iS0 = delta_iS0.multiply(numerator.divide(denominator));
                    System.out.println("etaValue = "+etaValue);
                    System.out.println("delta_iS0 = "+delta_iS0);
                    deltas.add(delta_iS0);  // save for later use
                }
            }
            // Power di_0 with delta:
            Element di_0_pow_delta = G2.newElement(privKey.get(i).di0);
            di_0_pow_delta.pow(delta_iS0);
            // multiply to pi:
            pi_di0_pow_delta.mul(di_0_pow_delta);
            System.out.println("pi_di0_pow_delta = "+pi_di0_pow_delta+"\n");
        }

        // calculate the second part of σ0:
        Element pi_hashed_pow_rp = G2.newElement();
        ArrayList<Element> r_primes = new ArrayList<>();
        for (int i=0; i<privKey.size(); i++) {
            // calculate hash:
            Element hashed = G2.newElement();
            elementFromString(hashed, privKey.get(i).attr);
            // generate random r':
            Element r_prime = Zr.newRandomElement();
            r_primes.add(r_prime);  // for later use
            // Power hash with r':
            Element hashed_pow_rp = G2.newElement(hashed);
            hashed_pow_rp.powZn(r_prime);
            // multiply to pi:
            pi_hashed_pow_rp.mul(hashed_pow_rp);
        }

        // calculate σ0:
        sigma0 = G2.newElement();
        sigma0.set(pi_di0_pow_delta);
        sigma0.mul(pi_hashed_pow_rp);
        System.out.println("σ0 = "+sigma0);

        // generate random s:
        Element s = Zr.newRandomElement();
        h2ms = G2.newElement();

        // calculate H2(m)^s:
        elementFromString(h2ms, message);
        h2ms.powZn(s);
        System.out.println("h2ms = "+h2ms+"\n");

        // calculate σi:
        sigma_is = new ArrayList<>();
        for (int i=0; i<privKey.size(); i++) {
            Element sigma_i = G1.newElement();
            // Power di_1 with delta:
            Element di_1_pow_delta = G2.newElement(privKey.get(i).di1);
            di_1_pow_delta.pow(deltas.get(i));
            // Power g with r':
            Element g_pow_rp = G1.newElement(g);
            g_pow_rp.powZn(r_primes.get(i));
            // multiply to get sigma_i:
            sigma_i.mul(di_1_pow_delta);
            sigma_i.mul(g_pow_rp);
            System.out.println("σ"+i+" = "+sigma_i+"\n");
        }

        // calculate σ':
        sigma_prime = G1.newElement(g);
        sigma_prime.powZn(s);
        System.out.println("σ' = "+sigma_prime);

    }

    public static void main (String args[]) throws Exception {
        System.out.println("Hello World\n");

        Main object = new Main();
        object.setup();
        System.out.println("Master Key: " + object.x.toBigInteger()+"\n");

        object.extract(object.attrs);
        System.out.println("Private Key Generated\n");

        object.sign("I go to school by bus", object.privKey);
        System.out.println("Signature Generated");

    }
}
