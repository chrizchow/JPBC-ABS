package hk.chriz;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import javax.sound.midi.SysexMessage;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Main {

    private Pairing pairing;
    private Field G1, G2, Gt, Zr;
    private Element x;              // master key
    private Element g, g1, g2, Z;   // public elements

    private Element sigma0, sigma_prime;          // signature
    ArrayList<Element> sigma_is;                  // signature

    // Attributes
    //String [] attrs = { "one" };
    String [] attrs = { "one", "two" };
    private int d = attrs.length + 1;       // (d-1) attributes = (d-1) polynomial degree = d points

    // Private Key for testing:
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

        // Set x = random with Z*r (it must be co-prime with n):
        do { x = Zr.newRandomElement();
        } while (x.toBigInteger().gcd(r).compareTo(BigInteger.ONE) != 0);

        // Set g1 = g^x:
        g1 = g.duplicate();
        g1.powZn(x);

        // Set g2 = random:
        g2 = G1.newRandomElement();

        // Set Z = e(g1, g2):
        Z = pairing.pairing(g1, g2);

    }

    // ============================ Check ============================
    private void checkup() {
        System.out.println("============== Parameters Check ==============");
        System.out.println("G1: "+G1);
        System.out.println("G2: "+G2);
        System.out.println("Gt: "+Gt);
        System.out.println("Zr: "+Zr);
        System.out.println("x: "+x+" (Master Key)");
        System.out.println("g: "+g);
        System.out.println("g1: "+g1);
        System.out.println("g2: "+g2);
        System.out.println("Z: "+Z);
        System.out.println("=============================================\n");
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
            comps.add(comp);

            // show debug message:
            System.out.println("attr = "+comp.attr);
            System.out.println("q("+i+") = "+comp.qi);
            System.out.println("d"+i+"0 = "+comp.di0);
            System.out.println("d"+i+"1 = "+comp.di1+"\n");
        }
        privKey = comps;
        System.out.println("=============================================\n"); // debug
    }

    // ====================== Signature ======================
    private static void lagrangeCoef(Element r, ArrayList<BigInteger> s, BigInteger i) {

        Element t = r.duplicate();
        r.setToOne();
        for (int k = 0; k < s.size(); k++) {
            BigInteger j = s.get(k);            // η (eta)
            if (j.equals(i))
                continue;
            t.set(BigInteger.ZERO.subtract(j)); // t = -η
            r.mul(t);                           // r = -η
            t.set(i.subtract(j));               // t = i-η
            t.invert();                         // t = 1/(i-η)
            r.mul(t);                           // r = -η/(i-η)
        }
    }

    public void sign(String message, ArrayList<ABSPrivKeyComp> privKey) throws NoSuchAlgorithmException {

        // Proposition:
        // To prove having at least k attributes among n-elements.
        // since we want to make sure all attributes (d-1) are there,
        // we set threshold (k = d - 1) and (n = d - 1).

        // omega prime = ( d - k ) = ( d - k + 1 ) = 1
        // choose ( n + d - k ) = n + 1 = d random values

        // generate random s:
        Element s = Zr.newRandomElement();

        // calculate first part of σ0:
        Element pi_di0_pow_delta = G2.newElement(1);
        ArrayList<Element> deltas = new ArrayList<>();

        // get the polynomial list:
        ArrayList <BigInteger> poly = new ArrayList<>();
        for (int i=0; i<privKey.size(); i++) {
            poly.add(privKey.get(i).qi.toBigInteger());
            System.out.println("inserted: "+poly.get(i));
        }

        // run the lagrange:
        for (int i=0; i<privKey.size(); i++) {
            // calculate ∆i,S(0) (aka delta):
            Element delta = Zr.newElement();
            lagrangeCoef(delta, poly, privKey.get(i).qi.toBigInteger());
            System.out.println("∆i,S("+i+"): "+delta);
            deltas.add(delta); // save for later use
            // Power di_0 with delta:
            Element di_0_pow_delta = privKey.get(i).di0.duplicate();
            di_0_pow_delta.powZn(delta);
            System.out.println("d"+i+"0^(∆i,S("+i+")): "+di_0_pow_delta);
            // multiply to pi:
            pi_di0_pow_delta.mul(di_0_pow_delta);
        }

        System.out.println();

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

        // calculate the third part of σ0 (H2(m)^s):
        Element h2ms = G1.newElement();
        elementFromString(h2ms, message);
        h2ms.powZn(s);
        System.out.println("H2(m)^s = "+h2ms);

        // calculate σ0:
        sigma0 = G2.newElement();
        sigma0.set(pi_di0_pow_delta);
        sigma0.mul(pi_hashed_pow_rp);
        sigma0.mul(h2ms);
        System.out.println("σ0 = "+sigma0);
        System.out.println();

        // calculate σi:
        sigma_is = new ArrayList<>();
        for (int i=0; i<privKey.size(); i++) {
            Element sigma_i = G1.newElement();
            // Power di_1 with delta:
            Element di_1_pow_delta = G2.newElement(privKey.get(i).di1);
            di_1_pow_delta.powZn(deltas.get(i));
            // Power g with r':
            Element g_pow_rp = G1.newElement(g);
            g_pow_rp.powZn(r_primes.get(i));
            // multiply to get sigma_i:
            sigma_i.set(di_1_pow_delta);
            sigma_i.mul(g_pow_rp);
            System.out.println("σ"+i+" = "+sigma_i);
            sigma_is.add(sigma_i);  // save for later use
        }
        System.out.println();

        // calculate σ':
        sigma_prime = g.duplicate();
        sigma_prime.powZn(s);
        System.out.println("σ' = "+sigma_prime);

    }

    // ====================== Verification ======================
    public void verify(String message) throws NoSuchAlgorithmException {
        // calculate e(g, σ0):
        Element numerator = pairing.pairing(g, sigma0);
        // calculate pi(e(H(i), σi)):
        Element pi_hi_sigmai_pair = Gt.newElement();
        pi_hi_sigmai_pair.setToOne();
        for (int i=0; i<attrs.length; i++) {
            // calculate H(i):
            Element hashed = G1.newElement();
            elementFromString(hashed, attrs[i]);
            // calculate e(H(i), σi):
            Element hi_sigmai_pair = pairing.pairing(hashed, sigma_is.get(i));
            // multiply to pi:
            pi_hi_sigmai_pair.mul(hi_sigmai_pair);
        }
        // calculate e(H(m), σ'0):
        Element hashed_message = G1.newElement();
        elementFromString(hashed_message, message);
        Element denominator = pairing.pairing(hashed_message, sigma_prime);
        // multiply together to get pi(e(H(i), σi))*e(H(m), σ'0):
        denominator.mul(pi_hi_sigmai_pair);

        // result of numerator/denominator:
        Element Z_prime = numerator.duplicate();
        Z_prime.div(denominator);
        System.out.println("Z' = "+Z_prime);
        System.out.println("Z  = "+Z);

    }

    public static void main (String [] args) throws Exception {
        String message = "Hello World";
        System.out.println(message);
        Main object = new Main();
        object.setup();
        object.checkup();

        System.out.println("==============");
        object.extract(object.attrs);
        System.out.println("Private Key Generated\n");

        System.out.println("==============");
        object.sign(message, object.privKey);
        System.out.println("Signature Generated\n");

        System.out.println("==============");
        object.verify(message);
        System.out.println("Signature Verified\n");

    }
}
