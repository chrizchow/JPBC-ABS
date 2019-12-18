package hk.chriz;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.lang.annotation.ElementType;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class ABS {

    private ABSPubKeyComp pubParam;   // Public Key Parameters
    private Element x;                // Master Key

    public void setup() {

        // Prevent initialising more than once:
        if (pubParam != null && x != null) {
            System.out.println("Setup has already run before!");
            return;
        }

        // Initialise Pairing and its Parameters:
        pubParam = new ABSPubKeyComp();
        pubParam.pairing = PairingFactory.getPairing("a.properties"); // read parameters from file
        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        // just for convenience:
        pubParam.G1 = pubParam.pairing.getG1();
        pubParam.G2 = pubParam.pairing.getG2();
        pubParam.Gt = pubParam.pairing.getGT();
        pubParam.Zr = pubParam.pairing.getZr();

        // Set g = random generator:
        pubParam.g = pubParam.G1.newRandomElement();

        // Set master key x = random with Z*r (it must be co-prime with n):
        do { x = pubParam.Zr.newRandomElement();
        } while (x.toBigInteger().gcd(pubParam.r).compareTo(BigInteger.ONE) != 0);

        // Set g1 = g^x:
        pubParam.g1 = pubParam.g.duplicate();
        pubParam.g1.powZn(x);

        // Set g2 = random:
        pubParam.g2 = pubParam.G1.newRandomElement();

        // Set Z = e(g1, g2):
        pubParam.Z = pubParam.pairing.pairing(pubParam.g1, pubParam.g2);

    }

    public ArrayList<ABSPrivKeyComp> extract(String [] attrs) throws NoSuchAlgorithmException {
        ArrayList<ABSPrivKeyComp> comps = new ArrayList<>();
        for (int i=0; i<attrs.length; i++) {

            // Initialise elements:
            ABSPrivKeyComp comp = new ABSPrivKeyComp();
            Element hashed = pubParam.G2.newElement();
            Element ri = pubParam.Zr.newRandomElement();

            // Set polynomial which q(0)=x, q(i)=random:
            comp.qi = pubParam.Zr.newElement();
            if (i == 0) comp.qi.set(x);
            else comp.qi.setToRandom();

            // Save attr for future reference:
            comp.attr = attrs[i];

            // Set di0 = g2^(q(i))*(H(i))^(ri), where ri is random:
            comp.di0 = pubParam.g2.duplicate();
            comp.di0.powZn(comp.qi);
            elementFromString(hashed, attrs[i]);
            hashed.powZn(ri);
            comp.di0.mul(hashed);

            // Set di1 = g^ri, where ri is random:
            comp.di1 = pubParam.g.duplicate();
            comp.di1.powZn(ri);
            comps.add(comp);

            // show debug message:
            System.out.println("attr = "+comp.attr);
            System.out.println("q("+i+") = "+comp.qi);
            System.out.println("d"+i+"0 = "+comp.di0);
            System.out.println("d"+i+"1 = "+comp.di1+"\n");
        }
        return comps;
    }

    public ABSSignatureComp sign (String message,
                                  ArrayList<ABSPrivKeyComp> privKey) throws NoSuchAlgorithmException {

        // This code assumed k = n = d-1 (verify all attributes)
        // We select the first element as default attribute subset Ω'
        // and generate n+d-k = d random values.

        //  the private key set appended with Ω':
        ArrayList<ABSPrivKeyComp> set_union_omega = (ArrayList<ABSPrivKeyComp>) privKey.clone();
        //set_union_omega.add(privKey.get(0));

        // Signature will be stored at:
        ABSSignatureComp sign = new ABSSignatureComp();

        // generate random s:
        Element s = pubParam.Zr.newRandomElement();

        // generate d of random r':
        ArrayList<Element> r_primes = new ArrayList<>();
        for (int i=0; i<set_union_omega.size(); i++) {
            r_primes.add(pubParam.Zr.newRandomElement());
            System.out.println("generated r"+i+"' = "+r_primes.get(i));
        }
        System.out.println();

        // get the polynomial list with d random values:
        ArrayList <BigInteger> poly = new ArrayList<>();
        for (int i=0; i<set_union_omega.size(); i++) {
            //poly.add(pubParam.Zr.newRandomElement().toBigInteger());
            poly.add(set_union_omega.get(i).qi.toBigInteger());
            System.out.println("generated q("+i+") = "+poly.get(i));
        }
        System.out.println();

        // get the lagrange coefficient ∆i,S(0) based on the polynomial (aka delta):
        ArrayList<Element> deltas = new ArrayList<>();
        for (int i=0; i<set_union_omega.size(); i++) {
            Element delta = pubParam.Zr.newElement();
            lagrangeCoef(delta, poly, poly.get(i));
            System.out.println("∆i,S(" + i + "): " + delta);
            deltas.add(delta);
        }
        System.out.println();

        // calculate first part of σ0 (Π di0^∆i,S(0)):
        Element pi_di0_pow_delta = pubParam.G2.newOneElement();
        for (int i=0; i<set_union_omega.size(); i++) {
            // Power di_0 with delta:
            Element di_0_pow_delta = set_union_omega.get(i).di0.duplicate();
            di_0_pow_delta.powZn(deltas.get(i));
            System.out.println("d"+i+"0^(∆i,S("+i+")): "+di_0_pow_delta);
            // multiply to pi:
            pi_di0_pow_delta.mul(di_0_pow_delta);
        }
        System.out.println();

        // calculate the second part of σ0 (Π H(i)^r'):
        Element pi_hashed_pow_rp = pubParam.G2.newElement();
        for (int i=0; i<set_union_omega.size(); i++) {
            // calculate hash^ri:
            Element hashed = pubParam.G2.newElement();
            elementFromString(hashed, set_union_omega.get(i).attr);
            hashed.powZn(r_primes.get(i));
            // multiply to pi:
            pi_hashed_pow_rp.mul(hashed);
        }

        // calculate the third part of σ0 (H2(m)^s):
        Element h2ms = pubParam.G1.newElement();
        elementFromString(h2ms, message);
        h2ms.powZn(s);
        System.out.println("H2(m)^s = "+h2ms);

        // calculate σ0:
        sign.sigma0 = pubParam.G2.newElement();
        sign.sigma0.set(pi_di0_pow_delta);
        sign.sigma0.mul(pi_hashed_pow_rp);
        sign.sigma0.mul(h2ms);
        System.out.println("σ0 = "+sign.sigma0);
        System.out.println();

        // calculate σi:
        sign.sigma_is = new ArrayList<>();
        for (int i=0; i<set_union_omega.size(); i++) {
            Element sigma_i = pubParam.G1.newElement();
            // Power di_1 with delta:
            Element di_1_pow_delta = set_union_omega.get(i).di1.duplicate();
            di_1_pow_delta.powZn(deltas.get(i));
            // Power g with r':
            Element g_pow_rp = pubParam.g.duplicate();
            g_pow_rp.powZn(r_primes.get(i));
            // multiply to get sigma_i:
            sigma_i.set(di_1_pow_delta);
            sigma_i.mul(g_pow_rp);
            System.out.println("σ"+i+" = "+sigma_i);
            sign.sigma_is.add(sigma_i);  // save for later use
        }
        System.out.println();

        // calculate σ0':
        sign.sigma_prime = pubParam.g.duplicate();
        sign.sigma_prime.powZn(s);
        System.out.println("σ0' = "+sign.sigma_prime);
        return sign;
    }

    public void verify(String message, String attrs[], ABSSignatureComp sign) throws NoSuchAlgorithmException {

        Element sigma0 = sign.sigma0;
        Element sigma_prime = sign.sigma_prime;
        ArrayList<Element> sigma_is = sign.sigma_is;

        // create an array list appended with Ω':
        ArrayList<String> total_attrs = new ArrayList<>(Arrays.asList(attrs));
        //total_attrs.add(attrs[0]);

        // make sure the size is same:
        if (sigma_is.size() != total_attrs.size()) {
            System.out.println("Either attribute or signature is corrupted!");
            return;
        }

        // calculate e(g, σ0):
        Element numerator = pubParam.pairing.pairing(pubParam.g, sigma0);
        // calculate pi(e(H(i), σi)):
        Element pi_hi_sigmai_pair = pubParam.Gt.newElement();
        pi_hi_sigmai_pair.setToOne();
        for (int i=0; i<sigma_is.size(); i++) {
            // calculate H(i):
            Element hashed = pubParam.G1.newElement();
            elementFromString(hashed, total_attrs.get(i));    // the order should be same as sigma_is
            // calculate e(H(i), σi):
            Element hi_sigmai_pair = pubParam.pairing.pairing(hashed, sigma_is.get(i));
            // multiply to pi:
            pi_hi_sigmai_pair.mul(hi_sigmai_pair);
        }
        // calculate e(H(m), σ'0):
        Element hashed_message = pubParam.G1.newElement();
        elementFromString(hashed_message, message);
        Element denominator = pubParam.pairing.pairing(hashed_message, sigma_prime);
        // multiply together to get pi(e(H(i), σi))*e(H(m), σ'0):
        denominator.mul(pi_hi_sigmai_pair);

        // result of numerator/denominator:
        Element Z_prime = numerator.duplicate();
        Z_prime.div(denominator);
        System.out.println("Z' = "+Z_prime);
        System.out.println("Z  = "+pubParam.Z);

    }

    // ======================= Utilities Functions Below =======================
    public void printParameters() {
        System.out.println("============ Public Key Parameters ==============");
        System.out.println("G1: "+pubParam.G1);
        System.out.println("G2: "+pubParam.G2);
        System.out.println("Gt: "+pubParam.Gt);
        System.out.println("Zr: "+pubParam.Zr);
        System.out.println("g: " +pubParam.g);
        System.out.println("g1: "+pubParam.g1);
        System.out.println("g2: "+pubParam.g2);
        System.out.println("Z: " +pubParam.Z);
        System.out.println("============== Private Parameters ===============");
        System.out.println("MASTER KEY X : "+x);
        System.out.println("=================================================\n");
    }

    private static void elementFromString(Element h, String s)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

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

}
