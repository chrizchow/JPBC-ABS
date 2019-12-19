package hk.chriz;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.math.BigInteger;

public class ABSPubKeyComp {
    public Pairing pairing;
    public Field G1, G2, Gt, Zr;   // the field from pairing object
    public Element g, g1, g2, Z;   // public elements
}
