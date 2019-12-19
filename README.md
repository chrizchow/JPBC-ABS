# JPBC Implementation of J. Li's ABS
This project is the implementation of Jin Li's Attribute-based Signature (ABS) using Java Pairing-Based Cryptography Library (JPBC).


## Description
Attribute-based Signature (ABS) is a scheme to provide proof of possessions of attributes and provide authenticity of the data issuers. Combining with attribute-based encryption such as CP-ABE or KP-ABE, ABS is useful for different scenarios such as attribute-based messaging (ABM), secure voting and fine-grain user access control.

This ABS implementation is based on J. Li's papers [1, 2]. For simplicity, I have only implemented the basic scheme which signs with all attributes in the private key and verify all given attributes, which means `(k = n = d-1)`.

This project only supports Type A (Symmetric) elliptic curve.

## Known Issues
- The attribute array used in `sign()` and `verify()` must follow the same order.


## Reference
[1] J. Li, M. H. Au, W. Susilo, D. Xie, and K. Ren, “Attribute-based signature and its applications,” Proc. 5th Int. Symp. Information, Comput. Commun. Secur. ASIACCS 2010, pp. 60–69, 2010. [https://dl.acm.org/citation.cfm?doid=1755688.1755697](https://dl.acm.org/citation.cfm?doid=1755688.1755697)

[2] J. Li and K. Kim, “Attribute-Based Ring Signatures,” Iacr, vol. 394, 2008. [https://eprint.iacr.org/2008/394](https://eprint.iacr.org/2008/394)

[3] A. De Caro and V. Iovino, “jPBC: Java pairing based cryptography,” in Proceedings of the 16th IEEE Symposium on Computers and Communications, ISCC 2011, 2011, pp. 850–855. [http://gas.dia.unisa.it/projects/jpbc/](http://gas.dia.unisa.it/projects/jpbc/)

[4] Junwei Wang. Java Realization for Ciphertext-Policy Attribute-Based Encryption. [https://github.com/junwei-wang/cpabe/](https://github.com/junwei-wang/cpabe/), 2012


## Citation
Please feel free to use my project with the following citation:
> Man Chun Chow. _JPBC Implementation of J. Li's ABS_. [https://github.com/cmcvista/JPBC-ABS](https://github.com/cmcvista/JPBC-ABS), 2019

