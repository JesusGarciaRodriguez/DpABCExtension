# License
The source code of the Extended PS-MS code open source modules is licensed under the Apache License, Version 2.0. The OLYMPUS source code used for the integration is also under the Apache License, Version 2.0.

# Extended PS-MS 
This repository contains the code for the extension of the distributed privacy-preserving Attribute-Based Credential (dp-ABC) system based on Pintcheval-Sanders Multi-Signatures (PS-MS) through commit-and-prove techniques described in the paper "Beyond Selective Disclosure: Extending Distributed p-ABC Implementations by Commit-and-Prove Techniques" (paper under review) by the authors Jesús García-Rodríguez, Stephan Krenn, Jorge Bernal and Antonio Skarmeta. 

**PS-MS libray code**: The PS-MS code has been integrated in the "/core/src/main/java/eu/olympus/util" package, particularly with a package for each added application proof (range proof, inspection, pseudonyms and revocation), along with the packages that detail model ands and functionalities for the PS-MS scheme. 

**Integration into OLYMPUS**: The integration into the [OLYMPUS](https://bitbucket.alexandra.dk/projects/OL/repos/olympus-identity/) code base mainly took work at the client-side functionality, particularly at the code for managing credentials (PSCredentialManagement), and the verifier of p-ABCs (PSPABCVerifier), along with supporting classes like models for Policies and Predicates.

**Benchmarking** The *core* module includes a benchmark package that works through an executable program (to generate the executable JAR follow the build steps for the module, i.e., run *mvn clean* and *mvn install*) that takes as input arguments for customizing the experiment:
- "--rep": Number of repetitions for the timing benchmark.
- "--warm": Number of warmup iterations before taking into account times for benchmark.
- "--seed": Set a seed.
- "--nattr": Number of identity attributes (outside revocation, range... i.e., hidden attributes) in the credential".
- "--range n": Include range proofs in benchmark for $2^n$ bits.
- "--nrangeattr").type(Integer.class).help("number of range proofs").setDefault(DEFAULT_NRANGE);
- "--inspection": Include inspection proof in benchmark.
- "--revocation": Include revocation proof in benchmark.
- "--pseudonym": Include pseudonym proof in benchmark.


# OLYMPUS code 
The extended implementation has bee integrated into the OLYMPUS source code, which can be found [here](https://bitbucket.alexandra.dk/projects/OL/repos/olympus-identity/), including Readmes and links to documentation.


# Acknowledgements
The research leading to these results has received funding from the European Union’s Horizon 2020 Research and Innovation Programme, Agreements No 830929 (CyberSec4Europe) and No 883335 (Eratosthenes), the Horizon Europe Programme under Grant Agreement No 101073821 (Sunrise), as well as Project PID2020-112675RB-C44  funded by MCIN/AEI/10.13039/501100011033 (Onofre).
