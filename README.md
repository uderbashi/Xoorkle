# Xoorkle
A simple tool for encrypting and decrypting data, based on a simplified version of Xoodyak and Sparkle algorithms. This was made for my assignment on block ciphers in autumn 2021.

# Disclaimer
These are not to be used as encryption methods, since they are not set 100% to the spec of [Xoodyak](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/round-1/spec-doc/Xoodyak-spec.pdf) or [Sparkle](https://tosc.iacr.org/index.php/ToSC/article/view/8627/8193).
The codes here are made as a proof of concept, and the encryption methodology is simpler compared to the actual spec.
The methods have not been tested for robustness with proper linear or differntial attacks, but in their simple stste they work properly.
I do not hold any liability for compromised data encrypted with the methods in this repository.

# How to use
The repository does not rely on any non-standard library, and was written for python 3.8
    
    python3 xoorkle.py -h
will display an adequate verbose help prompt.
