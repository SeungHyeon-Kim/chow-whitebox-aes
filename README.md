# chow-whitebox-aes
This **Whitebox AES** is implemented [Chow et al.](https://home.cs.colorado.edu/~jrblack/class/csci7000/s03/project/oorschot-whitebox.pdf) scheme, following [Muir's "A Tutorial on White-box AES"](https://eprint.iacr.org/2013/104.pdf) and with reference to [balena/aes-whitebox](https://github.com/balena/aes-whitebox).

A random non-linear encoding is appiled.
so, if you encrypt a naive data with `wbaes_encrypt()`, it's going to unexpected result. therefore apply external encoding to data and remove encoding after performed encryption.