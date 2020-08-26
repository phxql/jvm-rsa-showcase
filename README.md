# jvm-rsa-showcase

A small project showcasing a hybrid encryption scheme using RSA and AES in Java.

It showcases:

* Generation of RSA keys
* Save / load RSA keys to / from files
* Encrypt / decrypt data with AES
* Encrypt / decrypt data with RSA
* Sign / verify data with RSA

It's the code for [this blog entry on my blog](https://www.mkammerer.de/blog/rsa-on-the-jvm/).

To start, take a look at [the main method](src/main/java/de/mkammerer/rsaplayground/Main.java). 
Encryption from Alice to Bob is [here](src/main/java/de/mkammerer/rsaplayground/Alice.java), decryption from
Bob is [here](src/main/java/de/mkammerer/rsaplayground/Bob.java).
