##SecretFiles

SecretFiles is a small wrapper around the build-in Java 7+ Security API that provides a
more convenient usage for encrypting and decrypting files. The encryption source is either another 
file or some portion of text data. 
 
For efficiency, it is necessary to take a symmetric cryptographic technique, such as AES. But
unfortunately, symmetric keys are unsafe. Therefore it is advisable to encrypt the symmetric key
with an asymmetric key, e.g. by using a private/public key pair based on RSA.

Please note that ideas and algorithms that are necessary to stick together the right Java code for
this library base on [[1]](http://www.macs.hw.ac.uk/~ml355/lore/pkencryption.htm),
[[2]](https://stackoverflow.com/questions/2654949/how-to-read-a-password-encrypted-key-with-java?rq=1),
and [[3]](https://stackoverflow.com/questions/5127379/how-to-generate-a-rsa-keypair-with-a-privatekey-encrypted-with-password).
  
If you want to use this library with Oracle JRE, it is important to know that you have to install
the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files into your 
JRE. For that you have to download a ZIP file from the Oracle Java Download Page, extract
them and copy the two jars into the directory `/lib/security` of your JRE installation.
If you use a JDK put the files in the embedded JRE part of the JDK. More information you get
[here](https://stackoverflow.com/questions/3862800/invalidkeyexception-illegal-key-size). 

To generate a private/public key pair, you can either embed the generation into your source 
code by call some functions of this library (see below), or you generate this pair of key using
[openSSL](https://www.openssl.org/) from command line:

Generate a RSA private key of length 2048 bits:

```
openssl genrsa -out private.pem 2048
```

Convert this key into PKCS#8 format and protect it with a password:

```
openssl pkcs8 -topk8 -in private.pem -outform DER -out private.der
```

Generate the public key from the private key:

```
openssl rsa -in private.pem -pubout -outform DER -out public.der
```
###Usage

For encryption of the symmetric key you need to generate a PKCS#8 private/public key pair with
the openssl commands described above or programmatically:
 
```
PPKGenearor.create("private.der", public.der", "secret", "RSA", 2048);
```

For RSA 2048 there exists a shortcut:

```
PPKGenearor.createRSA2048("private.der", public.der", "secret");
```
 
Suppose that the files that hold both key are named by `private.der` and `public.der`, and the
password that protects the private key is `secret`, then you could generate a AES256 symmetric key
by 

```
SymKey aes256Key = SymKey.create("aes.key", "public.der", "AES", 256, "RSA");
```

Note that the AES key inside `aes256Key` is decrypted. After creation this method stores the
public key encrypted version into the file named `aes.key`.
 
If you have an encrypted symmetric key stored in to the file `aes.key`, you can reuse it by
loading and decrypting with the private key and the password:

```
SymKey aes256Key = SymKey.fromFile("aes.key", "private.der", "AES", 256, "RSA", "secret");
```

For the special case of AES256 und RSA for private/public key there exists a simple factory 
to avoid boring parameters:

```
SymKey aes256Key = AESKeyGenerator.create("aes.key", "public.der");
```

```
SymKey aes256Key = AESKeyGenerator.fromFile("aes.key", "private.der", "secret");
```

Although it is highly recommended to use password protected key files the library provides
an alternative call for loading and decrypting by private key without password:
```
SymKey aes256Key = SymKey.fromFile("aes.key", "private.der", "AES", 256, "RSA");
```
 
For an exiting symmetric key `symKey`you can create an instance of the class 'Crypto' by
 
```
Crypto crypto = new Crypto(symKey);
```
  
This class provides methods to encrypt a file source into a destination file or encrypt
a portion of text data given by a `String` and stores it into a file. For both ways there
are regarding methods for decryption.

From file to file:

```
crypto.encryptFile("source_file", "encrypted_file");
crypto.decryptFile("encrypted_file", "decrypted_file");
```

From text data to file and vice versa:
 
```
crypto.encrypt(data, "enyrpted_data_file", Charset.fromFile("ISO-8859-1"));
String decryptedData = crypto.decrypt("enyrpted_data_file", Charset.fromFile("ISO-8859-1"));
```

Note that you have to consider the charset encoding if you dael with special chars like 
ä, Ö, á etc. If you omit the definition then an explicit Charset encoding UTF-8 is taken
by default.   

###Licence Apache 2.0
 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
