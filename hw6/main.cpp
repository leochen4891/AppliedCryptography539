#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "RSA.h"
#include "BigInt.h"

using namespace RSAUtil;
using namespace std;

// NOT GOOD MACRO, don't do something like MAX(++a, ++b)
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

void q1();
void q2();
void q3();

int main() {
	srand(time(0));
    printf("--------------------------------------------------------------------------------\n");
    printf("---------------------------- CSE 539 HW6 Lei Chen ------------------------------\n");
    printf("--------------------------------------------------------------------------------\n");

    q1();
    q2();

    return 0;
}

void q1() {
    printf("\n");
    printf("- - - - - - - - - - 1. Encryption and decryption using RSA - - - - - - - - - - -\n");

    printf("\n");
    printf("a) Create 10 instances of the RSA class without giving arguments, generate      \n");  
    printf("random message or assign messages, and perform encryption through each of       \n");  
    printf("the 10 classes.                                                                 \n");   
    int count = 10;
    RSA* rsa;
    BigInt message = BigInt(0x00000000, 0x12345678);
    BigInt cipher; 
    BigInt decrypt;
    cout << endl << "  message:" << message.toHexString() << endl;
    for (int i = 0; i < count; i++) {
        rsa = new RSA();
        cipher = rsa->encrypt(message);
        decrypt = rsa->decrypt(cipher);

        cout << "  instance " << i << ": ";
        cout << "cipher = " << cipher.toHexString();
        cout << "(decrypt = " << decrypt.toHexString() << ")" << endl;
        //cout << "message text = " << message.toHexString() << endl;
        delete rsa;
    }
    printf("press ENTER to continue...");
    getchar();


    printf("\n");
    printf("b) Create 5 instances of the RSA class by passing a large prime number          \n");  
    printf("[p](> 30,000), and perform encryption decryption                                \n");   

    int p[] = {30011, 30013, 30029, 30047, 30059};
    count = sizeof(p)/sizeof(int);
    cout << endl << "  message:" << message.toHexString() << endl;
    for (int i = 0; i < count; i++) {
        rsa = new RSA(p[i]);
        cipher = rsa->encrypt(message);
        decrypt = rsa->decrypt(cipher);

        cout << "  instance " << i << ": ";
        cout << "p = " << p[i] << ", ";
        cout << "cipher = " << cipher.toHexString();
        cout << "(decrypt = " << decrypt.toHexString() << ")" << endl;
        //cout << "message text = " << message.toHexString() << endl;
        delete rsa;
    }
    printf("press ENTER to continue...");
    getchar();

    printf("\n");
    printf("c) Create 5 instances of the RSA class by passing 2 large prime numbers         \n");  
    printf("[p,q] (> 30,000) and perform encryption decryption                              \n");     
    int q[] = {40009, 40013, 40031, 40037, 40039};
    count = MIN(sizeof(p)/sizeof(int), sizeof(q)/sizeof(int));
    cout << endl << "  message:" << message.toHexString() << endl;
    for (int i = 0; i < count; i++) {
        rsa = new RSA(p[i], q[i]);
        cipher = rsa->encrypt(message);
        decrypt = rsa->decrypt(cipher);

        cout << "  instance " << i << ": ";
        cout << "p = " << p[i] << ", ";
        cout << "q = " << q[i] << ", ";
        cout << "cipher = " << cipher.toHexString();
        cout << "(decrypt = " << decrypt.toHexString() << ")" << endl;
        //cout << "message text = " << message.toHexString() << endl;
        delete rsa;
    }
    printf("press ENTER to continue...");
    getchar();

    printf("\n");
    printf("d) Create 10 instances of the RSA class by passing 2 large non prime            \n");  
    printf("numbers (> 30,000) and perform encryption decryption. In most of the cases      \n");   
    printf("the message should not get decrypted correctly.                                 \n");  
    int p1[] = {30002, 30004, 30006, 30008, 30010};
    int q1[] = {40002, 40004, 40006, 40008, 40010};
    count = MIN(sizeof(p)/sizeof(int), sizeof(q)/sizeof(int));
    cout << endl << "  message:" << message.toHexString() << endl;
    for (int i = 0; i < count; i++) {
        rsa = new RSA(p1[i], q1[i]);
        cipher = rsa->encrypt(message);
        decrypt = rsa->decrypt(cipher);

        cout << "  instance " << i << ": ";
        cout << "p = " << p1[i] << ", ";
        cout << "q = " << q1[i] << ", ";
        cout << "cipher = " << cipher.toHexString();
        cout << "(decrypt = " << decrypt.toHexString() << ")" << endl;
        //cout << "message text = " << message.toHexString() << endl;
        delete rsa;
    }
    printf("press ENTER to continue...");
    getchar();
}

void q2() {
    printf("\n");
    printf("- - - - - - - - - - - - Challenge Response: Scheme 0 - - - - - - - - - - - - - -\n");

    printf("a) Create an RSA object. Call it RSA1                                           \n");
    printf("b) Create a new RSA object, call it RSA2. Obtain the public key and             \n");
    printf("    modulus [n] of RSA1. Assign these two to the public key and N value in RSA2.\n");
    printf("c) Generate a random message [random BigInt number]. Encrypt it using the       \n");
    printf("    public key of RSA2 [You have stored the pub key of RSA1 in RSA2].           \n");
    printf("d) Decrypt the value using the private key of RSA1.                             \n");
    printf("e) Match both the values (original message vs decrypted message), they should   \n");
    printf("    be the same. If so Challenge Response scheme 0 is completed.                \n");

    RSA* rsa1;
    RSA* rsa2;

    rsa1 = new RSA();
    rsa2 = new RSA();
    rsa2->setPublicKey(rsa1->getPublicKey());
    rsa2->setN(rsa1->getModulus());

    BigInt message = BigInt(rand());
    BigInt cipher = rsa2->encrypt(message);
    BigInt decrypt = rsa1->decrypt(cipher);
    cout << "Public key = " << rsa2->getPublicKey().toHexString() << endl;
    cout << "Modulus N  = " << rsa2->getModulus().toHexString() << endl;
    cout << "Message    = " << message.toHexString() << endl; 
    cout << "Cipher     = " << cipher.toHexString() << endl; 
    cout << "Decrypt    = " << decrypt.toHexString() << endl; 
    cout << "Challenge Response Scheme 0" << ((message == decrypt)?" succeed!":" failed") << endl;

    printf("press ENTER to continue...");
    getchar();
    

    delete rsa1;
    delete rsa2;
}

void q3() {

        Blind Signature:

            Blind signature is a kind of signature, where the signing authority does not know what is being signed. Blind Signatures are used to implement Anonymous money orders. You have to implement a blind signature scheme. The scheme you have to implement is described in wikipedia at the link: http://en.wikipedia.org/wiki/Blind_signature

             

            The scheme can be briefly stated as:

            a.       Alice obtains the public key and Modulus N of the person (Bob) who is to sign the message

            b.      Obtain a random number and its inverse with respect to the Modulus [Not phi] of Bob

            c.       Alice obtains/generates a message to be signed.

            d.      Alice encrypts the random number with the public key.

            e.       Alice multiplies this value by the message

            f.       Alice then takes a modulus over N

            g.      Alice sends it to Bob

            h.      Bob simply decrypts the received value with the private key

            i.        Bob sends it back to Alice

            j.        Alice then multiplied the received value with the inverse and takes a modulus over N.

            k.      The value obtained above is the signed message. To obtain the original message from it, again encrypt it with Bob’s Public Key. 

}
