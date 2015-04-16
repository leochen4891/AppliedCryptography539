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

// Set to 
//  0 - Show questions
//  1 - Hide questions 
#define HIDE_QUSTIONS (1)

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
    q3();

    return 0;
}

void q1() {
    printf("\n");
    printf("- - - - - - - - - - 1. Encryption and decryption using RSA - - - - - - - - - - -\n");
#if(!HIDE_QUSTIONS)
    printf("\n");
    printf("a) Create 10 instances of the RSA class without giving arguments, generate      \n");  
    printf("random message or assign messages, and perform encryption through each of       \n");  
    printf("the 10 classes.                                                                 \n");   
#endif
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


#if(!HIDE_QUSTIONS)
    printf("\n");
    printf("b) Create 5 instances of the RSA class by passing a large prime number          \n");  
    printf("[p](> 30,000), and perform encryption decryption                                \n");   
#endif

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
#if(!HIDE_QUSTIONS)
    printf("c) Create 5 instances of the RSA class by passing 2 large prime numbers         \n");  
    printf("[p,q] (> 30,000) and perform encryption decryption                              \n");     
#endif
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
#if(!HIDE_QUSTIONS)
    printf("d) Create 10 instances of the RSA class by passing 2 large non prime            \n");  
    printf("numbers (> 30,000) and perform encryption decryption. In most of the cases      \n");   
    printf("the message should not get decrypted correctly.                                 \n");  
#endif
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
    printf("- - - - - - - - - - - 2. Challenge Response: Scheme 0 - - - - - - - - - - - - - \n");

#if(!HIDE_QUSTIONS)
    printf("a) Create an RSA object. Call it RSA1                                           \n");
    printf("b) Create a new RSA object, call it RSA2. Obtain the public key and             \n");
    printf("    modulus [n] of RSA1. Assign these two to the public key and N value in RSA2.\n");
    printf("c) Generate a random message [random BigInt number]. Encrypt it using the       \n");
    printf("    public key of RSA2 [You have stored the pub key of RSA1 in RSA2].           \n");
    printf("d) Decrypt the value using the private key of RSA1.                             \n");
    printf("e) Match both the values (original message vs decrypted message), they should   \n");
    printf("    be the same. If so Challenge Response scheme 0 is completed.                \n");
#endif

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
    cout << "Challenge Response Scheme 0" << ((message == decrypt)?" ---> succeed!":" failed") << endl;

    printf("press ENTER to continue...");
    getchar();


    delete rsa1;
    delete rsa2;
}

void q3() {

    printf("\n");
    printf("- - - - - - - - - - - - - - 3. Blind Signature - - - - - - - - - - - - - - - - \n");

#if(!HIDE_QUSTIONS)
    printf("Blind signature is a kind of signature, where the signing authority does not   \n");
    printf("know what is being signed. Blind Signatures are used to implement Anonymous    \n");
    printf("money orders. You have to implement a blind signature scheme. The scheme you   \n");
    printf("have to implement is described in wikipedia at the link:                       \n");
    printf("http://en.wikipedia.org/wiki/Blind_signature                                   \n");

    printf("The scheme can be briefly stated as:                                         \n");
    printf("a. Alice obtains the public key and Modulus N of the person (Bob) who is to  \n");
    printf("    sign the message                                                         \n");
    printf("b. Obtain a random number and its inverse with respect to the Modulus of Bob \n");
    printf("c. Alice obtains/generates a message to be signed.                           \n");
    printf("d. Alice encrypts the random number with the public key.                     \n");
    printf("e. Alice multiplies this value by the message                                \n");
    printf("f. Alice then takes a modulus over N                                         \n");
    printf("g. Alice sends it to Bob                                                     \n");
    printf("h. Bob simply decrypts the received value with the private key               \n");
    printf("i. Bob sends it back to Alice                                                \n");
    printf("j. Alice then multiplied the received value with the inverse and takes a     \n");
    printf("    modulus over N.                                                          \n");
    printf("k. The value obtained above is the signed message. To obtain the original    \n");
    printf("    message from it, again encrypt it with Bob’s Public Key.                 \n");
#endif

    RSA* alice = new RSA();
    RSA* bob = new RSA();
    BigInt pubB = bob->getPublicKey();
    BigInt N = bob->getModulus();
    BigInt R = BigInt(rand());
    BigInt I = modInverse(R, N);
    BigInt M = BigInt(0x12345678);
    BigInt cipherR = bob->encrypt(R);// equal to modPow(R, pubB, N);
    BigInt blindedM = (cipherR * M)%N;
    BigInt blindSig = bob->decrypt(blindedM);
    BigInt signedM = (blindSig*I)%N;
    BigInt targetM = bob->decrypt(M);
    BigInt oriM = bob->encrypt(signedM);

    cout << "Public key = " << pubB.toHexString() << endl;
    cout << "Modulus N  = " << N.toHexString() << endl;
    cout << "Random R   = " << R.toHexString() << endl; 
    cout << "Inverse I  = " << I.toHexString() << endl; 
    cout << "R*I mod N  = " << ((R*I)%N).toHexString() << endl; 
    cout << "Message M  = " << M.toHexString() << endl;
    cout << "Cipher R   = " << cipherR.toHexString() << endl;
    cout << "Blinded M  = " << blindedM.toHexString() << endl;
    cout << "Blind Sig  = " << blindSig.toHexString() << endl;
    cout << "Signed M   = " << signedM.toHexString() << endl;
    cout << "Target M   = " << targetM.toHexString() << endl;
    cout << "Original M = " << oriM.toHexString() << endl;
    cout << "Blind Signature" << (((signedM == targetM)&&(M == oriM))?" ---> succeed!":" failed") << endl;

    delete alice;
    delete bob;
}
