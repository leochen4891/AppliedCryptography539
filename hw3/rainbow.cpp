#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <math.h>
#include <tr1/unordered_map>

#include "md5.h"

using namespace std::tr1;
using namespace std;

char pass[4]; // 4 character password
MD5_CTX mdContext; 

const int RAINBOW_TABLE_W = 62;
const int RAINBOW_TABLE_H = 62;

int targets[] = {
    0x19fbc7c1,
    0x7e1d96fd,
    0x88df723c,
    0x3974cffc,
    0x8f6bb61b,
    0x8e564270,
    0x655ca818,
    0x58712b2b,
    0x97e75d32,
    0x14928501};

void nextPass() {
    char c;
    int carry = 1;

    for (int i = 3; i >= 0; i--) {
        if (carry == 0)
            break;

        carry = 0;
        c = pass[i];
        c++;

        if (c <= '9' || (c>= 'A' && c<= 'Z') || (c>='a' && c<= 'z')) ; // keep it
        else if (c == '9'+1)  c = 'A';
        else if (c == 'Z' + 1) c = 'a';
        else if (c == 'z' + 1)  {
            c = '0';
            carry = 1;
        }

        pass[i] = c;
        if (carry == 1 && i == 0) {
            pass[0] = pass[1] = pass[2] = pass[3] = '0';
            carry = 0;
        }
    }
}

int getHash(char* input) {
   int result;
   MD5Init(&mdContext);  // compute MD5 of password
   MD5Update(&mdContext, (unsigned char*)input, 4);
   MD5Final(&mdContext);
   int *temp = (int *) &mdContext.digest[12]; 
   result = *temp; // result is 32 bits of MD5 -- there is a BUG here, oh well.
   return result;
}

// reduce from hash to pwd
void reductionFunc(int hash, char* pwd) {
    for (int i = 3; i >=0 ; i--) {
        char c = hash >> (i*8) & 0xFF;
        if (c < '0') c = '0';
        else if (c > '9' && c < 'A') c = 'A';
        else if (c > 'Z' && c < 'a') c = 'a';
        else if (c > 'z') c = 'z';
        pwd[3-i] = c;
    }
}

void rainbowAttack() {
    unordered_map<string, int> rt;//rainbow table

    for (int i = 0; i < RAINBOW_TABLE_H; i++) {
        printf("%d pass=%c%c%c%c\n", i, pass[0], pass[1], pass[2], pass[3]);
        string head = string(pass);

        char pwd[4];
        int hash;
        
        memcpy(pwd,head.c_str(),4);
        hash = getHash(pwd);

        printf("%c%c%c%c -> %x\n", pwd[0],pwd[1],pwd[2],pwd[3],hash);

        reductionFunc(hash, pwd);
        
        for (int j = 0; j < RAINBOW_TABLE_W; j++) {

        }
        
        nextPass();
    }

}

int main(int argc, char *argv[])
{
    std::cout << "Start rainbow attacking: " << std::endl;
    pass[0] = pass[1] = pass[2] = pass[3] = '0';
    //rainbowAttack();
    reductionFunc(0x40506070, pass);
    printf("pass=%c%c%c%c\n", pass[0], pass[1], pass[2], pass[3]);

}
