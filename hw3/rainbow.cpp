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

const int RAINBOW_TABLE_W = 2;
const int RAINBOW_TABLE_H = 2;

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
    int method = 1;
    for (int i = 3; i >=0 ; i--) {
        unsigned char c = hash >> (i*8) & 0xFF;
        switch(method) {
            case 0:
                if (c < '0') c = '0';
                else if (c > '9' && c < 'A') c = 'A';
                else if (c > 'Z' && c < 'a') c = 'a';
                else if (c > 'z') c = 'z';
                //printf("c=%d\n", c);
                pwd[3-i] = c;
                break;
            case 1:
                c = c%62;
                if (c <= 9) c = '0'+c;
                else if (c <= 35) c = 'A' + (c-10);
                else  c = 'a' + (c-36);
                //printf("c=%d\n", c);
                pwd[3-i] = c;
                break;
        }
    }
}

void rainbowAttack() {
    unordered_map<int, string> rt;//rainbow table

    // generate rainbow table
    for (int i = 0; i < RAINBOW_TABLE_H; i++) {
        string head = string(pass);

        char pwd[4];
        memcpy(pwd,head.c_str(),4);
        int hash = getHash(pwd);
        printf("%c%c%c%c --H--> %x ", pwd[0],pwd[1],pwd[2],pwd[3], hash);

        for (int j = 0; j < RAINBOW_TABLE_W; j++) {
            reductionFunc(hash, pwd);
            hash = getHash(pwd);
            printf("--R--> %c%c%c%c --H--> %x ", pwd[0],pwd[1],pwd[2],pwd[3], hash);
        }

        printf("\noutput %d : %s -> %x\n",i, head.c_str() , hash);
        // add the start pwd and final hash to the table, 
        // since we are using the hash to find the pwd, the hash is the key
        rt[hash]=head;
        nextPass();
    }

    // dbg print the content of the rainbow table
    printf("rt size = %d\n", rt.size());
    for(unordered_map<int,string>::iterator it = rt.begin(); it != rt.end(); ++it) {
        std::cout << " " << hex << it->first << ":" << it->second << endl;
    }

    // try to find the target in the rainbow table
    int target = 0xc2add68c;
    target = 0xdc35ddb0;
    target = 0x9b3d65b8;// pwd = 0000

    char pwd[4];
    int hash=target;
    int count = 0;
    bool found;

    while(rt.find(hash) == rt.end() && count <= RAINBOW_TABLE_W) {
        reductionFunc(hash, pwd);
        hash = getHash(pwd);
        printf("hash = %x\n", hash);
        count++;
    }
    if (count > RAINBOW_TABLE_W) {
        printf("hash %x is not in the rainbow table\n", target);
        found = false;
    } else {
        printf("found hash %x\n", target);
        found = true;
    }

    if (found) {
        string head = rt[hash];
        printf("head = %s\n", head.c_str());
        count  = 0;
        memcpy(pwd,head.c_str(),4);
        hash = getHash(pwd);
        while(hash != target && count <= RAINBOW_TABLE_W) {
            reductionFunc(hash, pwd);
            hash = getHash(pwd);
            count++;
        }
        if (hash == target) {
            printf("succeed, %c%c%c%c --H--> %x\n", pwd[0],pwd[1],pwd[2],pwd[3], hash);
        }
    }
}

int main(int argc, char *argv[])
{
    std::cout << "Start rainbow attacking: " << std::endl;
    pass[0] = pass[1] = pass[2] = pass[3] = '0';
    rainbowAttack();

    /* int hash = 0x40506070; */
    /* reductionFunc(hash, pass); */
    /* printf("%x -R-> %c%c%c%c\n", hash, pass[0], pass[1], pass[2], pass[3]); */
}
