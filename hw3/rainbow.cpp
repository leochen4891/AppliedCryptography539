#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <math.h>
#include <tr1/unordered_map>
#include <list>

#include "md5.h"

#define DBG 0

using namespace std::tr1;
using namespace std;


char pass[4]; // 4 character password
MD5_CTX mdContext; 

const long long RAINBOW_TABLE_W = 200;
const long long RAINBOW_TABLE_H = 62*62*62;

int targets[] = {
    /* 0x9b3d65b8, */
    /* 0xdc35ddb0, */
    /* 0xc2add68c, */
    /* 0xb7c7555f, */
    /* 0x615bc1d4, */
    /* 0x96c1dbda, */
    /* 0xbf5a1d05, */
    /* 0xce5d0856, */
    /* 0xdffeb435, */
    /* 0x2e5cf5ce, */
    /* 0xdffb002f, */
    /* 0x9a618d6f, */
    /* 0xabe16626, */
    /* 0xb9292aca, */
    /* 0xf0a0d913, */
    /* 0xb60d81dd, */
    /* 0x4f25a476, */
    /* 0xdab760c1, */
    /* 0xc8a3f9e2, */
    /* 0x9f8684e5, */

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

// reduce hash to pwd
void reductionFunc(int hash, char* pwd, int step) {
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
                //c = (c+step)%62;
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
    unordered_map<int, list<string> > rt;//rainbow table

    /* unordered_map<int, string> line;//rainbow table */

    // generate rainbow table
    long long count=0;
    long long interval = RAINBOW_TABLE_H/1000;
    long long inc = 0;
    for (long long i = 0; i < RAINBOW_TABLE_H; i++) {
        if (inc == interval) {
            printf("\rgeneraing rainbow table...%c%c%c%c(%.1f%%)",pass[0],pass[1],pass[2],pass[3],100*((double)i)/RAINBOW_TABLE_H);
            fflush(stdout);
            inc = 0;
        }  else {
            inc++;
        }

        string head = string(pass);
        //cout << "head = " << head << endl;

        char pwd[4];
        memcpy(pwd,head.c_str(),4);
        int hash = getHash(pwd);
#if DBG
        printf("%c%c%c%c --H--> %x ", pwd[0],pwd[1],pwd[2],pwd[3], hash);
#endif 
        /* line[hash]=head; */

        for (int j = 0; j < RAINBOW_TABLE_W-1; j++) {
            reductionFunc(hash, pwd, j);
            hash = getHash(pwd);
#if DBG
            printf("\n%c%c%c%c --H--> %x ", pwd[0],pwd[1],pwd[2],pwd[3], hash);
#endif            

            /* unordered_map<int, string>::const_iterator got = line.find(hash); */
            /* if (got != rt.end() ) { */
            /*     printf("(duplicate %x)\n", hash); */
            /* } */
            /* line[hash]=string(pwd); */
        }

        //printf("\noutput %lld : %s -> %x\n",i, head.c_str() , hash);
        // add the start pwd and final hash to the table, 
        // since we are using the hash to find the pwd, the hash is the key

#if DBG
        cout << head << " --> " << hex << hash << endl;
        getchar();
#endif

        list<string> heads = rt[hash];
        heads.push_back(head);
        rt[hash] = heads;

        count++;
        nextPass();
        /* if (pass[0] == 'z' && pass[1] == 'z' && pass[2] == 'z' && pass[3] == 'z') */
        /*     break; */
    }
    printf("\rgeneraing rainbow table...completed(100.0%%)\n");

    // dbg print the content of the rainbow table
    printf("rainbow table size = %lld x %d (width x height), count = %lld\n", RAINBOW_TABLE_W, rt.size(), count);
    //for(unordered_map<int,string>::iterator it = rt.begin(); it != rt.end(); ++it) {
    //    std::cout << " " << hex << it->first << ":" << it->second << endl;
    //}

    // try to find the target in the rainbow table
    for (int i = 0; i < sizeof(targets)/sizeof(int); i++) {
        int target = targets[i];
        char pwd[4];
        int hash=target;
        bool foundHash = false;
        bool foundPwd= false;

        printf("target %d = %x, ", i, target);

        for (int j = 0; j < RAINBOW_TABLE_W; j++) {
            unordered_map<int, list<string> >::const_iterator got = rt.find(hash);
            if (got == rt.end() ) {
                //cout << hex << hash << " not found" << endl;
                reductionFunc(hash, pwd, j);
                //cout << hex << hash << " -> " << pwd << endl;
                hash = getHash(pwd);
                //cout << pwd << " -> " << hex << hash << endl;
            } else {
                //cout << hex << got->first << " found, heads size is " << got->second.size() << endl;
                foundHash = true;
                break;
            }
            //getchar();
        }

        if (foundHash) {
            list<string> heads = rt[hash];
            for (std::list<string>::iterator it = heads.begin(); it != heads.end(); it++) {
                string head = *it;
                //cout << "head = " << head << endl;
                memcpy(pwd,head.c_str(),4);
                hash = getHash(pwd);

                for (int j = 0; j < RAINBOW_TABLE_W; j++) {
                    if (hash == target) {
                        foundPwd = true;
                        break;
                    }
                    reductionFunc(hash, pwd, j);
                    hash = getHash(pwd);
                }

                if (foundPwd) {
                    break;
                } 
            }

            if (foundPwd) {
                printf("succeed ---> %c%c%c%c\n", pwd[0],pwd[1],pwd[2],pwd[3]);
            } else {
                printf("failed\n");
            }
        } else {
            printf("failed\n");
        }

    }
}

int main(int argc, char *argv[])
{
    std::cout << "Start rainbow attacking: " << std::endl;
    pass[0] = '0';
    pass[1] = '0';
    pass[2] = '0';
    pass[3] = '0';
    rainbowAttack();

    /* int hash = 0x40506070; */ 
    /* hash = 0x95038907; */
    /* reductionFunc(hash, pass); */ 
    /* printf("%x -R-> %c%c%c%c\n", hash, pass[0], pass[1], pass[2], pass[3]); */ 

    /* hash = targets[0]; */
    /* reductionFunc(hash, pass); */ 
    /* printf("%x -R-> %c%c%c%c\n", hash, pass[0], pass[1], pass[2], pass[3]); */ 
}
