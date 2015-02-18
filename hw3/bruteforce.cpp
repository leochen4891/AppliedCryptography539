#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <math.h>

#include "md5.h"

using namespace std;

#define DBG 0

char pass[4]; // 4 character password
int *pass_pointer, *temp;
MD5_CTX mdContext; 
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

    //cout << "pass " << pass[0] << pass[1] << pass[2] << pass[3];
    
    for (int i = 3; i >= 0; i--) {
        if (carry == 0)
            break;

        carry = 0;
        c = pass[i];
        c++;

        if (c <= '9' || (c>= 'A' && c<= 'Z') || (c>='a' && c<= 'z')) {
            ;
        } else if (c == '9'+1) {
            c = 'A';
        } else if (c == 'Z' + 1) {
            c = 'a';
        } else if (c == 'z' + 1) {
            c = '0';
            carry = 1;
        }

        pass[i] = c;
        if (carry == 1 && i == 0) {
            pass[0] = pass[1] = pass[2] = pass[3] = '0';
            carry = 0;
        }
        //cout << " ----> " << pass[0] << pass[1] << pass[2] << pass[3] << endl;
    }
}


int getHash(char* input) {
   int result;
   MD5Init(&mdContext);  // compute MD5 of password
   MD5Update(&mdContext, (unsigned char*)pass, 4);
   MD5Final(&mdContext);
   temp = (int *) &mdContext.digest[12]; 
   result = *temp; // result is 32 bits of MD5 -- there is a BUG here, oh well.
   return result;
}

int bruteforce() {

    long long BF_MAX =14776336 ;//62^4
    long long interval = BF_MAX / 1000; // precision of 1 digits. e.g. 2.5% 
    long long inc = 0;
    int result;
    int targetSize = sizeof(targets) / sizeof(int);

    for (long long i = 0; i <= BF_MAX; i++) {
        if (inc == interval) {
            printf("\rbrute forcing...%c%c%c%c(%.1f%%)",pass[0],pass[1],pass[2],pass[3],(double)(i/interval)/10);
            fflush(stdout);
            inc = 0;
        }  else {
            inc++;
        }
        nextPass();
        result = getHash(pass);
        for (int j = 0; j < targetSize; j++) {
            if (result == targets[j])
                printf("hash(%c%c%c%c) = %x\n", pass[0],pass[1],pass[2],pass[3], targets[j]);
        }
    }
    printf("\rbrute forcing...completed(100.0%%)\n");
};

int main(int argc, char *argv[])
{
    std::cout << "Start brute forcing: " << std::endl;
    pass[0] = pass[1] = pass[2] = pass[3] = '0';
    bruteforce();
}
