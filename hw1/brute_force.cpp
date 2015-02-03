#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
using namespace std;

unsigned int KEY = 0x065F88d5;

int permutationEnc(int input);
int permutationDec(int input);
int blockEnc(int plainText, int key);
int blockDec(int cipherText, int key);
void textEnc(int* src, int* dst, int size, int key);
void textDec(int* src, int* dst, int size, int key);
void bit2bit(int src, int* dst, int pos);
void printBuffer(int* buffer, int size);


int main(int argc, const char *argv[])
{
  char plainText[] = "nice day";
  int size = sizeof(plainText)/sizeof(int);

  int cipherText[size];
  int decryptedText[size];
  int bfText[size];


  printf("--------plain text--------\n");
  printBuffer((int*)plainText, size);
  printf("\n");

  textEnc((int*)plainText, cipherText, size, KEY);
  printf("--------cipher text--------\n");
  printBuffer((int*)cipherText, size);
  printf("\n");

  textDec((int*)cipherText, decryptedText, size, KEY);
  printf("--------decrypted text--------\n");
  printBuffer((int*)decryptedText, size);
  printf("\n");

  printf("--------brute force--------\n");
  printf("secret key = %u\n", KEY);
  unsigned long BF_MAX = 0xFFFFFFFFL;
  unsigned long interval = BF_MAX / 10000; // precision of 2 digits. e.g. 2.55% 
  for (unsigned long i = 0; i <= BF_MAX; i++) {
    if (i % interval == 0)  {
      printf("\rbrute forcing...(%.2f%%)", (double)(i/interval)/100);
      fflush(stdout);
    }
    textDec((int*)cipherText, bfText, size, i);
    if (0 == memcmp((char*)bfText, plainText, sizeof(plainText)- 1)) {
      printf("\nkey found!!\nkey = %lu\n", i);
      break;
    }
  }
  printf("\n");

  return 0;
}

void bit2bit(int src, int* dst, int from, int to) {

  int clearMask = 0xFFFFFFFF ^ (1<<to);
  int slot = *dst & clearMask;

  int bit = (src >> from) & 1;
  int bitMask = 0xFFFFFFFF & (bit<<to);

  *dst = slot | bitMask;
}


int blockEnc(int plainText, int key) {
  int temp = plainText ^ key;
  return permutationEnc(temp);
}

int blockDec(int cipherText, int key) {
  int temp = permutationDec(cipherText);
  return temp ^ key;
}

void textEnc(int* src, int* dst, int size, int key) {
  for (int i = 0; i < size; i++) {
    *(dst+i) = blockEnc(*(src+i), key);
  }
}

void textDec(int* src, int* dst, int size, int key) {
  for (int i = 0; i < size; i++) {
    *(dst+i) = blockDec(*(src+i), key);
  }
}

int permutationEnc(int input) {
  int ret = 0;
  bit2bit(input, &ret, 0  ,4 );
  bit2bit(input, &ret, 1  ,2 );
  bit2bit(input, &ret, 2  ,15);
  bit2bit(input, &ret, 3  ,27);
  bit2bit(input, &ret, 4  ,5 );
  bit2bit(input, &ret, 5  ,24);
  bit2bit(input, &ret, 6  ,29);
  bit2bit(input, &ret, 7  ,0 );
  bit2bit(input, &ret, 8  ,20);
  bit2bit(input, &ret, 9  ,16);
  bit2bit(input, &ret, 10 ,28);
  bit2bit(input, &ret, 11 ,3 );
  bit2bit(input, &ret, 12 ,7 );
  bit2bit(input, &ret, 13 ,26);
  bit2bit(input, &ret, 14 ,10);
  bit2bit(input, &ret, 15 ,9 );
  bit2bit(input, &ret, 16 ,22);
  bit2bit(input, &ret, 17 ,21);
  bit2bit(input, &ret, 18 ,23);
  bit2bit(input, &ret, 19 ,13);
  bit2bit(input, &ret, 20 ,25);
  bit2bit(input, &ret, 21 ,17);
  bit2bit(input, &ret, 22 ,31);
  bit2bit(input, &ret, 23 ,8 );
  bit2bit(input, &ret, 24 ,11);
  bit2bit(input, &ret, 25 ,12);
  bit2bit(input, &ret, 26 ,19);
  bit2bit(input, &ret, 27 ,1 );
  bit2bit(input, &ret, 28 ,6 );
  bit2bit(input, &ret, 29 ,30);
  bit2bit(input, &ret, 30 ,18);
  bit2bit(input, &ret, 31 ,14);
  return ret;
}

int permutationDec(int input) {
  int ret = 0;
  bit2bit(input, &ret, 0 , 7  );
  bit2bit(input, &ret, 1 , 27 );
  bit2bit(input, &ret, 2 , 1  );
  bit2bit(input, &ret, 3 , 11 );
  bit2bit(input, &ret, 4 , 0  );
  bit2bit(input, &ret, 5 , 4  );
  bit2bit(input, &ret, 6 , 28 );
  bit2bit(input, &ret, 7 , 12 );
  bit2bit(input, &ret, 8 , 23 );
  bit2bit(input, &ret, 9 , 15 );
  bit2bit(input, &ret, 10, 14 );
  bit2bit(input, &ret, 11, 24 );
  bit2bit(input, &ret, 12, 25 );
  bit2bit(input, &ret, 13, 19 );
  bit2bit(input, &ret, 14, 31 );
  bit2bit(input, &ret, 15, 2  );
  bit2bit(input, &ret, 16, 9  );
  bit2bit(input, &ret, 17, 21 );
  bit2bit(input, &ret, 18, 30 );
  bit2bit(input, &ret, 19, 26 );
  bit2bit(input, &ret, 20, 8  );
  bit2bit(input, &ret, 21, 17 );
  bit2bit(input, &ret, 22, 16 );
  bit2bit(input, &ret, 23, 18 );
  bit2bit(input, &ret, 24, 5  );
  bit2bit(input, &ret, 25, 20 );
  bit2bit(input, &ret, 26, 13 );
  bit2bit(input, &ret, 27, 3  );
  bit2bit(input, &ret, 28, 10 );
  bit2bit(input, &ret, 29, 6  );
  bit2bit(input, &ret, 30, 29 );
  bit2bit(input, &ret, 31, 22 );
  return ret;
}

void printBuffer(int* buffer, int size) {
  char* cur = (char*)buffer;
  for (int i = 0 ; i < size*4; i++) {
    printf("%c", *(cur+i));
  }
  cout << endl;
}
