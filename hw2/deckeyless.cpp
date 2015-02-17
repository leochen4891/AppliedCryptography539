#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <iostream>

#include "md5.h"

#define UKN_FILE_TYPE -1

#define ENC_FILE_TYPE_PDF 0
unsigned char ENC_FILE_TYPE_PDF_ARR[4] = {0x25, 0x50, 0x44, 0x46};// %PDF
unsigned int ENC_FILE_HEAD_PDF= 0x46445025;

#define ENC_FILE_TYPE_PNG 1
unsigned char ENC_FILE_HEAD_PNG_ARR[4] = {0x89, 0x50, 0x4e, 0x47};//.PNG
unsigned int ENC_FILE_HEAD_PNG = 0x474e5089;

#define ENC_FILE_TYPE_TXT 2

char* encFileName;
int encFileType;

unsigned int key;
int buf, infile, outfile;
MD5_CTX mdContext;

int lastbytes(int outfile, int size, int buf) // magic code for extracting last bytes of encryption without the padding
{ 
    int i = 0;
    char *last;
    last = (char*) &buf;
    for (i=0;i<size;i++) {write(outfile, &last[i], 1);} 
};

int decryptKeyless() {

    struct stat st;
    int size,fsize;
    int *temp, result;   
    int rollingkey;    

    infile = open (encFileName, O_RDONLY);
    if (infile<0) { printf("input %s error\n", encFileName); exit(0); }

    outfile = open ("output-dec", O_RDWR|O_CREAT|O_TRUNC, 0700);
    if (outfile<0) { printf("output open error\n"); exit(0); }

    buf = 0;
    read(infile,&buf,4);
    size=buf; // get plaintext size

    // ciphertext has xtra 4 bytes (size) and padding 
    stat(encFileName, &st); 
    fsize = st.st_size; // get ciphertext size
    if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {
        printf("file size sanity check failed\n");
        return 1;
    } 

    int n = read(infile, &buf, 4);
    if (n != 4) {
        printf("read first 4 bytes failed");
        return 1;
    }

    if (encFileType == ENC_FILE_TYPE_PDF) {
        key = buf ^ ENC_FILE_HEAD_PDF;
    } else if ( encFileType == ENC_FILE_TYPE_PNG) {
        key = buf ^ ENC_FILE_HEAD_PNG;
    } else if ( encFileType == ENC_FILE_TYPE_TXT) {
        key = 0;
        printf("don't know how to calculate the key\n");
        return 1;

    } else {
        key = 0;
        printf("don't know how to calculate the key\n");
        return 1;
    }
    printf("key = %x\n", key);

    rollingkey = key;
    while (n > 0) {
        buf = buf ^ rollingkey; // doing the reverse of encrypt
        MD5Init(&mdContext);
        MD5Update(&mdContext, (unsigned char*)&rollingkey, 4);
        MD5Final(&mdContext);
        temp = (int *) &mdContext.digest[12]; 
        result = *temp; // result is 32 bits of MD5 of key
        rollingkey = rollingkey ^ result; // new key

        if (size >= 4) write(outfile, &buf, 4);  
        else lastbytes(outfile, size, buf);

        buf = 0;  // repeat, keep track of output size in size.
        size = size - 4;
        n = read(infile, &buf, 4);
    };
    printf("decryption completed\n");
};

static void show_usage(std::string name)
{
    std::cerr << "Usage: " << "burteforce" << " FILE_NAME FILE_TYPE\n"
        << "FILE_TYPE options:\n"
        << "\t-pdf\tthe ENC_FILE is a pdf file\n"
        << "\t-png\tthe ENC_FILE is a png file\n"
        << "\t-txt\tthe ENC_FILE is a txt file\n"
        << std::endl;
}


int main(int argc, char *argv[])
{
    if (argc < 3) {
        show_usage(argv[0]);
        return 1;
    }

    encFileName = argv[1];
    encFileType = UKN_FILE_TYPE;

    if (0 == strcmp("-pdf", argv[2])) {
        encFileType = ENC_FILE_TYPE_PDF;
    } else if (0 == strcmp("-png", argv[2])) {
        encFileType = ENC_FILE_TYPE_PNG;
    } else if (0 == strcmp("-txt", argv[2])) {
        encFileType = ENC_FILE_TYPE_TXT;
    }

    std::cout << "Start decryption: " << encFileName << " (type = " << encFileType << ")" <<std::endl;

    decryptKeyless();
};
