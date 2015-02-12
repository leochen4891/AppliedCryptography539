#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <iostream>

#include "md5.h"

unsigned int key;
int buf, n, infile, outfile;
MD5_CTX mdContext; 

#define UKN_FILE_TYPE -1
#define PDF_FILE_TYPE 0
#define PNG_FILE_TYPE 1
#define TXT_FILE_TYPE 2


int lastbytes(int outfile, int size, int buf) // magic code for extracting last bytes of encryption without the padding
{ 
    int i = 0;
    char *last;
    last = (char*) &buf;
    for (i=0;i<size;i++) {write(outfile, &last[i], 1);} 
};

int decrypt(int key)
{
    printf("decrypting using key: %x\n", key);
    struct stat st;
    int size,fsize;
    int *temp, result;   
    int rollingkey;    
    rollingkey = key;   

    infile = open ("output", O_RDONLY);
    if (infile<0) { printf("input open error\n"); exit(0); }

    buf = 0;
    read(infile,&buf,4);
    size=buf; // get plaintext size

    // ciphertext has xtra 4 bytes (size) and padding 

    stat("output", &st); fsize = st.st_size; // get ciphertext size
    if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {printf("file size sanity check failed\n");}; 

    outfile = open ("output-dec", O_RDWR|O_CREAT|O_TRUNC, 0700);
    if (outfile<0) { printf("output open error\n"); exit(0); }

    while ((n = read(infile, &buf, 4))> 0) {
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
    };
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
    char* encFileName = argv[1];
    int encFileType = UKN_FILE_TYPE;

    if (0 == strcmp("-pdf", argv[2])) {
        encFileType = PDF_FILE_TYPE;
    } else if (0 == strcmp("-png", argv[2])) {
        encFileType = PNG_FILE_TYPE;
    } else if (0 == strcmp("-txt", argv[2])) {
        encFileType = TXT_FILE_TYPE;
    }

    std::cout << "Start brute forcing: " << encFileName << " (type = " << encFileType << ")" <<std::endl;
};
