#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <iostream>

#include "md5.h"

#define DBG 0

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

int key;
int buf, infile, outfile;

MD5_CTX mdContext; 

int isValidText(int input, int size);
int nextRollingKey(unsigned int rollingkey) {
    int nextKey;
    MD5Init(&mdContext);
    MD5Update(&mdContext, (unsigned char*)&rollingkey, 4);
    MD5Final(&mdContext);
    int* temp = (int *) &mdContext.digest[12]; 
    int result = *temp; // result is 32 bits of MD5 of key
    nextKey = rollingkey ^ result; // new key
    return nextKey;
}

void writeToBuffer(int input, char* buf, int offset, int count) {
    char c;
    for (int i = 0 ; i < count; i++) {
        c = (char)(input >> 8*i) & 0xFF;
        *(buf + offset + i) = c;
    }
}

int bruteforce() {


    struct stat st;
    int size,fsize;
    int *temp, result;   
    int rollingkey;    

    infile = open (encFileName, O_RDONLY);
    if (infile<0) { printf("input %s error\n", encFileName); exit(0); }

    buf = 0;
    read(infile,&buf,4);
    size=buf; // get plaintext size

    // ciphertext has xtra 4 bytes (size) and padding 
    stat(encFileName, &st); 
    fsize = st.st_size; // get ciphertext size
    if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {
        printf("file size sanity check failed, size = %d, fsize = %d\n", size, fsize);
        return 1;
    } 

    int n = read(infile, &buf, 4);
    if (n != 4) {
        printf("read first 4 bytes failed");
        return 1;
    }

    fflush(stdout);

    long long BF_MAX = 0xFFFFFFFFL;
    long long interval = BF_MAX / 1000; // precision of 1 digits. e.g. 2.5% 
    long long inc = 0;

    if (encFileType == ENC_FILE_TYPE_PDF || encFileType == ENC_FILE_TYPE_PNG) {
        int header = encFileType == ENC_FILE_TYPE_PDF?ENC_FILE_HEAD_PDF:ENC_FILE_HEAD_PNG;
        for (long long i = 0; i <= BF_MAX; i++) {
            if (inc == interval) {
                printf("\rbrute forcing...%llx(%.1f%%)", i,(double)(i/interval)/10);
                fflush(stdout);
                inc = 0;
            }  else {
                inc++;
            }

            key = (int)i;
            result = buf ^ key;
            if (result == header) {
                printf("\rkey found:%x                      \n", key);
                //break;
            }
        }
    } else if (encFileType == ENC_FILE_TYPE_TXT) {
        char* outputBuf = (char*) malloc(fsize);
        int writeCount = 0;
        int wrongKey = 0;
        int remain = size;

        int THE_KEY = 0x1d41ba64;

        for (long long i = THE_KEY ; i <= BF_MAX; i++) {
            if (inc == interval) {
                printf("\rbrute forcing...%llx(%.1f%%)", i,(double)(i/interval)/10);
                fflush(stdout);
                inc = 0;
            }  else {
                inc++;
            }


            key = (int)i;
#if DBG
            printf("key = %x\n", key);
            getchar();
#endif
            int rollingKey = key;
            writeCount = 0;
            wrongKey = 0;
            remain = size;
            lseek(infile, 4L, SEEK_SET);
            memset(outputBuf, 0, fsize);

            // start trying the key
            while ((n = read(infile, &buf, 4))> 0) {
                result = buf ^ rollingKey;
                if (remain < 4) {
                    n = remain;
                }
#if DBG
                printf("buf = %x, key = %x, result = %x, n = %d\n", buf, key, result, n);
                getchar();

                printf("isValidText(result) = %d\n", isValidText(result, n));
                getchar();
#endif

                if (isValidText(result, n) < 0) {
                    wrongKey = 1;
                    break;
                } 

                // write to the outputBuffer
                writeToBuffer(result, outputBuf, writeCount, n);
                rollingKey = nextRollingKey(rollingKey);
                writeCount+=n;
                remain-=n;
#if DBG
                printf("outputBuf = %s\n", outputBuf);
                getchar();
#endif
            }

            if (!wrongKey) {
                printf("%x : %s\n", key, outputBuf);
            }
        }
        free(outputBuf);
    } else {
        printf("ERROR, unkown file type\n");
    }
    printf("\rbrute forcing...completed(100.0%%)\n");
};

// > 0 means true
int isValidText(int input, int size) {
    //printf("input = %x, size = %d\n", input, size);
    char c;
    for (int i = 0; i < size; i++) {
        c = (input >> (8*i)) & 0xFF;
        if (!(c == 0x0a || c == 0x0d || (c >= 0x20 && c < 0x7F))) // \r, \n, or printable chars
            return -1;
    }
    return 1;
}

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

    std::cout << "Start brute forcing: " << encFileName << " (type = " << encFileType << ")" <<std::endl;

    bruteforce();
};
