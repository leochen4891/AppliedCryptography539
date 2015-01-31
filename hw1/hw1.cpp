#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

using namespace std;

#define DBG 0

off_t fsize(FILE* file);
off_t readSize(FILE * file);
void writeSize(FILE * file, off_t size); 

unsigned int enc32(unsigned int plainText, unsigned int key);
unsigned int dec32(unsigned int cipherText, unsigned int key);

int permEnc32(int input);
int permDec32(int input);

void bit2bit(int src, int* dst, int from, int to);

int encryptFile(const char* inputFilename, const char* outputFilename, unsigned int key);
int decryptFile(const char* inputFilename, const char* outputFilename, unsigned int key);

int main(int argc, const char *argv[])
{
    // check if unsigned int is 32 bit, on which this encryption is based 
    if (sizeof(unsigned int) != 4) {
        cerr << "ERROR, unsigned int is not 32-bit!" << endl;
        return 1;
    }

    const char defaultInputFilename[] = "file.in";
    const char defaultOutputFilename[] = "file.out"; 
    const char defaultDecryptFilename[] = "file.dec"; 
    const unsigned int defaultKey = 0x065F88d5;

    const char* inputFilename = defaultInputFilename;
    const char* outputFilename = defaultOutputFilename;
    const char* decryptFilename = defaultDecryptFilename;
    unsigned int key = defaultKey;

    if (argc <= 1 || argc > 4) {
        printf( "Usage: %s file.in\n", argv[0] ); // argc == 2
        printf( "Usage: %s file.in file.out\n", argv[0] );// argc == 3
        printf( "Usage: %s file.in file.out key\n", argv[0] );// argc == 4
        return 1; 
    } 

    if (argc >= 2) {
        inputFilename = argv[1];
    } 

    if (argc >= 3) {
        outputFilename = argv[2];
    }

    if (argc >= 4) {
        // NOTE:
        // key can be 0, INT_MIN, or INT_MAX if the input is invalid or out of range
        key = atoi(argv[3]);
    }

    encryptFile(inputFilename, outputFilename, key);
    decryptFile(outputFilename, decryptFilename, key);

    return 0;
}

int encryptFile(const char* inputFilename, const char* outputFilename, unsigned int key) {

    FILE *inputFile;
    inputFile=fopen(inputFilename, "r");
    if (NULL == inputFile) {
        cerr << "open file " << inputFilename << " failed" << endl;
        return 1;
    }

    FILE *outputFile;
    outputFile = fopen(outputFilename, "w");
    if (NULL == outputFile) {
        cerr << "open file " << outputFilename << " failed" << endl;
        fclose(inputFile);
        return 1;
    }

    off_t inputFileSize = fsize(inputFile);

    cout << "======================= start encrypting ====================" << endl;
    cout << inputFilename << " --> " << outputFilename << endl;

#if DBG
    cout << "input file name = " <<  inputFilename << ", size = " << inputFileSize << endl;
    cout << "output file name = " << outputFilename << endl;
    cout << "key = " << hex << key << endl;
#endif



    // write the size of the input file first
    writeSize(outputFile, inputFileSize);

    // start encrypting the input file
    off_t totalRead = 0;
    off_t totalWrite = sizeof(off_t);
    int readCount = 0;
    int writeCount = 0;
    unsigned int input32;
    unsigned int output32;
    off_t unitSize = inputFileSize < 10000 ? inputFileSize : 10000;
    off_t updateSize = inputFileSize / unitSize; // precision of 2 digits. e.g. 2.55% 
    while(true) {
        if (totalRead % updateSize == 0)  {
            printf("\rencrypting...(%.2f%%)", (double)(totalRead*100)/inputFileSize);
            fflush(stdout);
        }
        input32 = 0; 
        output32 = 0;
        readCount = fread(&input32, 1, sizeof(input32), inputFile);
        if (readCount > 0) {
            output32 = enc32(input32, key);
            writeCount = fwrite(&output32, 1, sizeof(output32), outputFile);
#if DBG
            cout << "read " << readCount << " bytes: " << hex << input32 << endl;
            cout << "encrypted into: " << hex << output32 << endl;
            cout << "write " << writeCount << " bytes: " << hex << output32 << endl;
            getchar();
#endif
            totalRead += readCount;
            totalWrite += writeCount;
        } else {
            cout << "\rencrypting...(completed), write size = " << totalWrite << endl;
            break;
        }
    }
    fclose(inputFile);
    fclose(outputFile);

    return 0;
}

int decryptFile(const char* cipherFilename, const char* decryptFilename, unsigned int key) {
    // decrypting the encrypted file

    cout << "======================= start decrypting ====================" << endl;
    cout << cipherFilename << " --> " << decryptFilename << endl;

    FILE* cipherFile;
    cipherFile=fopen(cipherFilename, "r");
    if (NULL == cipherFile) {
        cerr << "open file " << cipherFilename << " failed" << endl;
        return 1;
    }

    FILE* decryptFile;
    decryptFile = fopen(decryptFilename, "w");
    if (NULL == decryptFile) {
        cerr << "open file " << decryptFilename << " failed" << endl;
        fclose(cipherFile);
        return 1;
    }

    // read the size of the file first
    off_t cipherFileSize = fsize(cipherFile); // input file size
    off_t decryptFileSize = readSize(cipherFile); // expected output file size

#if DBG
    cout << "cipher file name = " <<  cipherFilename << ", size = " << cipherFileSize << endl;
    cout << "decrypt file name = " << decryptFilename << ", expected size = " << decryptFileSize << endl;
    cout << "key = " << key << endl;
#endif

    // start encrypting the input file
    off_t totalRead = 0;
    off_t toWrite = decryptFileSize;
    int writeCount = 0;
    unsigned int input32;
    unsigned int output32;
    off_t unitSize = cipherFileSize < 10000 ? cipherFileSize : 10000;
    off_t updateSize = cipherFileSize / unitSize; // precision of 2 digits. e.g. 2.55% 
    while(true) {
        if (totalRead % updateSize == 0)  {
            printf("\rdecrypting...(%.2f%%)", (double)(totalRead*100)/cipherFileSize);
            fflush(stdout);
        }
        input32 = 0; 
        output32 = 0;
        int readCount = fread(&input32, 1, sizeof(input32), cipherFile);
        if (readCount > 0) {
            output32 = dec32(input32, key);
            int writeSize = toWrite < sizeof(output32)? toWrite:sizeof(output32);
            writeCount = fwrite(&output32, 1, writeSize, decryptFile);
#if DBG
            cout << "read " << readCount << " bytes: " << hex << input32 << endl;
            cout << "decrypted into: " << hex << output32 << endl;
            cout << "write " << writeCount << " bytes: " << hex << output32 << endl;
            getchar();
#endif
            totalRead += readCount;
            toWrite -= writeCount;
        } else {
            cout << "\rdecrypting...(completed), write size = " << decryptFileSize << endl;
            break;
        }
    }
    fclose(cipherFile);
    fclose(decryptFile);

    return 0;
}

void writeSize(FILE * file, off_t size) {
    fwrite(&size, 1, sizeof(off_t), file);
}

off_t readSize(FILE * file) {
    off_t ret;
    fread(&ret, 1, sizeof(off_t), file);
    return ret;
}

unsigned int enc32(unsigned int plain, unsigned int key) {
    unsigned int temp = (~plain) ^ key;
    return permEnc32(temp);
}

unsigned int dec32(unsigned int cipher, unsigned int key) {
    unsigned int temp = permDec32(cipher);
    return ~(temp ^ key);
}


void bit2bit(int src, int* dst, int from, int to) {
    int clearMask = 0xFFFFFFFF ^ (1<<to);
    int slot = *dst & clearMask;

    int bit = (src >> from) & 1;
    int bitMask = 0xFFFFFFFF & (bit<<to);

    *dst = slot | bitMask;
}

int permEnc32(int input) {
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

int permDec32(int input) {
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
off_t fsize(FILE* file) {
    fseek(file, 0, SEEK_END);
    off_t len = (unsigned long)ftell(file);
    fseek(file, 0, SEEK_SET);
    return len;
}
