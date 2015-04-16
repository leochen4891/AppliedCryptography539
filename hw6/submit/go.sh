g++ BigInt.cpp RSA.cpp main.cpp
g++ -c BigInt.cpp RSA.cpp
ar rc libRSAutil.a BigInt.o RSA.o
ranlib libRSAutil.a
g++ main.cpp -L. -l RSAutil -o prog
./prog
