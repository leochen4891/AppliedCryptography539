g++ -w -o encrypt encrypt.c
g++ -w -o decrypt decrypt.c
g++ -w -o bf bruteforce.cpp
g++ -w -o deckeyless deckeyless.cpp
xterm -e ./encrypt input.pdf
