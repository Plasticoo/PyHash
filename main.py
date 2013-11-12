import sys
from functions import *


def main():
    if len(sys.argv) == 2:
        word = sys.argv[1]
        hashing = CryptoLib(word)
        print hashing.CalculateAllComplete()
    elif len(sys.argv) == 3:
        word = sys.argv[1]
        salt = sys.argv[2]
        hashing = CryptoLib(word)
        print hashing.CalculateAllCompleteSalt(salt)
    else:
        print "How to use: python main.py [word] [salt]"

main()