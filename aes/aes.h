#ifndef AES_INCLUDED
#define AES_INCLUDED AES_INCLUDED

#include <c++utilities/application/global.h>

#include <cstring>

namespace Crypto {

class LIB_EXPORT Aes {

public:
    typedef unsigned char byte;
    typedef unsigned long word;

    Aes();
    ~Aes();

    size_t encrypt(char **data, size_t length, char *key);
    size_t decrypt(char **data, size_t length, char *key);

private:
    static byte gmul(byte a, byte b);
    static void rotWord(word *b );
    static void subWord(word *b );

    bool setKey(char *key);
    void expandKey(byte *key);

    void addRoundKey(byte round);

    void shiftRows(void);
    void invShiftRows(void);

    void mixColumns(void);
    void invMixColumns(void);

    void cipher(void);
    void invCipher(void);

    static byte sbox[16][16];
    static byte inv_sbox[16][16];
    static word rcon[52];

    byte key_length;
    byte num_rounds;

    word *w;
    byte state[4][4];
};

}

#endif /* AES_INCLUDED */
