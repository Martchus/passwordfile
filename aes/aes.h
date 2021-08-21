#ifndef AES_INCLUDED
#define AES_INCLUDED AES_INCLUDED

#include "../global.h"

#include <cstring>

namespace Crypto {

class PASSWORD_FILE_EXPORT Aes {

public:
    using byte = unsigned char;
    using word = unsigned long;

    Aes();
    ~Aes();

    std::size_t encrypt(char **data, std::size_t length, char *key);
    std::size_t decrypt(char **data, std::size_t length, char *key);

private:
    static byte gmul(byte a, byte b);
    static void rotWord(word *b);
    static void subWord(word *b);

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

    byte keyLength;
    byte numRounds;

    word *w;
    byte state[4][4];
};

} // namespace Crypto

#endif /* AES_INCLUDED */
