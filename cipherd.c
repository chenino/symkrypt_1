#include <stdint.h>

static const uint16_t SBOX[16] = {0xf,0xe,0xb,0xc,0x6,0xd,0x7,0x8,0x0,0x3,0x9,0xa,0x4,0x2,0x1,0x5};


/**
 * @brief Permutation for CipherD
 * 
 * @param in Input Value
 * @return uint16_t Permutated Value
 */
static uint16_t permutateCipherD(uint16_t in){
    uint16_t out = 0;
    out &= (in & 0b0100001000010000)>>3;
    out &= (in & 0b0010000100000000)>>6;
    out &= (in & 0b0001000000000000)>>9;
    out &= (in & 0b0000100001000010)<<3;
    out &= (in & 0b0000000010000100)<<6;
    out &= (in & 0b0000000000001000)<<9;
    return out;
}

/**
 * @brief SBOX Calculator for CipherD
 * 
 * @param in SBOX Input
 * @return uint16_t SBOX Output
 */
static uint16_t sboxCipherD(uint16_t in){
    return SBOX[in];
}

/**
 * @brief Round Function of CipherD
 * 
 * @param in 16bit Input
 * @param key Round Key
 * @return uint16_t Ciphertext
 */
static uint16_t roundCipherD(uint16_t in, uint16_t key){
    in ^= key;
    in = sboxCipherD(in);
    in = permutateCipherD(in);
    return in;
}

/**
 * @brief Last Round Function
 * 
 * @param in Input
 * @param key1 Key at round start
 * @param key2 Key at round end
 * @return uint16_t Ciphertext
 */
static uint16_t lastRoundCipherD(uint16_t in, uint16_t key1, uint16_t key2){
    in ^= key1;
    in = sboxCipherD(in);
    in ^= key2;
    return in;
}

/**
 * @brief Encryption for a flexible ammount of keys
 * 
 * @param plaintext Plaintext to encrypt
 * @param rounds Number of rounds, has to be number of keys -2 and >=2
 * @param keys Array of keysa
 * @return uint16_t Encrypted Ciphertext
 */
static uint16_t encryptCipherD(uint16_t plaintext, int rounds, uint16_t **keys){
    
    // Exit if too few keys
    if(rounds <2){
        return 0;
    }
    int counter=0;
    for(counter=0;counter<(rounds-2);counter++){
        plaintext  = roundCipherD(plaintext,keys[counter]);
    }
    plaintext = (lastRoundCipherD(plaintext,keys[counter],keys[counter+1]));
    return plaintext;
}