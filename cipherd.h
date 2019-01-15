#include <stdint.h>


static uint16_t permutateCipherD(uint16_t in);
static uint16_t sboxCipherD(uint16_t in);
static uint16_t roundCipherD(uint16_t in, uint16_t key);
static uint16_t lastRoundCipherD(uint16_t in, uint16_t key1, uint16_t key2);
static uint16_t encryptCipherD(uint16_t plaintext, int rounds, uint16_t **keys);