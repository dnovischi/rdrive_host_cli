#define UNIQUE_ID_START_ADDRESS 0x1200

/**
 * @brief Reads the unique device identifier from memory.
 *
 * @param uniqueID Pointer to an array of 5 uint32_t elements where the unique ID will be stored.
 */
void getUniqueDeviceIdentifier(uint32_t *uniqueID) {
    // Assuming uniqueID is an array of 5 uint32_t elements
    TBLPAG = 0x80;

    uniqueID[0] = __builtin_tblrdl(UNIQUE_ID_START_ADDRESS);
    uniqueID[0] |= ((uint32_t)(__builtin_tblrdh(UNIQUE_ID_START_ADDRESS))) << 16;

    uniqueID[1] = __builtin_tblrdl(UNIQUE_ID_START_ADDRESS + 2);
    uniqueID[1] |= ((uint32_t)(__builtin_tblrdh(UNIQUE_ID_START_ADDRESS + 2))) << 16;

    uniqueID[2] = __builtin_tblrdl(UNIQUE_ID_START_ADDRESS + 4);
    uniqueID[2] |= ((uint32_t)(__builtin_tblrdh(UNIQUE_ID_START_ADDRESS + 4))) << 16;

    uniqueID[3] = __builtin_tblrdl(UNIQUE_ID_START_ADDRESS + 6);
    uniqueID[3] |= ((uint32_t)(__builtin_tblrdh(UNIQUE_ID_START_ADDRESS + 6))) << 16;

    uniqueID[4] = __builtin_tblrdl(UNIQUE_ID_START_ADDRESS + 8);
    uniqueID[4] |= ((uint32_t)(__builtin_tblrdh(UNIQUE_ID_START_ADDRESS + 8))) << 16;
}

/**
 * @brief Transforms the unique device identifier into a 16-bit value.
 *
 * @param uniqueID Pointer to an array of 5 uint32_t elements containing the unique ID.
 * @return uint16_t The transformed 16-bit value.
 */
uint16_t transformUniqueIDTo16Bit(uint32_t *uniqueID) {
    uint16_t transformedID = 0;
    for (int i = 0; i < 5; i++) {
        transformedID ^= (uniqueID[i] & 0xFFFF);         // XOR lower 16 bits
        transformedID ^= ((uniqueID[i] >> 16) & 0xFFFF); // XOR upper 16 bits
    }
    return transformedID;
}