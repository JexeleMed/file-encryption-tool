#ifndef AES_H
#define AES_H

#include <algorithm>
#include <iostream>
#include <random>
#include <array>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>

// Define types for AES blocks
using Block = std::array<uint8_t, 16>;
using Blocks = std::vector<Block>;

class AES {
public:
    /**
     * Constructor to initialize AES with a key and IV.
     * @param key - 128-bit encryption key.
     * @param iv - 128-bit initialization vector.
     */
    AES(const std::array<uint8_t, 16>& key, const std::array<uint8_t, 16>& iv);

    /**
     * Encrypts a file using AES encryption.
     * @param inputFilePath - Path to the input file.
     * @param outputFilePath - Path to save the encrypted file.
     */
    void encryptFile(const std::string& inputFilePath, const std::string& outputFilePath);
    void AES::invMixColumns(Blocks& blocks);
    void decryptFile(const std::string& inputFilePath, const std::string& outputFilePath);

    /**
     * Returns the encryption key as a hexadecimal string.
     * @return Hexadecimal representation of the key.
     */
    std::string getKeyHex() const;

    /**
     * Returns the initialization vector (IV) as a hexadecimal string.
     * @return Hexadecimal representation of the IV.
     */
    std::string getIVHex() const;

    /**
     * Updates the encryption key.
     * @param key - New 128-bit encryption key.
     */
    void setKey(const std::array<uint8_t, 16>& key);

    /**
     * Updates the initialization vector (IV).
     * @param iv - New 128-bit initialization vector.
     */
    void setIV(const std::array<uint8_t, 16>& iv);

private:
    // AES encryption key and initialization vector (IV)
    std::array<uint8_t, 16> key;
    std::array<uint8_t, 16> iv;

    // Precomputed round keys for AES
    std::vector<Block> roundKeys;

    // AES constants
    static const std::array<uint8_t, 256> sbox; // Substitution box
    static const std::array<uint8_t, 10> rcon; // Round constants

    // AES-specific methods
    /**
     * Performs the key expansion for AES encryption.
     * @param key - The initial encryption key.
     * @return A vector of round keys for each AES round.
     */
    std::vector<Block> keyExpansion(const Block& key);

    /**
     * Performs the SubBytes transformation on the data.
     * @param blocks - The data blocks to transform.
     */
    void subBytes(Blocks& blocks);

    /**
     * Performs the ShiftRows transformation on the data.
     * @param blocks - The data blocks to transform.
     */
    void shiftRows(Blocks& blocks);

    /**
     * Performs the MixColumns transformation on the data.
     * @param blocks - The data blocks to transform.
     */
    void mixColumns(Blocks& blocks);

    /**
     * XORs the data with the round key.
     * @param blocks - The data blocks to transform.
     * @param roundKeys - The precomputed round keys.
     * @param round - The current round number.
     */
    void addRoundKey(Blocks& blocks, const std::vector<Block>& roundKeys, size_t round);

    /**
     * Multiplies two numbers in the Galois Field GF(2^8).
     * @param a - First number.
     * @param b - Second number.
     * @return The result of the multiplication.
     */
    uint8_t gfMul(uint8_t a, uint8_t b);

    // File I/O helpers
    /**
     * Loads and pads data from a file.
     * @param filename - Path to the input file.
     * @return A vector of 128-bit blocks representing the file's content.
     */
    Blocks load(const std::string& filename);

    /**
     * Saves encrypted data to a file.
     * @param blocks - The encrypted data blocks.
     * @param filename - Path to save the encrypted file.
     */
    void save(const Blocks& blocks, const std::string& filename);

    // Utility methods
    /**
     * Converts a 128-bit block to a hexadecimal string.
     * @param data - The block to convert.
     * @return Hexadecimal representation of the block.
     */
    std::string toHex(const std::array<uint8_t, 16>& data) const;

    /**
     * Prints data blocks to the console for debugging.
     * @param blocks - The blocks to print.
     */
    void printBlocks(const Blocks& blocks) const;
};

#endif // AES_H
