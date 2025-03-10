#include "AES.h"
#include <iostream>

int main() {

    std::array<uint8_t, 16> key = {0};
    std::array<uint8_t, 16> iv = {0};
    AES aes(key, iv);

    std::string inputFile = "sample.txt";
    std::string decrypted = "decrypted.txt";
    std::string outputFile = "encrypted.bin";

    aes.encryptFile(inputFile, outputFile);
    aes.decryptFile(outputFile, decrypted);



    std::cout << "File encrypted successfully!" << std::endl;
    return 0;
}
