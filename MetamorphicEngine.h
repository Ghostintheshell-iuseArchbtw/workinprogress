#ifndef METAMORPHICENGINE_H
#define METAMORPHICENGINE_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <thread>
#include <mutex>

class MetamorphicEngine {
public:
    // Constructor
    MetamorphicEngine(const std::string& inputFile, const std::string& outputFile);

    // Main obfuscation method
    void obfuscate();

    // Add a custom obfuscation technique
    void addTechnique(std::function<void(std::vector<uint8_t>&)> technique);

    // Set obfuscation intensity (0-100)
    void setIntensity(int intensity);

    // Select specific obfuscation techniques
    void selectTechniques(const std::vector<std::string>& techniques);

private:
    // File names
    std::string inputFileName;
    std::string outputFileName;

    // Container for file data
    std::vector<uint8_t> fileData;

    // Read the input file into fileData
    void readFile();

    // Write the obfuscated data to the output file
    void writeFile();

    // Perform all obfuscation techniques
    void performObfuscation();

    // Obfuscation techniques
    void controlFlowFlattening();
    void instructionSubstitution();
    void registerRenaming();
    void codeEncryption();
    void insertGarbageCode();
    void insertAntiDebugging();
    void generateDynamicCode();
    void applyCodeTransformation();
    void encryptCode();
    void decryptCode();
    void antiDebuggingCheck();
    void addStackSmashingProtection();
    void includeAntiReverseEngineeringTechniques();
    void insertNOPsleds();
    void insertROPchains();
    void duplicateStackFrames();

    // Custom obfuscation techniques
    std::vector<std::function<void(std::vector<uint8_t>&)>> customTechniques;

    // Obfuscation intensity
    int intensity;

    // Selected obfuscation techniques
    std::vector<std::string> selectedTechniques;

    // Mutex for multi-threading
    std::mutex mtx;
};

#endif // METAMORPHICENGINE_H
