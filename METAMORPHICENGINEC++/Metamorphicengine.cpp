#ifndef METAMORPHICENGINE_H
#define METAMORPHICENGINE_H

#include <string>
#include <vector>
#include <cstdint>  // This header defines uint8_t and other fixed-width integer types

class MetamorphicEngine {
public:
    // Constructor
    MetamorphicEngine(const std::string& inputFile, const std::string& outputFile);

    // Main obfuscation method
    void obfuscate();

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
    void reorderCode();
    void substituteInstructions();
    void insertGarbageCode();
    void insertAntiDebugging();
    void generateDynamicCode();
    void executeDynamicCode(const std::vector<uint8_t>& code);
    void applyCodeTransformation();
    void encryptCode();
    void decryptCode();
    void antiDebuggingCheck();
    void addStackSmashingProtection();
    void includeAntiReverseEngineeringTechniques();
    void insertNOPsleds();
    void insertROPchains();
    void duplicateStackFrames();
};

#endif // METAMORPHICENGINE_H
#ifndef METAMORPHICENGINE_H
#define METAMORPHICENGINE_H

#include <string>
#include <vector>

class MetamorphicEngine {
public:
    // Constructor
    MetamorphicEngine(const std::string& inputFile, const std::string& outputFile);

    // Main obfuscation method
    void obfuscate();

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
    void reorderCode();
    void substituteInstructions();
    void insertGarbageCode();
    void insertAntiDebugging();
    void generateDynamicCode();
    void executeDynamicCode(const std::vector<uint8_t>& code);
    void applyCodeTransformation();
    void encryptCode();
    void decryptCode();
    void antiDebuggingCheck();
    void addStackSmashingProtection();
    void includeAntiReverseEngineeringTechniques();
    void insertNOPsleds();
    void insertROPchains();
    void duplicateStackFrames();
};

#endif // METAMORPHICENGINE_H

