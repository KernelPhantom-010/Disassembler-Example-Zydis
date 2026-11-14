#include <windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include "include/Zydis/Zydis.h"
#include <cstring>

uint64_t getruntimeAddr(std::string &filePath, int arch){
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE) {printf("\n CreateFile failed in read mode \n");
    return 1;}
    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY , 0, 0, NULL);
    if (hFileMapping == 0){
            printf("\n CreateFileMapping failed \n");
    CloseHandle(hFile);
    return 1;
    }    
    LPVOID fileBaseImportant = MapViewOfFile(hFileMapping, FILE_MAP_READ,0,0,0);
    if(fileBaseImportant==0){
            printf("\n MapViewOfFile failed \n");
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return 1;
    }
    
    IMAGE_DOS_HEADER * dosHeaderToFill = nullptr;
    dosHeaderToFill = (PIMAGE_DOS_HEADER)fileBaseImportant;
    IMAGE_NT_HEADERS *ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBaseImportant + dosHeaderToFill->e_lfanew);
    DWORD offsetPE = dosHeaderToFill->e_lfanew;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int init = 0; init < ntHeaders->FileHeader.NumberOfSections; ++init){
        auto& section = sectionHeader[init];
        if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)){continue;}
        BYTE* code = (BYTE*)fileBaseImportant + section.PointerToRawData; //get data:
        SIZE_T codeSize = section.SizeOfRawData;

        ZyanU64 runTimeAddress = ntHeaders->OptionalHeader.ImageBase + section.VirtualAddress;
        ZydisDecoder decoder;
        if (arch == 64){
            ZyanStatus status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            ZyanUSize offset = 0;
            
            while (offset < codeSize){
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                ZydisDecodedInstruction sectionInformation;
                status = ZydisDecoderDecodeFull(&decoder, code + offset, codeSize - offset, &sectionInformation, operands);
                if (!ZYAN_SUCCESS(status)){
                    offset++;
                    continue;
                }
                char buffer[256];

                ZydisFormatter formatter;
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

                ZydisFormatterFormatInstruction(
                    &formatter,
                    &sectionInformation,
                    operands,
                    sectionInformation.operand_count_visible,
                    buffer,
                    sizeof(buffer),
                    runTimeAddress + offset,
                    nullptr
                );
                printf("0x%llX: %s\n", (unsigned long long)(runTimeAddress + offset), buffer);
                offset += sectionInformation.length;
            }
        }else if (arch == 32){
            ZyanStatus status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
            ZyanUSize offset = 0;
            
            while (offset < codeSize){
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                ZydisDecodedInstruction sectionInformation;
                status = ZydisDecoderDecodeFull(&decoder, code + offset, codeSize - offset, &sectionInformation, operands);
                if (!ZYAN_SUCCESS(status)){
                    offset++;
                    continue;
                }
                char buffer[256];

                ZydisFormatter formatter;
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

                ZydisFormatterFormatInstruction(
                    &formatter,
                    &sectionInformation,
                    operands,
                    sectionInformation.operand_count_visible,
                    buffer,
                    sizeof(buffer),
                    runTimeAddress + offset,
                    nullptr
                );
                printf("0x%llX: %s\n", (unsigned long long)(runTimeAddress + offset), buffer);
                offset += sectionInformation.length;
            }
        }else if (arch == 16){
            ZyanStatus status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_16, ZYDIS_STACK_WIDTH_16);
            ZyanUSize offset = 0;
            
            while (offset < codeSize){
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                ZydisDecodedInstruction sectionInformation;
                status = ZydisDecoderDecodeFull(&decoder, code + offset, codeSize - offset, &sectionInformation, operands);
                if (!ZYAN_SUCCESS(status)){
                    offset++;
                    continue;
                }
                char buffer[256];

                ZydisFormatter formatter;
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

                ZydisFormatterFormatInstruction(
                    &formatter,
                    &sectionInformation,
                    operands,
                    sectionInformation.operand_count_visible,
                    buffer,
                    sizeof(buffer),
                    runTimeAddress + offset,
                    nullptr
                );
                printf("0x%llX: %s\n", (unsigned long long)(runTimeAddress + offset), buffer);
                offset += sectionInformation.length;
            }
        }

    }

}

void analyzeAndDropAsm(std::string &filePath, char* architecture)
{
    HANDLE baseAddr = GetModuleHandleA(nullptr);
    uintptr_t fullBaseAddr = reinterpret_cast<uintptr_t>(baseAddr);
    if (strcmp(architecture, "64b") == 0){
        ZyanU64 runtime_addr = fullBaseAddr;
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;
        getruntimeAddr(filePath, 64); 
    }else if (strcmp(architecture, "32b") == 0){
        ZyanU64 runtime_addr = fullBaseAddr;
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;
        getruntimeAddr(filePath, 32); 
    }else if (strcmp(architecture, "16b") == 0){
        ZyanU64 runtime_addr = fullBaseAddr;
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;
        getruntimeAddr(filePath, 16); 
    }
}

int main(int argc, char* paramss[]){
    if (argc < 3) {printf("Usage: /disaas.exe PATH ARCH.\n\nARCH.-Values: 64b - 32b - 16b\n"); return 0;}
    std::cout << "Checking if file path is valid..";
    std::string filePath = paramss[1];
    bool isValidOrNot = std::filesystem::exists(filePath);
    if (isValidOrNot){
        std::cout << "String is valid! Analyzing.." << std::endl;
        analyzeAndDropAsm(filePath, paramss[2]);
    }else{
        std::cout << "Invalid string path!" << std::endl;
        exit(0);
    }
}