// Includes
#include <windows.h>
#include <stdio.h>

// Defines

// Variables

// File Mapping
HANDLE file, fileMapping;
LPVOID baseAddr;

// Sections Headers

PIMAGE_DOS_HEADER dosHeader;
PIMAGE_NT_HEADERS ntHeader;
PIMAGE_FILE_HEADER header;
PIMAGE_OPTIONAL_HEADER optionalHeader;

// Functions

// Load pe

int loadExe(LPCTSTR filename)
{
    file = CreateFile(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if(file == INVALID_HANDLE_VALUE)
    {
        printf("[-] Couldnt open file.\n");
        return -1;
    }

    fileMapping = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL); // Add SEC_IMAGE_NO_EXECUTE

    if(fileMapping == INVALID_HANDLE_VALUE)
    {
        printf("[-] Couldnt open file mapping.\n");
        CloseHandle(file);
        return -1;
    }

    baseAddr = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);

    if(baseAddr == NULL)
    {
        printf("[-] Couldnt map view of file.\n");
        CloseHandle(file);
        CloseHandle(fileMapping);
        return -1;
    }

    return 0;
}

int loadHeaders()
{
    dosHeader = (PIMAGE_DOS_HEADER)baseAddr;
    ntHeader = (PIMAGE_NT_HEADERS)((DWORD)dosHeader + dosHeader->e_lfanew);
    header = (PIMAGE_FILE_HEADER)(&ntHeader->FileHeader);
    optionalHeader = (PIMAGE_OPTIONAL_HEADER)(&ntHeader->OptionalHeader);

    if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Invalid DOS file.\n");
        return -1;
    }

    if(ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid PE file.\n");
        return -1;
    }

    return 0;
}

int load(char* filename)
{
    if(loadExe((LPCTSTR)filename) == -1) return -1;
    return loadHeaders();
}

void closeFile()
{
    CloseHandle(file);
    CloseHandle(fileMapping);
    UnmapViewOfFile(baseAddr);
}

// Dump pe contents

void dumpNTHeader()
{
    printf("COFF Header:\n");
    printf("Signature: 0x%04lx\n", ntHeader->Signature);
    printf("Machine: 0x%02x\n", header->Machine);
    printf("NumberOfSections: %hd\n", header->NumberOfSections);
    printf("TimeDateStamp: %lu\n", header->TimeDateStamp);
    printf("PointerToSymbolTable: 0x%04lx\n", header->PointerToSymbolTable);
    printf("NumberOfSymbols: %lu\n", header->NumberOfSymbols);
    printf("SizeOfOptionalHeader: %hd\n", header->SizeOfOptionalHeader);
    printf("Characteristics: 0x%02x\n", header->Characteristics);

    // NT Characteristics

    if(header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)       printf("Executable\n");
    if(header->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)    printf("Can handle addresses larger than 2GB\n");
    if(header->Characteristics & IMAGE_FILE_32BIT_MACHINE)          printf("Supports 32bit addresses\n");
    if(header->Characteristics & IMAGE_FILE_SYSTEM)                 printf("System file (Driver)\n");
    if(header->Characteristics & IMAGE_FILE_DLL)                    printf("DLL File\n");
    if(header->Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)         printf("Executable only in a uniprocessor\n");

    printf("\n");
}

void dumpOptionalHeader()
{
    printf("Optional Header:\n");
    printf("Magic: 0x%02x\n", optionalHeader->Magic);
    printf("MajorLinkerVersion: 0x%01x\n", optionalHeader->MajorLinkerVersion);
    printf("MinorLinkerVersion: 0x%01x\n", optionalHeader->MinorLinkerVersion);
    printf("SizeOfCode: %ld\n", optionalHeader->SizeOfCode);
    printf("SizeOfInitializedData: %ld\n", optionalHeader->SizeOfInitializedData);
    printf("SizeOfUninitializedData: %ld\n", optionalHeader->SizeOfUninitializedData);
    printf("AddressOfEntryPoint: 0x%04lx\n", optionalHeader->AddressOfEntryPoint);
    printf("BaseOfCode: 0x%04lx\n", optionalHeader->BaseOfCode);
    printf("BaseOfData: 0x%04lx\n", optionalHeader->BaseOfData);
    printf("ImageBase: 0x%04lx\n", optionalHeader->ImageBase);
    printf("SectionAlignment: 0x%04lx\n", optionalHeader->SectionAlignment);
    printf("FileAlignment: 0x%04lx\n", optionalHeader->FileAlignment);
    printf("MajorOperatingSystemVersion: %hd\n", optionalHeader->MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %hd\n", optionalHeader->MinorOperatingSystemVersion);
    printf("MajorImageVersion: %hd\n", optionalHeader->MajorImageVersion);
    printf("MinorImageVersion: %hd\n", optionalHeader->MinorImageVersion);
    printf("MajorSubsystemVersion: %hd\n", optionalHeader->MajorSubsystemVersion);
    printf("MinorSubsystemVersion: %hd\n", optionalHeader->MinorSubsystemVersion);
    printf("Win32VersionValue: %ld\n", optionalHeader->Win32VersionValue);
    printf("SizeOfImage: %ld\n", optionalHeader->SizeOfImage);
    printf("SizeOfHeaders: %ld\n", optionalHeader->SizeOfHeaders);
    printf("CheckSum: %ld\n", optionalHeader->CheckSum);
    printf("Subsystem: %hd\n", optionalHeader->Subsystem);
    printf("DllCharacteristics: 0x%04x\n", optionalHeader->DllCharacteristics);
    printf("SizeOfStackReserve: %ld\n", optionalHeader->SizeOfStackReserve);
    printf("SizeOfStackCommit: %ld\n", optionalHeader->SizeOfStackCommit);
    printf("SizeOfHeapReserve: %ld\n", optionalHeader->SizeOfHeapReserve);
    printf("SizeOfHeapCommit: %ld\n", optionalHeader->SizeOfHeapCommit);
    printf("LoaderFlags: %ld\n", optionalHeader->LoaderFlags);
    printf("NumberOfRvaAndSizes: %ld\n", optionalHeader->NumberOfRvaAndSizes);
    //IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    printf("\n");
}

void dumpSectionHeader(PIMAGE_SECTION_HEADER section)
{
    printf("Section: %.*s\n", IMAGE_SIZEOF_SHORT_NAME, section->Name);
    printf("PhysycalAddress/VirtualSize: 0x%04lx\n", section->Misc.PhysicalAddress);
    printf("VirtualAddress: 0x%04lx\n", section->VirtualAddress);
    printf("SizeOfRawData: %ld\n", section->SizeOfRawData);
    printf("PointerToRawData: 0x%04lx\n", section->PointerToRawData);
    printf("PointerToRelocations: 0x%04lx\n", section->PointerToRelocations);
    printf("PointerToLinenumbers: 0x%04lx\n", section->PointerToLinenumbers);
    printf("NumberOfRelocations: %hd\n", section->NumberOfRelocations);
    printf("NumberOfLinenumbers: %hd\n", section->NumberOfLinenumbers);
    printf("Characteristics: 0x%04lx\n", section->Characteristics);

    // Section Characteristics
    if(section->Characteristics & IMAGE_SCN_CNT_CODE)                   printf("Code\n");
    if(section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)       printf("Initialized Data\n");
    if(section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)     printf("Uninitialized Data\n");
    if(section->Characteristics & IMAGE_SCN_LNK_INFO)                   printf("Comments and/or Linker info\n");
    if(section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)             printf("Cannot be cached\n");
    if(section->Characteristics & IMAGE_SCN_MEM_NOT_PAGED)              printf("Cannot be paged\n");
    if(section->Characteristics & IMAGE_SCN_MEM_SHARED)                 printf("Can be shared\n");
    if(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)                printf("Executable\n");
    if(section->Characteristics & IMAGE_SCN_MEM_READ)                   printf("Readable\n");
    if(section->Characteristics & IMAGE_SCN_MEM_WRITE)                  printf("Writable\n");

    printf("\n");
}

void dumpSectionHeaders()
{
    PIMAGE_SECTION_HEADER section;

    unsigned int i;
    for(section = IMAGE_FIRST_SECTION(ntHeader), i = 0; i < header->NumberOfSections; i++, section++)
    {
        dumpSectionHeader(section);
    }
}
