#include <stdio.h>
#include <stdlib.h>
#include "exe.h"

int main(int argc, char *argv[])
{
    if(argc < 2)
    {
        printf("Usage: <filename>\n");
        return -1;
    }

    if(load(argv[1]) < 0)
    {
        printf("[-] An error has occured loading the executable.\n");
        return -1;
    }

    printf("[+] Successfully opened the executable... Dumping contents\n\n");

    dumpNTHeader();
    dumpOptionalHeader();
    dumpSectionHeaders();

    // Remove executable from memory
    closeFile();

    return 0;
}

