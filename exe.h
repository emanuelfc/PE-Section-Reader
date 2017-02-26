#ifndef EXE_H_INCLUDED
#define EXE_H_INCLUDED

int loadExe(char* filename);
void closeFile();
void dumpNTHeader();
void dumpOptionalHeader();
void dumpSectionHeaders();

#endif // EXE_H_INCLUDED
