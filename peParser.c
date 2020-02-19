#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

IMAGE_DOS_HEADER DH;
IMAGE_NT_HEADERS NH;
IMAGE_SECTION_HEADER *SH;
IMAGE_IMPORT_DESCRIPTOR *ID;
FILE* fileIn;

DWORD RVAtoRAW(DWORD RVA)
{
	int i;
	DWORD raw;
	for (i = 0;i < NH.FileHeader.NumberOfSections -1;i++)
	{
		if (RVA >= SH[i].VirtualAddress && RVA <= SH[i + 1].VirtualAddress)
		{
			raw = RVA - SH[i].VirtualAddress + SH[i].PointerToRawData;
		}
	}
	return raw;
}

void printDosHeader()
{
	printf("< DOS HEADER >\n");
	printf("| MZ Signature: %x %x(%c%c)\n",DH.e_magic & 0xff,(DH.e_magic & 0xff00) >> 8, DH.e_magic & 0xff, (DH.e_magic & 0xff00) >> 8);
	printf("| NT header offset: 0x%02x\n",DH.e_lfanew);
	printf("\n\n");
}

void printOptionalHeader()
{
	printf("| Optional Magic: 0x%x", NH.OptionalHeader.Magic);
	switch (NH.OptionalHeader.Magic)
	{
	case 0x10b: printf(" -> (IMAGE_OPTIONAL_HEADER32) \n"); break;
	case 0x20b: printf(" -> (IMAGE_OPTIONAL_HEADER64) \n"); break;
	}
	printf("| Address of Entry Point: 0x%x\n", NH.OptionalHeader.AddressOfEntryPoint);
	printf("| Image Base: 0x%x\n", NH.OptionalHeader.ImageBase);
	printf("| Section Alignment: 0x%x\n", NH.OptionalHeader.SectionAlignment);
	printf("| File Alignment: 0x%x\n", NH.OptionalHeader.FileAlignment);
	printf("| Size of Image: 0x%x\n", NH.OptionalHeader.SizeOfImage);
	printf("| Size of Headers: 0x%x\n", NH.OptionalHeader.SizeOfHeaders);
	printf("| Subsystem: 0x%x", NH.OptionalHeader.Subsystem);
	switch (NH.OptionalHeader.Subsystem)
	{
	case 0x1: printf(" -> (Driver file) \n");break;
	case 0x2: printf(" -> (GUI file) \n"); break;
	case 0x3: printf(" -> (CUI file) \n"); break;
	}
	printf("| Number of RVA sizes: 0x%x\n", NH.OptionalHeader.NumberOfRvaAndSizes);
	printf("\n\n");
}

void printNTHeader()
{
	printf("< NT HEADER >\n");
	printf("| Signature: %x %x(%c%c)\n", NH.Signature & 0xff, (NH.Signature & 0xff00) >> 8, NH.Signature & 0xff, (NH.Signature & 0xff00) >> 8);
	printf("| MACHINE: 0x%x",NH.FileHeader.Machine);
	switch(NH.FileHeader.Machine)
	{
		case 0x14c:	printf(" -> (IA32) \n"); break;
		case 0x200: printf(" -> (IA64) \n"); break;
		case 0x8664: printf(" -> (AMD64) \n"); break;
	}
	printf("| Number of Section: 0x%x\n",NH.FileHeader.NumberOfSections);
	printf("| Size of OptionalHeader: 0x%x\n",NH.FileHeader.SizeOfOptionalHeader);
	printf("| File Characteristics: 0x%x\n", NH.FileHeader.Characteristics);
	printOptionalHeader();
}

void printSectionHeader()
{
	int i;
	printf("< SECTION HEADER >\n");
	for (i = 0;i < NH.FileHeader.NumberOfSections;i++)
	{
		printf("| Name: %s\n", SH[i].Name);
		printf("| Virtual Size: 0x%x\n", SH[i].Misc.VirtualSize);
		printf("| Virtual Address: 0x%x\n", SH[i].VirtualAddress);
		printf("| Size of Raw Data: 0x%x\n", SH[i].SizeOfRawData);
		printf("| Pointer of Raw Data: 0x%x\n", SH[i].PointerToRawData);
		printf("| Characteristics: 0x%x\n", SH[i].Characteristics);
		printf("\n");
	}
	printf("\n\n");
}

void readName(DWORD raw)
{
	char* name = (char*)malloc(sizeof(char) * 256);
	int i=0;
	fseek(fileIn, raw, SEEK_SET);
	do {
		fread(&name[i], 1, 1, fileIn);
		printf("%c", name[i]);
		i++;
	} while (name[i-1]!=0x0);
	printf("\n");
}

void INTable(DWORD raw)
{
	DWORD another=0;
	int i=0;
	char* name;
	fseek(fileIn, raw, SEEK_SET);
	do {
		fread(&another, 4, 1, fileIn);
		if (!another) break;
		fseek(fileIn, RVAtoRAW(another)+2, SEEK_SET);
		name = (char*)malloc(sizeof(char) * 256);
		printf("|\t");
		do {
			fread(&name[i], 1, 1, fileIn);
			if(name[i]!=0x0) printf("%c", name[i]);
			i++;
		} while (name[i-1] != 0x0);
		printf("\n");
		free(name);
		i = 0;
		raw += 4;
		fseek(fileIn, raw, SEEK_SET);
	} while (another);
}
void printID()
{
	int i;
	printf("< IMPORT DESCRIPTOR >\n|\n");
	for (i = 0;i < NH.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1;i++)
	{
		printf("| Original First Thunk: 0x%x (raw: 0x%x) \n", ID[i].OriginalFirstThunk, RVAtoRAW(ID[i].OriginalFirstThunk));
		printf("| IMAGE IMPORT BY NAME(INT): \n");
		INTable(RVAtoRAW(ID[i].OriginalFirstThunk));
		printf("| Name: 0x%x (raw: 0x%x) -> ", ID[i].Name, RVAtoRAW(ID[i].Name));
		readName(RVAtoRAW(ID[i].Name));
		printf("| First Thunk: 0x%x (raw: 0x%x)\n\n", ID[i].FirstThunk, RVAtoRAW(ID[i].FirstThunk));
	}
	printf("\n\n");
}

int main(void) {
	int filesize;
	char* filename;
	int i;
	filename = malloc(sizeof(char) * 256);
	printf("파일 이름을 입력하세요 : ");
	scanf("%s", filename);
	printf("\n\n");
	if ((fileIn = fopen(filename, "rb")) == NULL) {
		fputs("File Open Error!\n", stderr);
		return;
	}
	fseek(fileIn, 0, SEEK_END); //get file size
	filesize = ftell(fileIn);
	rewind(fileIn);
	fread(&DH, sizeof(IMAGE_DOS_HEADER), 1, fileIn); //IMAGE_DOS_HEADER
	printDosHeader(); //print imaeg_dos_header
	fseek(fileIn, DH.e_lfanew, SEEK_SET); //find image_nt_header
	fread(&NH, sizeof(IMAGE_NT_HEADERS), 1, fileIn); //IMAGE_NT_HEADERS
	printNTHeader(); //print IMAGE_NT_HEADERS
	SH = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * NH.FileHeader.NumberOfSections); //malloc with number of sections
	for (i = 0;i < NH.FileHeader.NumberOfSections;i++)
	{
		fread(&SH[i], sizeof(IMAGE_SECTION_HEADER), 1, fileIn); //IMAGE_SECTION_HEADER
	}
	printSectionHeader(); //print IMAGE_SECTION_HEADER[]
	fseek(fileIn, RVAtoRAW(NH.OptionalHeader.DataDirectory[1].VirtualAddress), SEEK_SET); //find IMAGE_IMPORT_DESCRIPTOR's start point
	ID = (IMAGE_IMPORT_DESCRIPTOR*)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR) * (NH.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1)); // -1 means last structure is null
	for (i = 0;i < NH.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1;i++)
	{
		fread(&ID[i], sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, fileIn); //IMAGE_IMPORT_DESCRIPTOR
	}
	printID(); //print IMAGE_IMPORT_DESCRIPTOR[]
	printf("\n");
	free(filename);
	fclose(fileIn);
	return 0;
}