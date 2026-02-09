#include "Structs.h"

#define createstring __attribute__((section(".text.data"), used))

// Functions from Shellcode-Toolkit
static void *GetPEBBase() {
	void *PEB = 0;
	asm volatile("movq %%gs:0x60, %0" : "=r"(PEB));
	return PEB;
}

static void *GetDLLBase(void *PEBBase, unsigned int ModuleHash) {
	unsigned char *LDRData = *(unsigned char**)((unsigned char*)PEBBase + 0x18);
	unsigned char *InLoadOrderList = LDRData + 0x20;
	unsigned char *CurrentListEntry = *(unsigned char**)(InLoadOrderList);
	for (; CurrentListEntry && CurrentListEntry != InLoadOrderList; CurrentListEntry = *(unsigned char**)(CurrentListEntry)) {
		unsigned char *ModuleEntry = CurrentListEntry - 0x10;
		void *ModuleBase = *(void**)(ModuleEntry + 0x30);
		unsigned short NameLengthBytes = *(unsigned short*)(ModuleEntry + 0x58);
		unsigned short *NameBuffer = *(unsigned short**)(ModuleEntry + 0x60);
		int NameLengthChars = (int)(NameLengthBytes >> 1);
		unsigned int ModuleHashCalc = 5381u;
		for (int NameIndex = 0; NameIndex < NameLengthChars; ++NameIndex) {
			unsigned char NameChar = (unsigned char)NameBuffer[NameIndex];
			ModuleHashCalc = ((ModuleHashCalc << 5) + ModuleHashCalc) + (unsigned int)NameChar;
		}
		if (ModuleHashCalc == ModuleHash) {
			return ModuleBase;
		}
	}
	return 0;
}

static void *GetExportAddress(void *ModuleBase, unsigned int ExportHash) {
	unsigned int PEHeaderOffset = *(unsigned int*)(ModuleBase + 0x3C);
	unsigned char *OptionalHeader = ModuleBase + PEHeaderOffset + 4 + 20;
	unsigned short Magic = *(unsigned short*)OptionalHeader;
	unsigned char *DataDirectory = (Magic == 0x20B ? OptionalHeader + 0x70 : OptionalHeader + 0x60);
	unsigned char *ExportDirectory = ModuleBase + *(unsigned int*)DataDirectory;
	unsigned int NumberOfNames = *(unsigned int*)(ExportDirectory + 0x18);
	unsigned int AddressOfFunctionsRVA = *(unsigned int*)(ExportDirectory + 0x1C);
	unsigned int AddressOfNamesRVA = *(unsigned int*)(ExportDirectory + 0x20);
	unsigned int AddressOfNameOrdinalsRVA = *(unsigned int*)(ExportDirectory + 0x24);
	for (unsigned int Index = 0; Index < NumberOfNames; Index++) {
		const unsigned char *Name = (const unsigned char*)(ModuleBase + *(unsigned int*)(ModuleBase + AddressOfNamesRVA + Index * 4));
		unsigned int ExportHashCalc = 5381u;
		for (const unsigned char *Ptr = Name; *Ptr; ++Ptr) {
			ExportHashCalc = ((ExportHashCalc << 5) + ExportHashCalc) + (unsigned int)(*Ptr);
		}
		if (ExportHashCalc == ExportHash) {
			unsigned short Ordinal = *(unsigned short*)(ModuleBase + AddressOfNameOrdinalsRVA + Index * 2);
			void *Address = ModuleBase + *(unsigned int*)(ModuleBase + AddressOfFunctionsRVA + Ordinal * 4);
			return Address;
		}
	}
	return 0;
}

// FOR PRINTF
createstring char CLibrary[] = "MSVCRT";
createstring char PrintResults[] = "%s: 0x%03x\n";

// Process to suspend
createstring char ProcessToSuspend[] = "notepad.exe";

__attribute__((section(".text.entrypoint"), used))
int EntryPoint() {
	void *PEBBase = GetPEBBase();

	void *Kernel32Base = GetDLLBase(PEBBase, 0x6DDB9555); // "KERNEL32.DLL"
	void *NTDLLBase = GetDLLBase(PEBBase, 0x22D3B5ED); // "ntdll.dll"

	// Get required functions
	void *CreateProcessAPointer = GetExportAddress(Kernel32Base, 0xAEB52E19); // "CreateProcessA"
	typedef int (*CreateProcessAType)(const char *lpApplicationName, char *lpCommandLine, void *lpProcessAttributes, void *lpThreadAttributes, int bInheritHandles, unsigned long dwCreationFlags, void *lpEnvironment, const char *lpCurrentDirectory, void *lpStartupInfo, void *lpProcessInformation);
	CreateProcessAType CreateProcessA = (CreateProcessAType)CreateProcessAPointer;

	void *ReadProcessMemoryPointer = GetExportAddress(Kernel32Base, 0xB8932459); // "ReadProcessMemory"
	typedef int (*ReadProcessMemoryType)(void *hProcess, const void *lpBaseAddress, void *lpBuffer, unsigned long nSize, unsigned long *lpNumberOfBytesRead);
	ReadProcessMemoryType ReadProcessMemory = (ReadProcessMemoryType)ReadProcessMemoryPointer;

	void *TerminateProcessPointer = GetExportAddress(Kernel32Base, 0x60AF076D); // "TerminateProcess"
	typedef int (*TerminateProcessType)(void *hProcess, unsigned int uExitCode);
	TerminateProcessType TerminateProcess = (TerminateProcessType)TerminateProcessPointer;

	// FOR PRINTF
	void *LoadLibraryAPointer = GetExportAddress(Kernel32Base, 0x5FBFF0FB); // "LoadLibraryA"
	typedef void *(*LoadLibraryAType)(const char *lpLibFileName);
	LoadLibraryAType LoadLibraryA = (LoadLibraryAType)LoadLibraryAPointer;

	LoadLibraryA(CLibrary);

	void *MSVCRTBaseAddress = GetDLLBase(PEBBase, 0x7A21064E); // "MSVCRT.DLL"

	void *PrinterPointer = GetExportAddress(MSVCRTBaseAddress, 0x156B2BB8); // "printf"
	typedef int (*printfType)(const char *, ...);
	printfType printf = (printfType)PrinterPointer;

	// Create suspended process
	PROCESS_INFORMATION ProcessInfo;
	STARTUPINFOA StartupInfo = {0}; StartupInfo.cb = sizeof(StartupInfo);
	CreateProcessA(0, ProcessToSuspend, 0, 0, 0, 0x00000004 | 0x08000000, 0, 0, &StartupInfo, &ProcessInfo);

	void *ProcessHandle = ProcessInfo.hProcess;

	// Read the DOS header of the suspended process
	IMAGE_DOS_HEADER DOSHeader;
	unsigned long BytesReadLocal = 0;
	ReadProcessMemory(ProcessHandle, NTDLLBase, &DOSHeader, (unsigned long)sizeof(DOSHeader), &BytesReadLocal);

	// Read the process PE headers
	IMAGE_NT_HEADERS64 NTHeaders;
	ReadProcessMemory(ProcessHandle, (const void *)((unsigned long long)NTDLLBase + DOSHeader.e_lfanew), &NTHeaders, (unsigned long)sizeof(NTHeaders), &BytesReadLocal);

	unsigned long ExportRVA = NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;

	// Read the process export directory
	IMAGE_EXPORT_DIRECTORY ExportDirectory;
	ReadProcessMemory(ProcessHandle, (const void *)((unsigned long long)NTDLLBase + ExportRVA), &ExportDirectory, (unsigned long)sizeof(ExportDirectory), &BytesReadLocal);

	unsigned int NumberOfNames = (unsigned int)ExportDirectory.NumberOfNames;
	unsigned int NumberOfFunctions = (unsigned int)ExportDirectory.NumberOfFunctions;

	// 64 should be long enough to survive the feared NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
	char ExportNameBuffer[64];
	unsigned int NameRVA = 0;
	unsigned short Ordinal = 0;
	unsigned int FunctionRVA = 0;
	unsigned long BytesRead = 0;

	// Print the service number of every Nt export in the suspended process NTDLL
	for (unsigned int Index = 0; Index < NumberOfNames; ++Index) {
		// NTDLL base of the suspended process should be the same as this process.
		ReadProcessMemory(ProcessHandle, (const void *)((unsigned long long)NTDLLBase + ExportDirectory.AddressOfNames + Index * sizeof(unsigned int)), &NameRVA, (unsigned long)sizeof(unsigned int), &BytesRead);

		ReadProcessMemory(ProcessHandle, (const void *)((unsigned long long)NTDLLBase + NameRVA), ExportNameBuffer, (unsigned long)(sizeof(ExportNameBuffer) - 1), &BytesRead);

		// Skip every other NTDLL export
		if (ExportNameBuffer[0] != 'N' || ExportNameBuffer[1] != 't') continue;
		if (ExportNameBuffer[2] == 'd') continue;

		ReadProcessMemory(ProcessHandle, (const void *)((unsigned long long)NTDLLBase + ExportDirectory.AddressOfNameOrdinals + Index * sizeof(unsigned short)), &Ordinal, (unsigned long)sizeof(unsigned short), &BytesRead);

		ReadProcessMemory(ProcessHandle, (const void *)((unsigned long long)NTDLLBase + ExportDirectory.AddressOfFunctions + ((unsigned int)Ordinal * sizeof(unsigned int))), &FunctionRVA, (unsigned long)sizeof(unsigned int), &BytesRead);

		unsigned char FunctionCode[64];
		ReadProcessMemory(ProcessHandle, (const void *)((unsigned long long)NTDLLBase + FunctionRVA), FunctionCode, (unsigned long)sizeof(FunctionCode), &BytesRead);

		// Extract the system service number, this should work correctly as the functions wont be hooked
		unsigned int ServiceNumber = *(const unsigned int*)(FunctionCode + 4);
		printf(PrintResults, ExportNameBuffer, ServiceNumber);
	}

	// Terminate the suspended process
	TerminateProcess(ProcessHandle, 0);
	return 3;
}
