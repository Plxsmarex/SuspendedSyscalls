#include "Structs.h"

#define createstring __attribute__((section(".text.data"), used))

// Functions from Shellcode-Toolkit
static void *GetPEBBase() {
	void *PEB = 0;
	asm volatile("movq %%gs:0x60, %0" : "=r"(PEB));
	return PEB;
}

static void *GetDLLBase(void *PEBBase, unsigned int ModuleHash) {
	unsigned char *ModulesListEntry = *(unsigned char**)(*(unsigned char**)((unsigned char*)PEBBase + 0x18) + 0x20);
	for (;ModulesListEntry && ModulesListEntry != *(unsigned char**)((unsigned char*)PEBBase + 0x18) + 0x20; ModulesListEntry = *(unsigned char**)(ModulesListEntry)) {
		unsigned short *NameBuffer = *(unsigned short**)(ModulesListEntry + 0x50);
		int NameIndex, NameLength = *(unsigned short*)(ModulesListEntry + 0x48) >> 1;
		unsigned int ModuleHashCalc = 5381;
		for (NameIndex = 0; NameIndex < NameLength; ++NameIndex) ModuleHashCalc = (ModuleHashCalc * 33) + NameBuffer[NameIndex];
		if (ModuleHashCalc == ModuleHash) return *(void**)(ModulesListEntry + 0x20);
	}
}

static void *GetExportAddress(void *ModuleBase, unsigned int ExportHash) {
	unsigned char *OptionalHeader = ModuleBase + *(unsigned int*)(ModuleBase + 0x3C) + 24;
	unsigned char *ExportDirectory = ModuleBase + *(unsigned int*)(*(unsigned short*)OptionalHeader == 0x20B ? OptionalHeader + 0x70 : OptionalHeader + 0x60);
	for (unsigned int Index = 0; Index < *(unsigned int*)(ExportDirectory + 0x18); Index++) {
		unsigned int ExportHashCalc = 5381;
		for (const unsigned char *Ptr = (const unsigned char*)(ModuleBase + *(unsigned int*)(ModuleBase + *(unsigned int*)(ExportDirectory + 0x20) + Index * 4)); *Ptr; ++Ptr) ExportHashCalc = ((ExportHashCalc << 5) + ExportHashCalc) + (unsigned int)(*Ptr);
		if (ExportHashCalc == ExportHash) return ModuleBase + *(unsigned int*)(ModuleBase + *(unsigned int*)(ExportDirectory + 0x1C) + *(unsigned short*)(ModuleBase + *(unsigned int*)(ExportDirectory + 0x24) + Index * 2) * 4);
	}
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
	typedef int (*CreateProcessAType)(const char *lpApplicationName, char *lpCommandLine, void *lpProcessAttributes, void *lpThreadAttributes, int bInheritHandles, unsigned long dwCreationFlags, void *lpEnvironment, const char *lpCurrentDirectory, void *lpStartupInfo, void *lpProcessInformation);
	CreateProcessAType CreateProcessA = (CreateProcessAType)GetExportAddress(Kernel32Base, 0xAEB52E19); // "CreateProcessA"

	typedef int (*ReadProcessMemoryType)(void *hProcess, const void *lpBaseAddress, void *lpBuffer, unsigned long nSize, unsigned long *lpNumberOfBytesRead);
	ReadProcessMemoryType ReadProcessMemory = (ReadProcessMemoryType)GetExportAddress(Kernel32Base, 0xB8932459); // "ReadProcessMemory"

	typedef int (*TerminateProcessType)(void *hProcess, unsigned int uExitCode);
	TerminateProcessType TerminateProcess = (TerminateProcessType)GetExportAddress(Kernel32Base, 0x60AF076D); // "TerminateProcess"

	// FOR PRINTF
	typedef void *(*LoadLibraryAType)(const char *lpLibFileName);
	LoadLibraryAType LoadLibraryA = (LoadLibraryAType)GetExportAddress(Kernel32Base, 0x5FBFF0FB); // "LoadLibraryA"

	void *MSVCRTBaseAddress = LoadLibraryA(CLibrary);

	typedef int (*printfType)(const char *, ...);
	printfType printf = (printfType)GetExportAddress(MSVCRTBaseAddress, 0x156B2BB8); // "printf"

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

	// Read the process export directory
	IMAGE_EXPORT_DIRECTORY ExportDirectory;
	ReadProcessMemory(ProcessHandle, (const void *)((unsigned long long)NTDLLBase + NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress), &ExportDirectory, (unsigned long)sizeof(ExportDirectory), &BytesReadLocal);

	// 64 should be long enough to survive the feared NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
	char ExportNameBuffer[64];
	unsigned int NameRVA = 0;
	unsigned short Ordinal = 0;
	unsigned int FunctionRVA = 0;
	unsigned long BytesRead = 0;

	// Print the service number of every Nt export in the suspended process NTDLL
	for (unsigned int Index = 0; Index < (unsigned int)ExportDirectory.NumberOfNames; ++Index) {
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
}
