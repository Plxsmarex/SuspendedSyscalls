typedef struct _PROCESS_INFORMATION {
	void *hProcess;
	void *hThread;
	unsigned long dwProcessId;
	unsigned long dwThreadId;
} PROCESS_INFORMATION;

typedef struct _STARTUPINFOA {
	unsigned long cb;
} STARTUPINFOA;

typedef struct _IMAGE_DOS_HEADER {
	unsigned short e_magic;
	unsigned short e_cblp;
	unsigned short e_cp;
	unsigned short e_crlc;
	unsigned short e_cparhdr;
	unsigned short e_minalloc;
	unsigned short e_maxalloc;
	unsigned short e_ss;
	unsigned short e_sp;
	unsigned short e_csum;
	unsigned short e_ip;
	unsigned short e_cs;
	unsigned short e_lfarlc;
	unsigned short e_ovno;
	unsigned short e_res[4];
	unsigned short e_oemid;
	unsigned short e_oeminfo;
	unsigned short e_res2[10];
	long e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned long VirtualAddress;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	unsigned short Machine;
	unsigned short NumberOfSections;
	unsigned long TimeDateStamp;
	unsigned long PointerToSymbolTable;
	unsigned long NumberOfSymbols;
	unsigned short SizeOfOptionalHeader;
	unsigned short Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	unsigned short Magic;
	unsigned char MajorLinkerVersion;
	unsigned char MinorLinkerVersion;
	unsigned long SizeOfCode;
	unsigned long SizeOfInitializedData;
	unsigned long SizeOfUninitializedData;
	unsigned long AddressOfEntryPoint;
	unsigned long BaseOfCode;
	unsigned long long ImageBase;
	unsigned long SectionAlignment;
	unsigned long FileAlignment;
	unsigned short MajorOperatingSystemVersion;
	unsigned short MinorOperatingSystemVersion;
	unsigned short MajorImageVersion;
	unsigned short MinorImageVersion;
	unsigned short MajorSubsystemVersion;
	unsigned short MinorSubsystemVersion;
	unsigned long Win32VersionValue;
	unsigned long SizeOfImage;
	unsigned long SizeOfHeaders;
	unsigned long CheckSum;
	unsigned short Subsystem;
	unsigned short DllCharacteristics;
	unsigned long long SizeOfStackReserve;
	unsigned long long SizeOfStackCommit;
	unsigned long long SizeOfHeapReserve;
	unsigned long long SizeOfHeapCommit;
	unsigned long LoaderFlags;
	unsigned long NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	unsigned long Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	unsigned long Characteristics;
	unsigned long TimeDateStamp;
	unsigned short MajorVersion;
	unsigned short MinorVersion;
	unsigned long Name;
	unsigned long Base;
	unsigned long NumberOfFunctions;
	unsigned long NumberOfNames;
	unsigned long AddressOfFunctions;
	unsigned long AddressOfNames;
	unsigned long AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;
