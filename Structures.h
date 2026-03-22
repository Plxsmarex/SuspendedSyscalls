// Function types
typedef void *(*Type_LoadLibraryA)(const char *lpLibFileName);
typedef int   (*Type_CreateProcessA)(const char *lpApplicationName, char *lpCommandLine, void *lpProcessAttributes, void *lpThreadAttributes, int bInheritHandles, unsigned long dwCreationFlags, void *lpEnvironment, const char *lpCurrentDirectory, void *lpStartupInfo, void *lpProcessInformation);
typedef int   (*Type_ReadProcessMemory)(void *hProcess, const void *lpBaseAddress, void *lpBuffer, unsigned long nSize, unsigned long *lpNumberOfBytesRead);
typedef int   (*Type_printf)(const char *, ...);

// Structures
typedef struct {
	void *hProcess;
	void *hThread;
	unsigned long dwProcessId;
	unsigned long dwThreadId;
} PROCESS_INFORMATION;

typedef struct {
	unsigned long cb;
	char *lpReserved;
	char *lpDesktop;
	char *lpTitle;
	unsigned long dwX;
	unsigned long dwY;
	unsigned long dwXSize;
	unsigned long dwYSize;
	unsigned long dwXCountChars;
	unsigned long dwYCountChars;
	unsigned long dwFillAttribute;
	unsigned long dwFlags;
	unsigned short wShowWindow;
	unsigned short cbReserved2;
	unsigned char *lpReserved2;
	void *hStdInput;
	void *hStdOutput;
	void *hStdError;
} STARTUPINFOA;

typedef struct {
	void *Reserved1;
	void *PebBaseAddress;
	void *Reserved2[2];
	unsigned long long UniqueProcessId;
	void *Reserved3;
} PROCESS_BASIC_INFORMATION;
