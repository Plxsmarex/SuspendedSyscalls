# SuspendedSyscalls
Extracting syscall numbers from a suspended process before it can be hooked or obfuscated by an EDR

# Windows System Calls
To execute a syscall on Windows you need the system service number (Also known as syscall numbers), the issue with this is that they are sometimes different on versions of the operating system, so you can't hardcode them.

Windows uses syscalls for the Nt/Zw native API functions in ntdll.dll and for NtUser/NtGdi in win32u.dll, so the solution was to dynamically find the syscall number in these libraries, projects like Hell's Gate do this by finding the location of an Nt export in NTDLL in memory, and then extracting the syscall number from it. You can also read NTDLL from the disk, but EDRs will find it suspicious.

The issue with Hell's Gate was that many EDR and other security solutions were hooking the native API, which also hid the syscall numbers, meaning that trying to directly find an Nt export's syscall number would fail. Because of this, a new project named Halo's Gate was created. This had an additional feature of detecting if the first byte was a jmp instruction, where it would then search for a nearby Nt export and get its syscall number, then add or subtract the number based on how many Nt exports it had to travel to find the clean one.

This works because Windows syscall numbers are sorted in ascending order. But what if every Nt export was hooked? Then you can simply find all Nt exports in NTDLL and sort them by address, the issue with this is that if Windows ever decides to not sort syscall numbers in order, this would fail. Also security solutions might be able to add dummy Nt exports to trick it.

SuspendedSyscalls is the solution to all of these problems: It doesn't care about if the exports are hooked or not, it doesn't care about the order of the syscall numbers, and EDRs likely won't care about the APIs it uses.

# How it works
SuspendedSyscalls will create a process and suspend it, by doing this, EDRs and other security solutions won't have hooked NTDLL yet, which lets us easily get the syscall numbers without having to worry about hooks or other types of potential obfuscation.

For this example, it will just print every Nt export and its syscall number, however it could be modified to do stuff like using the newly acquired numbers to inject shellcode into the suspended process using syscalls.

SuspendedSyscalls uses my Shellcode-Toolkit library, meaning it also compiles a small 1056 byte position independent flat binary file, and a tiny 2048 bytes executable file.

# Potential issues
SuspendedSyscalls itself could be detected using API hooking/monitoring, as it requires CreateProcessA and ReadProcessMemory to get the syscall numbers.

If there is a big Windows update that changes the structure of NTDLL or how processes operate, it could cause issues.

# Credits
https://github.com/am0nsec/HellsGate - Hell's Gate project

https://blog.sektor7.net/#!res/2021/halosgate.md - Halo's Gate project

https://blog.sektor7.net/#!res/2021/perunsfart.md - Using a suspended process NTDLL to unhook the Nt APIs, similar to this project

https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - Mentions the sorting by syscall address technique
