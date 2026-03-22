# SuspendedSyscalls
Extracting clean syscall numbers from a suspended process before injecting shellcode into it using indirect syscalls

# Windows system calls
To execute a syscall on Windows, you need the system service number (Also known as syscall numbers), the issue with this is that they can be different on versions of the operating system, so it's not safe to hardcode them.

Windows uses syscalls for the Nt/Zw native API functions in ntdll.dll and for NtUser and NtGdi in win32u.dll, the solution to the issue should be to dynamically find the syscall number in these libraries, so that it always gets the right one for the operation system version. Projects like Hell's Gate do this by finding the address of an Nt function in NTDLL in memory, and then extracting the syscall number from it. You can also use the Windows API to read NTDLL from the disk, but EDRs could find that suspicious.

The issue with Hell's Gate, was that many EDR and other security solutions were hooking the native APIs, which also hid the syscall numbers, meaning that trying to directly find an Nt function's syscall number would fail. Because of this, a new project named Halo's Gate was created. This had an additional feature of detecting if the first byte was a jmp instruction, where it would then search for a nearby Nt function and get its syscall number, then add or subtract the number based on how many Nt functions it had to travel to find the clean one. This works because Windows syscall numbers are sorted in ascending order; you can predict what a certain function's number is based on other nearby functions.

But what if every Nt function was hooked? Then you can simply find all Nt functions in NTDLL and sort them by address, this works because of Windows having them in order. A possible problem with this would be that if Windows ever decides to not sort syscall numbers in order, this would fail. Security solutions also might be able to add dummy Nt functions to trick it.

SuspendedSyscalls is the solution to all of these problems; it doesn't care about if the functions are hooked or not, it doesn't care about the order of the syscall numbers, and EDRs likely won't care about the APIs it uses to find them.

# How it works
SuspendedSyscalls will first create a suspended process, by doing this, EDRs and other security solutions won't have hooked NTDLL yet, which lets us easily read the syscall numbers without having to worry about hooks or any other types of potential obfuscation. For each syscall number we find, SuspendedSyscalls will print it along with the symbol name of the function it belongs to. When looping through each one, we will have a few target functions to get and save the syscall number for.

Near the start of the program, we got the addresses for several Nt functions, and after the loop we saved syscall numbers for a few functions, now we will use these to perform indirect syscalls...

# Indirect syscalls
For a program to execute a syscall on Windows, the most common approach is to replicate what happens in an Nt function stub and embed that in the program, this is usually known as a direct syscall. While direct syscalls have worked well, they had several big problems; first of all, the syscall instruction (0F05) was visible in a disassembly for a program using them, legitimate programs rarely use them on Windows so it's a reliable indicator of something wrong, and the second even bigger problem was that EDRs could watch the callstack, where it would show that the program did a direct call to the kernel, with no calls to library functions in between like it should have.

The fix to this is to jump to the syscall instruction in a library like NTDLL, therefore the callstack would show that the syscall came from the legitimate library, doing it like this is known as an indirect syscall. They still have some issues though; the callstack now shows a direct call to a native API, which while quite common in legitimate software, directly calling native APIs like NtProtectVirtualMemory can be an indicator, these can be avoided using other techniques, but for this example we won't go that far. Another detection of indirect syscalls could be to try to see if the syscall instruction was jumped to directly instead of reached from a normal native API call, for example if the Nt function is hooked by an EDR, a legitimate callstack would show it go to the EDRs module, but since an indirect syscall goes past any hooks, that wouldn't be visible on the callstack.

# Entry point injection
Continuing to SuspendedSyscalls, now we will use indirect syscalls to get the base address of the suspended process's main module and locate the entry point, then we will set the memory protection of the entry point to read write (RW), this lets us write our payload directly to the entry point, after that, we will revert it back to its original protection, which should be read execute (RX), and finally, we will resume the process, executing our messagebox shellcode.

This injection method is effective as it lets us execute the payload in backed memory, which can bypass a lot of detection, and the process of performing it is less known than more common methods like allocating memory and creating a thread.

SuspendedSyscalls also uses my Shellcode-Toolkit library, meaning it also compiles a compact 3872 byte position independent flat binary file, as well as a 4608 bytes executable file.

# Potential issues
SuspendedSyscalls itself could be detected using API hooking/monitoring, as it requires CreateProcessA and ReadProcessMemory to get the syscall numbers.

If there is a big Windows update that changes the structure of NTDLL, or how processes operate, it could cause issues.

# Credits
https://github.com/am0nsec/HellsGate - Hell's Gate project

https://blog.sektor7.net/#!res/2021/halosgate.md - Halo's Gate project

https://blog.sektor7.net/#!res/2021/perunsfart.md - Using a suspended process's clean NTDLL to unhook the Nt APIs, gave me the idea for this project

https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - Mentions the sorting by syscall address technique

https://www.ired.team/offensive-security/code-injection-process-injection/addressofentrypoint-code-injection-without-virtualallocex-rwx - Injecting code into a suspended process's entry point
