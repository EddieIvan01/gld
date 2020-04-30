#include <Windows.h>
#include <stdio.h>

// #pragma comment(linker, "/section:.data,RWE")
// #pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")

unsigned char buf[] = "";

void virtualProtect() {
    void(*fn)(void);
    fn = (void(*)(void)) & buf;
    
    DWORD oldperm;
    if (!VirtualProtect(&buf, sizeof buf, 0x40, &oldperm)) return -1;
    (*fn)();
}

void virtualAlloc() {
    LPVOID lpAlloc = VirtualAlloc(0, sizeof buf, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(lpAlloc, buf, sizeof buf);
    ((void(*)())lpAlloc)();
}

void asm() {
    void(*fn)(void);
    fn = (void(*)(void)) & buf;
    
    DWORD oldperm;
    if (!VirtualProtect(&buf, sizeof buf, 0x40, &oldperm)) return -1;
    __asm {
        mov eax, offset buf
        jmp eax
    }
}

int main() {
    return 0;
}
