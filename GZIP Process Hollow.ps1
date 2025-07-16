$fileBytes = [System.IO.File]::ReadAllBytes("$PATH_TO_PRCOESS_HOLLOWING_PAYLOAD")
$memoryStream = New-Object System.IO.MemoryStream
$gzipStream = New-Object System.IO.Compression.GzipStream($memoryStream, [IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($fileBytes, 0, $fileBytes.Length)
$gzipStream.Close()
$base64String = [Convert]::ToBase64String($memoryStream.ToArray())
$base64String | clip
