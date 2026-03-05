#source folder where repo exists
$sourceDir = ""

#destination folder to put into iso 
$destinationDir = ""

#do last 30 days bc monthly updates
$cutoff = (Get-Date).AddDays(-30)

Get-ChildItem -Path $SourceDir -File -Recurse | Where-Object { $_.LastWriteTime -gt $cutoff } | ForEach-Object {
  $relativePath = $_.FullName.Substring($sourceDir.Length)
  $destinationPath = Join-Path -Path $destinationDir -ChildPath $relativePath
  $destinationDirectory = Split-Path -Path $destinationPath -Parent
}

Move-Item -Path $sourceDir -Destination $destinationPath -Force
