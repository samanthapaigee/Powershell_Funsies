[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)] [string]$SourcePath,
  [Parameter(Mandatory)] [string]$TargetPath,
  [string]$OutputPath,
  [switch]$InPlace,
  [switch]$SkipEmpty = $true,
  [switch]$Backup
)

function Assert-File([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "File not found: $Path"
  }
}

function Load-Xml([string]$Path) {

Add-Type -AssemblyName System.IO.Compression.FileSystem

function Load-Xml([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "File not found: $Path"
  }

  # Read first 4 bytes to detect ZIP ("PK")
  $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    [byte[]]$sig = New-Object byte[] 4
    $null = $fs.Read($sig, 0, 4)
    $isZip = ($sig[0] -eq 0x50 -and $sig[1] -eq 0x4B) # 'P''K'
    $fs.Position = 0

    if ($isZip) {
      # It's a CKLB package (ZIP). Open and find an inner XML/CKL/CKLB file.
      $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read, $true)
      try {
        $entry = $zip.Entries |
          Where-Object { $_.FullName -match '\.(xml|ckl|cklb)$' } |
          Sort-Object { $_.Length } |
          Select-Object -First 1

        if (-not $entry) {
          throw "ZIP package contains no XML/CKL/CKLB entries: $Path"
        }

        $es = $entry.Open()
        try {
          $sr = New-Object System.IO.StreamReader($es)
          try {
            $xmlText = $sr.ReadToEnd()
          } finally { $sr.Dispose() }
        } finally { $es.Dispose() }

        if (-not $xmlText.TrimStart().StartsWith('<')) {
          throw "Inner entry '$($entry.FullName)' is not XML (starts with: '$($xmlText.TrimStart().Substring(0, [Math]::Min(20, $xmlText.TrimStart().Length)))')."
        }

        $xml = New-Object System.Xml.XmlDocument
        $xml.PreserveWhitespace = $true
        $xml.LoadXml($xmlText)
        return $xml
      } finally {
        $zip.Dispose()
      }
    } else {
      # Plain text XML file path
      $xml = New-Object System.Xml.XmlDocument
      $xml.PreserveWhitespace = $true
      $xml.Load($Path)   # handles UTF-8 BOM
      return $xml
    }
  } finally {
    $fs.Dispose()
  }
}

function Save-Xml([xml]$XmlDoc, [string]$Path) {
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  $writer = New-Object System.IO.StreamWriter($Path, $false, $utf8NoBom)
  try {
    $XmlDoc.Save($writer)
  } finally {
    $writer.Dispose()
  }
}

function Get-VulnId([System.Xml.XmlElement]$Vuln) {
  # Typical CKL layout uses <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-12345</ATTRIBUTE_DATA>
  foreach ($sd in @($Vuln.STIG_DATA)) {
    $attr = ($sd.VULN_ATTRIBUTE | ForEach-Object { $_.'#text' }) -join ''
    $data = ($sd.ATTRIBUTE_DATA | ForEach-Object { $_.'#text' }) -join ''
    if ($attr -match '^(Vuln[_\s-]?Num|Vuln[_\s-]?ID|Vuln ID)$' -and $data -match '^V-\d+') {
      return $data.Trim()
    }
  }
  # Fallback for old ckls
  foreach ($candidate in @('Vuln_Num','Vuln ID','VulnID','Vuln-Num','Vuln-Id')) {
    $node = @($Vuln.STIG_DATA) | Where-Object {
      $_.VULN_ATTRIBUTE -and ($_.VULN_ATTRIBUTE.'#text' -eq $candidate)
    } | Select-Object -First 1
    if ($node -and $node.ATTRIBUTE_DATA -and $node.ATTRIBUTE_DATA.'#text' -match '^V-\d+') {
      return $node.ATTRIBUTE_DATA.'#text'.Trim()
    }
  }
  return $null
}

function Get-VulnMap([xml]$Doc) {
  $map = @{}
  $vulns = $Doc.CHECKLIST.STIGS.iSTIG.VULN
  foreach ($v in @($vulns)) {
    $vid = Get-VulnId $v
    if ($vid) { $map[$vid] = $v }
  }
  return $map
}

function Get-Text([System.Xml.XmlElement]$node) {
  if (-not $node) { return '' }
  return ($node.'#text' | ForEach-Object { $_ }) -join ''
}

function Set-Text([ref]$nodeRef, [string]$value) {
  $node = $nodeRef.Value
  if (-not $node) { return }
  # Replace inner text (preserve element)
  $node.RemoveAll() | Out-Null
  [void]$node.AppendChild($node.OwnerDocument.CreateTextNode($value))
}

function Ensure-Child([System.Xml.XmlElement]$parent, [string]$name) {
  $child = $parent.SelectSingleNode($name)
  if (-not $child) {
    $child = $parent.OwnerDocument.CreateElement($name)
    [void]$parent.AppendChild($child)
  }
  return $child
}

try {
  Assert-File $SourcePath
  Assert-File $TargetPath

  if (-not $OutputPath -and -not $InPlace) {
    throw "Provide -OutputPath or specify -InPlace to update the target in place."
  }
  if ($OutputPath -and $InPlace) {
    throw "Use either -OutputPath or -InPlace, not both."
  }

  Write-Verbose "Loading XML..."
  $srcXml = Load-Xml $SourcePath
  $tgtXml = Load-Xml $TargetPath

  $srcMap = Get-VulnMap $srcXml
  $tgtMap = Get-VulnMap $tgtXml

  $updated = 0
  $matched = 0
  $skipped = 0

  $report = New-Object System.Collections.Generic.List[object]

  foreach ($kv in $tgtMap.GetEnumerator()) {
    $vid = $kv.Key
    $tgtV = $kv.Value
    if (-not $srcMap.ContainsKey($vid)) { continue }

    $matched++

    $srcV = $srcMap[$vid]

    # Fields of interest
    $tgtSTATUS = Ensure-Child $tgtV 'STATUS'
    $tgtCOMMENTS = Ensure-Child $tgtV 'COMMENTS'
    $tgtFINDING_DETAILS = Ensure-Child $tgtV 'FINDING_DETAILS'

    $srcSTATUS = $srcV.SelectSingleNode('STATUS')
    $srcCOMMENTS = $srcV.SelectSingleNode('COMMENTS')
    $srcFINDING_DETAILS = $srcV.SelectSingleNode('FINDING_DETAILS')

    $before = [pscustomobject]@{
      VID = $vid
      TargetSTATUS = Get-Text $tgtSTATUS
      TargetCOMMENTS = (Get-Text $tgtCOMMENTS).Substring(0, [Math]::Min(60, (Get-Text $tgtCOMMENTS).Length))
      TargetFINDING_DETAILS = (Get-Text $tgtFINDING_DETAILS).Substring(0, [Math]::Min(60, (Get-Text $tgtFINDING_DETAILS).Length))
      SourceSTATUS = Get-Text $srcSTATUS
    }

    $didChange = $false

    # Copy STATUS
    $srcStatusText = Get-Text $srcSTATUS
    if ($srcStatusText) {
      if ($PSCmdlet.ShouldProcess("VID $vid", "Set STATUS -> '$srcStatusText'")) {
        Set-Text ([ref]$tgtSTATUS) $srcStatusText
        $didChange = $true
      }
    } elseif (-not $SkipEmpty) {
      if ($PSCmdlet.ShouldProcess("VID $vid", "Clear STATUS")) {
        Set-Text ([ref]$tgtSTATUS) ''
        $didChange = $true
      }
    }

    # Copy COMMENTS
    $srcCommentsText = Get-Text $srcCOMMENTS
    $tgtCommentsText = Get-Text $tgtCOMMENTS
    if ($srcCommentsText -or -not $SkipEmpty) {
      if ($PSCmdlet.ShouldProcess("VID $vid", "Set COMMENTS")) {
        Set-Text ([ref]$tgtCOMMENTS) ($srcCommentsText ?? '')
        $didChange = $true
      }
    }

    # Copy FINDING_DETAILS
    $srcFDText = Get-Text $srcFINDING_DETAILS
    if ($srcFDText -or -not $SkipEmpty) {
      if ($PSCmdlet.ShouldProcess("VID $vid", "Set FINDING_DETAILS")) {
        Set-Text ([ref]$tgtFINDING_DETAILS) ($srcFDText ?? '')
        $didChange = $true
      }
    }

    if ($didChange) { $updated++ } else { $skipped++ }

    $after = [pscustomobject]@{
      VID = $vid
      NewSTATUS = Get-Text $tgtSTATUS
    }

    $report.Add([pscustomobject]@{
      VID = $vid
      SourceSTATUS = $before.SourceSTATUS
      TargetSTATUS_Before = $before.TargetSTATUS
      TargetSTATUS_After  = $after.NewSTATUS
      Changed = $didChange
    }) | Out-Null
  }

  # Save results
  if ($InPlace) {
    if ($Backup) {
      $bak = "$TargetPath.bak"
      Copy-Item -LiteralPath $TargetPath -Destination $bak -Force
      Write-Host "Backup created: $bak"
    }
    Save-Xml $tgtXml $TargetPath
    Write-Host "Updated target in place: $TargetPath"
  } else {
    Save-Xml $tgtXml $OutputPath
    Write-Host "Wrote merged file: $OutputPath"
  }

  Write-Host ""
  Write-Host "Merge Summary"
  Write-Host ("Matched V-IDs : {0}" -f $matched)
  Write-Host ("Updated       : {0}" -f $updated)
  Write-Host ("Unchanged     : {0}" -f $skipped)

  # Optional: emit a small table
  $report | Sort-Object VID | Format-Table -AutoSize

} catch {
  Write-Error $_.Exception.Message
  exit 1
}
