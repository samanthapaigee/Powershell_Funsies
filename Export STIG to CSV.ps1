#Define the path to the XML file
$xmlFilePath = ""
#Define output path for CSV
$outputPath = ""

#Load XML file
[xml]$xmlData = Get-Content -Path $xmlFilePath

#Define the namespace
$namespace = @{"xccdf" = "http://checklists.nist.gov/xccdf/1.1"}

#Extract controls
$controls = $xmlData.SelectNodes("//xccdf:Rule", $namespace) | ForEach-Object {
	[PSCustomObject]{
		"Coontrol ID" = $_.id
		"Description" = $_.SelectSingleNode(".//xccdf:description", $namespace).InnerText.Trim()
	}
}

#Export to CSV
$controls | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
#confirm output
Write-Output "Controls extracted and saved to $outputPath"