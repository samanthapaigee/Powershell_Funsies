# define the program name to search for
$programName = ""

$Define registry roots to search. HKLM is local machine, system info, scheduling tasks and services. HKCU is current user, info about currently logged on user
$registryRoots +@(
	"HKLM:\SOFTWARE",
	"HKCU:\SOFTWARE"
)

#initialize somewhere to store the results
$results = @()

#loop through each root and searchforeach ($root in $registryRoots) {
	Write-Host "Searching in $root"
	Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue |
	ForEach-Object {
		#Search for matching keys or values
		if ($_ -match $programName){
			#add to the results
			$results += [PSCustomObject]@{
				RegistryRoot = $root
				KeyPath = $_.PSPath
			}
		}
	}
}

#Define the output CSV file Path
$outputPath = ""

#export the results to a CSV
if ($results.Count -gt 0) {
	$results | -Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
	Write-Host "Results exported to $outputPath"
}	else {
	Write-Host "No matches found for $programName"  
}