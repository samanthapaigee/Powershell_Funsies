#check if running as admin
if (-not([Security.Principal.WindowsPrincipal]
	[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
		Write-Host "Please run this script as an administrator" -ForegroundColor Red
		exit		
	}

#Checking the status of secure boot
$secureBootStatus = Confirm-SecureBootUEFI

#Output result with pretty colors!
if ($secureBootStatus -eq $true){
	Write-Host "Secure Boot is enabled!" -ForegroundColor Green
} elseif ($secureBootStatus -eq $false) {
	Write-Host "Secure Boot is disabled. This must be enabled to maintain compliance!" -ForegroundColor Red
} else {
	Write-Host "Secure Boot is not supported, or the status cannot be determined. Please refer to OEM guides or BIOS." -ForegroundColor Yellow
}