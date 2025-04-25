# Powershell_Funsies
A random compilation of things I learned how to do with PowerShell to make some of my Windows sys admin work easier!

Registry Checker:
  I made this script after Evaluate STIG was incorrectly compiling results for software that had been deleted from the system and marking 100% of the vulnerabilities as open. If you've never worked with Evaluate STIG, it primarily looks at the registry values for an application. This script aims to find all relevant registry keys. 
  Using it, I found that there were values still associated with the removed program. While eSTIG did not look for those values specifically in the checklist, it did make it appear to still be on the system. 

Export STIG to CSV:
  If you've worked with STIGs and STIG Viewer, you know it's not always the easiest thing to understand and offlaods a lot of various information. In my attempts to make secure coding more of a relevant practice, I wanted to introduce the Application Security and Development STIG earlier in the software creation. However, without the time or desire to train software engineers on STIG Viewer or what the relevant information is, I didn't know what I could do. 
  Knowing that eSTIG is primarily PowerShell, I figured that PS could also ingest the checklists and put them into a CSV, which is exactly what I did!

Block USB:
  When machines go out, external devices should be blocked. In some cases, that hasn't always happened for a host of reasons. In trying to create a USB Rubber Ducky process, this was one of the scripts I created to be used during machine set up. This script gives you a fun color to determine the status of USB ports.
  Red: Failure, USB is not blocked
  Green: Success, USB is blocked
  Yellow: The typical registry path where this is set does not exist

Secure Boot Checker:
  Similar to blocking USB, this doesn't always get set up. However, it is a Windows STIG check. It gets disabled for the imaging of machines, and sometimes admins don't remember to reenable it. In my Rubber Ducky process, this is the end of the scripts. While Secure Boot cannot be altered outside of the BIOS, this script gives you a fun color based upon the status of Secure Boot, making it very easy to determine if the machine needs to be touched again.
  Red: Secure Boot is disabled
  Green: Secure Boot is enabled
  Yellow: Unable to determine
