
# OWALogonExclusions

DESCRIPTION: 
- Generate list of accounts that have a recent OWA logon and no recent logon recorded in Active Directory to exclude from processing

> NOTES: "v1.0" was completed in 2011. OWALogonExclusions was written to work in on-premises Active Directory environments. The purpose of OWALogonExclusions was/is to find accouts logging on via OWA to check email. OWALogonExclusions was designed to work with other tools.

## Requirements:

Operating System Requirements:
- Windows Server 2003 or higher (32-bit)
- Windows Server 2008 or higher (32-bit)

Additional software requirements:
Microsoft .NET Framework v3.5

Active Directory requirements:
One of following domain functional levels
- Windows Server 2003 domain functional level
- Windows Server 2008 domain functional level

Additional requirements:
Domain administrative access is required to perform operations by OWALogonExclusions


## Operation and Configuration:

Command-line parameters:
- run (Required parameter)

Configuration file: configOWALogonExclusions.txt
- Located in the same directory as OWALogonExclusions.exe

Configuration file parameters:

OWALogFileLocation: Location for OWALogonExclusions to find the OWA log files to create the appropriate exclusions

ExclusionGroupLocation: Specifies an OU location in Active Directory to create a group called OWALogonExclusions to hold the exclusions create by the tool

Output:
- Located in the Log directory inside the installation directory; log files are in tab-delimited format
- Path example: (InstallationDirectory)\Log\

Additional detail:
- OWALogonExclusions will only scan OWA log files that meet the criteria:
    - Older than 12 hours from the time the tool is run to avoid open file issues with other processes writing to the log files
    - Newer than 14 days ago
- The OWALogonExclusions group will be recreated every 14 days
