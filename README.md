# Active Directory Management Toolkit

Lab Overview
This repository documents a comprehensive Active Directory management solution developed during the Google IT Support Certificate program, providing scripts, documentation, and best practices for Windows Server administration.

Objectives

Automate Active Directory user and group management
Implement consistent security policies
Provide reusable PowerShell scripts for system administrators

You can find the PowerShell automation scripts here: 
[active-directory-scripts.txt](https://github.com/user-attachments/files/17904114/active-directory-scripts.txt)# Active Directory Management Scripts
# A collection of useful PowerShell scripts for automating AD tasks

#region User Management Scripts

function New-ADUserWithDefaults {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FirstName,
        
        [Parameter(Mandatory=$true)]
        [string]$LastName,
        
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [SecureString]$Password,
        
        [string]$Department,
        [string]$Title,
        [string[]]$Groups
    )
    
    try {
        # Create new user with basic attributes
        $userParams = @{
            Name = "$FirstName $LastName"
            GivenName = $FirstName
            Surname = $LastName
            SamAccountName = $Username
            UserPrincipalName = "$Username@$((Get-ADDomain).DNSRoot)"
            Enabled = $true
            ChangePasswordAtLogon = $true
            AccountPassword = $Password
            Path = (Get-ADDomain).UsersContainer
        }
        
        if ($Department) { $userParams.Department = $Department }
        if ($Title) { $userParams.Title = $Title }
        
        New-ADUser @userParams
        
        # Add user to specified groups
        if ($Groups) {
            foreach ($group in $Groups) {
                Add-ADGroupMember -Identity $group -Members $Username
            }
        }
        
        Write-Host "User $Username created successfully!" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create user: $_"
    }
}

function Remove-InactiveADUsers {
    param(
        [int]$DaysInactive = 90,
        [switch]$WhatIf
    )
    
    $inactiveDate = (Get-Date).AddDays(-$DaysInactive)
    
    Get-ADUser -Filter {
        LastLogonDate -lt $inactiveDate -and Enabled -eq $true
    } -Properties LastLogonDate | ForEach-Object {
        if ($WhatIf) {
            Write-Host "Would disable user: $($_.SamAccountName)" -ForegroundColor Yellow
        } else {
            Disable-ADAccount -Identity $_.SamAccountName
            Write-Host "Disabled inactive user: $($_.SamAccountName)" -ForegroundColor Green
        }
    }
}

#endregion

#region Group Management Scripts

function New-ADGroupWithMembers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        
        [string]$Description,
        [string[]]$Members,
        [string]$ParentGroup
    )
    
    try {
        # Create new group
        $groupParams = @{
            Name = $GroupName
            GroupScope = 'Global'
            GroupCategory = 'Security'
            Path = (Get-ADDomain).UsersContainer
        }
        
        if ($Description) { $groupParams.Description = $Description }
        
        New-ADGroup @groupParams
        
        # Add members if specified
        if ($Members) {
            Add-ADGroupMember -Identity $GroupName -Members $Members
        }
        
        # Add to parent group if specified
        if ($ParentGroup) {
            Add-ADGroupMember -Identity $ParentGroup -Members $GroupName
        }
        
        Write-Host "Group $GroupName created successfully!" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create group: $_"
    }
}

function Sync-ADGroupMembers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourceGroup,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationGroup
    )
    
    try {
        $sourceMembers = Get-ADGroupMember -Identity $SourceGroup
        $destMembers = Get-ADGroupMember -Identity $DestinationGroup
        
        # Add missing members
        $sourceMembers | Where-Object {
            $_.distinguishedName -notin $destMembers.distinguishedName
        } | ForEach-Object {
            Add-ADGroupMember -Identity $DestinationGroup -Members $_.distinguishedName
            Write-Host "Added $($_.name) to $DestinationGroup" -ForegroundColor Green
        }
        
        # Remove extra members
        $destMembers | Where-Object {
            $_.distinguishedName -notin $sourceMembers.distinguishedName
        } | ForEach-Object {
            Remove-ADGroupMember -Identity $DestinationGroup -Members $_.distinguishedName -Confirm:$false
            Write-Host "Removed $($_.name) from $DestinationGroup" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Failed to sync groups: $_"
    }
}

#endregion

#region GPO Management Scripts

function New-WallpaperGPO {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GPOName,
        
        [Parameter(Mandatory=$true)]
        [string]$WallpaperPath,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetOU
    )
    
    try {
        # Create new GPO
        $gpo = New-GPO -Name $GPOName
        
        # Set wallpaper configuration
        Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName Wallpaper -Type String -Value $WallpaperPath
        
        Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
            -ValueName WallpaperStyle -Type String -Value "2"
        
        # Link GPO to target OU
        New-GPLink -Name $GPOName -Target $TargetOU
        
        Write-Host "Wallpaper GPO created and linked successfully!" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create GPO: $_"
    }
}

function Export-GPOSettings {
    param(
        [string]$OutputPath = "C:\GPOBackups",
        [switch]$IncludeACL
    )
    
    # Create backup directory if it doesn't exist
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath
    }
    
    $date = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $backupPath = Join-Path $OutputPath $date
    
    try {
        # Backup all GPOs
        Backup-GPO -All -Path $backupPath
        
        if ($IncludeACL) {
            # Export GPO permissions
            $gpos = Get-GPO -All
            foreach ($gpo in $gpos) {
                $aclPath = Join-Path $backupPath "$($gpo.DisplayName)_ACL.csv"
                Get-GPPermissions -Name $gpo.DisplayName -All | 
                    Export-Csv -Path $aclPath -NoTypeInformation
            }
        }
        
        Write-Host "GPO backup completed successfully at: $backupPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to backup GPOs: $_"
    }
}

#endregion

#region Reporting Scripts

function Get-ADUserReport {
    param(
        [string]$OutputPath = "C:\Reports\UserReport.csv"
    )
    
    try {
        Get-ADUser -Filter * -Properties Department, Title, LastLogonDate, 
            Enabled, PasswordLastSet, PasswordExpired, PasswordNeverExpires |
            Select-Object Name, SamAccountName, Department, Title, LastLogonDate,
                Enabled, PasswordLastSet, PasswordExpired, PasswordNeverExpires |
            Export-Csv -Path $OutputPath -NoTypeInformation
        
        Write-Host "User report generated at: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to generate user report: $_"
    }
}

function Get-ADGroupReport {
    param(
        [string]$OutputPath = "C:\Reports\GroupReport.csv"
    )
    
    try {
        $groups = Get-ADGroup -Filter * -Properties Description, Members
        
        $groupReport = foreach ($group in $groups) {
            [PSCustomObject]@{
                Name = $group.Name
                Description = $group.Description
                MemberCount = @($group.Members).Count
                Members = ($group.Members | ForEach-Object { (Get-ADObject $_).Name }) -join '; '
            }
        }
        
        $groupReport | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Host "Group report generated at: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to generate group report: $_"
    }
}

#endregion

# Example Usage:

<#

# Create new user
$password = ConvertTo-SecureString "ComplexPass123!" -AsPlainText -Force
New-ADUserWithDefaults -FirstName "John" -LastName "Doe" -Username "jdoe" -Password $password -Department "IT" -Groups "Python Developers"

# Create new group
New-ADGroupWithMembers -GroupName "Python Developers" -Description "Python Development Team" -ParentGroup "Developers"

# Create wallpaper GPO
New-WallpaperGPO -GPOName "Developer Wallpaper" -WallpaperPath "C:\Wallpapers\dev.jpg" -TargetOU "OU=Developers,DC=example,DC=com"

# Generate reports
Get-ADUserReport
Get-ADGroupReport

#>


 Prerequisites

Windows Server
PowerShell 5.1 or later
Active Directory Domain Services (AD DS) installed
Administrator privileges

 Lab Walkthrough: Active Directory Installation
1. Active Directory Installation Process
PowerShell Installation Commands
powershellCopy# Install Active Directory Domain Services
C:\Qwiklabs\ADSetup\active_directory_install.ps1

# Configure Active Directory post-installation
C:\Qwiklabs\ADSetup\configure_active_directory.ps1
2. User Management Workflow
Creating a New User

Open Active Directory Administrative Center (ADAC)
Navigate to Users container
Click "New" → "User"
Complete user details
Set initial password
Enable account

PowerShell Script Example
powershellCopy# Create new user with defaults
$password = ConvertTo-SecureString "ComplexPass123!" -AsPlainText -Force
New-ADUserWithDefaults `
    -FirstName "John" `
    -LastName "Doe" `
    -Username "jdoe" `
    -Password $password `
    -Department "IT" `
    -Groups "Python Developers"
3. Group Management
Creating Security Groups

Open Active Directory Administrative Center
Navigate to Users container
Click "New" → "Group"
Define group name and scope

PowerShell Script Example
powershellCopy# Create new group with members
New-ADGroupWithMembers `
    -GroupName "Python Developers" `
    -Description "Python Development Team" `
    -Members "jdoe", "msmith" `
    -ParentGroup "Developers"
4. Group Policy Configuration
Creating Wallpaper GPO

Open Group Policy Management
Right-click domain/OU
Create new GPO
Configure wallpaper settings

PowerShell Script Example
powershellCopy# Create wallpaper GPO
New-WallpaperGPO `
    -GPOName "Developer Wallpaper" `
    -WallpaperPath "C:\Wallpapers\dev.jpg" `
    -TargetOU "OU=Developers,DC=example,DC=com"
    
  Key Automation Scripts
User Management

New-ADUserWithDefaults: Automated user creation
Remove-InactiveADUsers: Disable inactive user accounts

Group Management

New-ADGroupWithMembers: Create groups with optional membership
Sync-ADGroupMembers: Synchronize group memberships

GPO Management

New-WallpaperGPO: Create wallpaper group policies
Export-GPOSettings: Backup GPO configurations

Reporting

Get-ADUserReport: Generate comprehensive user reports
Get-ADGroupReport: Create detailed group membership reports

 Best Practices

Use strong, complex passwords
Implement principle of least privilege
Regularly audit user and group memberships
Backup GPO configurations
Monitor inactive accounts

Quick Start
Script Execution

Open PowerShell as Administrator
Import the AD-Management-Scripts.ps1
Use functions as demonstrated in examples

Example Workflow
powershellCopy# Import the script
. .\AD-Management-Scripts.ps1

# Create user
$securePass = ConvertTo-SecureString "SecurePassword123!" -AsPlainText -Force
New-ADUserWithDefaults -FirstName "Jane" -LastName "Smith" -Username "jsmith" -Password $securePass

# Generate reports
Get-ADUserReport
Get-ADGroupReport
Security Considerations

Never hardcode passwords in scripts
Use secure string for password handling
Implement multi-factor authentication
Regularly update and patch systems

 Additional Resources

Microsoft Active Directory Documentation
PowerShell Active Directory Module
Windows Server Security Best Practices

 Notes
Created during Google IT Support Certificate training
For educational and demonstration purposes
 License
This project is open-source. Refer to the licensing terms in the repository.
