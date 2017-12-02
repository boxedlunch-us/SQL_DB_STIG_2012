<#
    Author:  Ricky Nelson
    Description:  SQL 2012 Database STIG automation
    Date:  20150402
#>

# Import SQL native tools
Add-PSSnapin SqlServerCmdletSnapin100
Add-PSSnapin SqlServerProviderSnapin100


# Get current driectory
$ScriptDir = Split-Path $script:MyInvocation.mycommand.path

# Import custom SQL Module
Import-Module "$ScriptDir\SQL2012_DB_Stig_Module.psm1"


# Get serverlist
$serverlist = Get-Content "$ScriptDir\servers.txt"

$modules = Get-Module | Where-Object {$_.moduletype -eq "Script" -and $_.name -like "SQL2012_DB*"}

$commandlist = $modules.ExportedCommands.values.name | where {$_ -like "SQL*" -and $_ -ne "SQL_00000"}

foreach($server in $serverlist)
{
    foreach($command in $commandlist)
    {
        $run = (Get-Command $command -CommandType Function).ScriptBlock
        invoke-command $run -ArgumentList $server
    }
}
