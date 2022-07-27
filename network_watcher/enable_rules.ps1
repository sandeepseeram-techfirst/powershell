[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False)]
  [string]$portNumber="8084",
[switch]$DisableRule #by default it is false
)

$firewallRuleName="NPMDFirewallRule"
$firewallRuleDescription = "NPMD Firewall port exception"
$processName = "NPMDAgent.exe"
$protocolName = "tcp"
$direction = "in"
$isPortInUse = $False

$ICMPv4DestinationUnreachableRuleName = "NPMDICMPV4DestinationUnreachable"
$ICMPv4TimeExceededRuleName = "NPMDICMPV4TimeExceeded"
$ICMPv6DestinationUnreachableRuleName = "NPMDICMPV6DestinationUnreachable"
$ICMPv6TimeExceededRuleName = "NPMDICMPV6TimeExceeded"

$registryPath = "HKLM:\Software\Microsoft"
$keyName = "NPMD"
$NPMDPath = "HKLM:\Software\Microsoft\NPMD"
$NPMDLogRegistryPath = "Registry::HKEY_USERS\S-1-5-20\Software\Microsoft"
$NPMDLogKeyPath = "Registry::HKEY_USERS\S-1-5-20\Software\Microsoft\NPMD"
$portNumberName = "PortNumber"
$logLocationName = "LogLocation"
$enableLogName = "EnableLog"
$NPMDProcess = "NPMDAgent"

#Creates or deletes firewall rule based on disable rule flag
#Incase rule already created if it is just update of port number it just updates rule
function EnableDisableFirewallRule
{
    #Check if the ICMPv4 firewall rules already exist
    $icmpV4DURuleExists = 1;
    $existingRule = netsh advfirewall firewall show rule name=$ICMPv4DestinationUnreachableRuleName
    if(!($existingRule -cmatch $ICMPv4DestinationUnreachableRuleName))
    { 
        $icmpV4DURuleExists = 0;
    }

    $icmpV4TERuleExists = 1;
    $existingRule = netsh advfirewall firewall show rule name=$ICMPv4TimeExceededRuleName
    if(!($existingRule -cmatch $ICMPv4TimeExceededRuleName))
    { 
        $icmpV4TERuleExists = 0;
    }        
	
    #Check if the ICMPv6 firewall rule already exists
    $icmpV6DURuleExists = 1;
    $existingRule = netsh advfirewall firewall show rule name=$ICMPv6DestinationUnreachableRuleName
    if(!($existingRule -cmatch $ICMPv6DestinationUnreachableRuleName))
    { 
        $icmpV6DURuleExists = 0;
    }

    $icmpV6TERuleExists = 1;
    $existingRule = netsh advfirewall firewall show rule name=$ICMPv6TimeExceededRuleName
    if(!($existingRule -cmatch $ICMPv6TimeExceededRuleName))
    { 
        $icmpV6TERuleExists = 0;
    }
    		
    if(!($DisableRule))
    {
        #TCP Firewall Rule
        $existingRule = (New-object -comObject HNetCfg.FwPolicy2).rules | Where-Object {$_.name -like $firewallRuleName}
        if(!($existingRule))
        { 
            netsh advfirewall firewall add rule action="Allow" Description=$firewallRuleDescription Dir=$direction LocalPort=$portNumber Name=$firewallRuleName Protocol=$protocolName
        }
        #Rule already exists, update port number if different 
        else
        {
            if($existingRule.Name -cmatch $firewallRuleName)
            {
                if(!($existingRule.LocalPorts -cmatch $portNumber))
                {
                    $existingRule.LocalPorts=$portNumber
                    Write-Host "Firewall rule NPMDFirewallRule already exists.`nPort updated successfully to" $portNumber"." -ForegroundColor Green
                }
                else
                {
                    Write-Host "Firewall rule NPMDFirewallRule on"$portNumber "already exits.`nNo changes were made." -ForegroundColor Green
                }
            }
        }
		
        #ICMPv4 firewall rule
        if($icmpV4DURuleExists -eq 0)
        {
            netsh advfirewall firewall add rule name=$ICMPv4DestinationUnreachableRuleName protocol="icmpv4:3,any" dir=in action=allow
        }

        if($icmpV4TERuleExists -eq 0)
        {
            netsh advfirewall firewall add rule name=$ICMPv4TimeExceededRuleName protocol="icmpv4:11,any" dir=in action=allow
        }
		
        #ICMPv6 firewall rule
        if($icmpV6DURuleExists -eq 0)
        {
            netsh advfirewall firewall add rule name=$ICMPv6DestinationUnreachableRuleName protocol="icmpv6:1,any" dir=in action=allow
        }

        if($icmpV6TERuleExists -eq 0)
        {
            netsh advfirewall firewall add rule name=$ICMPv6TimeExceededRuleName protocol="icmpv6:3,any" dir=in action=allow
        }
    }
    else
    {
        #Remove TCP rule, if it exist
        $existingRule = netsh advfirewall firewall show rule name=$firewallRuleName
        if($existingRule)
        {
            netsh advfirewall firewall delete rule name=$firewallRuleName
        }
        #Remove ICMPv4 firewall rules
        if($icmpV4DURuleExists -eq 1)
        {
            netsh advfirewall firewall delete rule name=$ICMPv4DestinationUnreachableRuleName
        }

        if($icmpV4TERuleExists -eq 1)
        {
            netsh advfirewall firewall delete rule name=$ICMPv4TimeExceededRuleName
        }
		
        #Remove ICMPv6 firewall rules
        if($icmpV6DURuleExists -eq 1)
        {
            netsh advfirewall firewall delete rule name=$ICMPv6DestinationUnreachableRuleName
        }

        if($icmpV6TERuleExists -eq 1)
        {
            netsh advfirewall firewall delete rule name=$ICMPv6TimeExceededRuleName
        }
    }

    CreateDeleteRegistry
}

#Creates or deletes registry based on disablerule flag
#In case registry already created, if it just update of port number it updates port on registry
function CreateDeleteRegistry
{
    if(!($DisableRule))
    {
        if(!(Test-Path -Path $NPMDPath))
        {
            New-Item -Path $registryPath -Name $keyName
            New-ItemProperty -Path $NPMDPath -Name $portNumberName -Value $portNumber -PropertyType DWORD
        }
        else
        {
            $NPMDKeys = Get-Item -Path $NPMDPath
            if ($NPMDKeys.GetValue($portNumberName) -eq $null) 
            {
               New-ItemProperty -Path $NPMDPath -Name $portNumberName -Value $portNumber -PropertyType DWORD
            } 
            elseif ($NPMDKeys.GetValueKind($portNumberName) -ne "DWORD") 
            {
               Remove-ItemProperty -Path $NPMDPath -Name $portNumberName
               New-ItemProperty -Path $NPMDPath -Name $portNumberName -Value $portNumber -PropertyType DWORD
            }
            else
            {
               Set-ItemProperty -Path $NPMDPath -Name $portNumberName -Value $portNumber              
            }            
        }
        #Key path to set Log key for Network Service SID
        if(!(Test-Path -Path $NPMDLogKeyPath))
        {
            New-Item -Path $NPMDLogRegistryPath -Name $keyName
            New-ItemProperty -Path $NPMDLogKeyPath -Name $logLocationName
            New-ItemProperty -Path $NPMDLogKeyPath -Name $enableLogName -Value 0 -PropertyType DWORD
        }
        SetAclOnRegistry $NPMDPath
        SetAclOnRegistry $NPMDLogKeyPath

    }
    else
    {
        if((Test-Path -Path $NPMDPath))
        {
            Remove-Item -Path $NPMDPath
        }
        if((Test-Path -Path $NPMDLogKeyPath))
        {
            Remove-Item -Path $NPMDLogKeyPath
        }
    }
    
}

#set acl to network service to read registry
function SetAclOnRegistry([string] $path)
{
    $sid = "S-1-5-20"
    $objUser = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $str_account = ($objUser.Translate([System.Security.Principal.NTAccount])).Value 
    $acl = Get-Acl -Path $path
    $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [system.security.accesscontrol.PropagationFlags]"None"
    $rule=new-object system.security.accesscontrol.registryaccessrule "$str_account","ReadKey",$inherit,$propagation,"Allow"
    $acl.addaccessrule($rule)
    $acl|set-acl
}

#Script starts here
#Check if the specified port is already Listening
$getPortInfo = netstat -aon | Select-String "LISTENING" | Select-String $portNumber
if(!($DisableRule) -and ($getPortInfo))
{
    $isPortInUse = $true
    $getPortInfo = $getPortInfo[0]
    #repalce all the extra spaces with ':'
    $getPortInfo=$getPortInfo -replace '\s+',':'
    #remove all the non-digit chars with ':'
    $getPortInfo=$getPortInfo -replace '\D+',':'
    #if the last char of the string is ':', which will be the case in localized version,
    #remove the last char 
    if($getPortInfo[$getPortInfo.Length-1] -eq ':')
    { 
        $getPortInfo=$getPortInfo.Substring(0,$getPortInfo.Length - 1) 
    }
    #Get the peocessID corresponding to the current listening port
    #And the process with this processID
    $portProcessId = $getPortInfo.Split(":")[-1]
    $processOnPort = Get-Process -ID $portProcessId
    #If the process is not NPMD, terminate the script
    #else we will be updating the rules
    if($processOnPort -and $processOnPort.Name -eq $NPMDProcess)
    {
        EnableDisableFirewallRule   
    }
    else
    {
        Write-Host "Port number" $portNumber "already in use by some other process.`nPlease specify a different port using the argument [portNumber] to the script.`nYou must ensure that same port is used while running this script on other machines." -ForegroundColor "red"
        exit
    }
}
else
{
    EnableDisableFirewallRule
} 