#*************************************************************************
#
#
# SCRIPT	QND.Azure.Sentinel.Workspace.Rule.Discovery.ps1
# AUTHOR	PROGEL SpA
# VERSION	1.5_2020.08.11
# PURPOSE	
#
#
# CHANGELOG
#	2019.12.06 1.0 [FGa] - First release.
#	2019.12.09 1.1 [FGa] - Add filter.
#	2020.07.28 1.2 [FG] - Updated api-version
#	2020.07.30 1.3 [FG] - Fixed Severity Discovery for rules with severitiesFilter
#	2020.08.10 1.4 [FG] - Added inclusion Filters
#	2020.08.11 1.5 [FG] - Fixed Filter check
#
# (c) Copyright 2020, PROGEL SpA, All Rights Reserved. Proprietary and confidential to PROGEL SpA.
#
#
#*************************************************************************

Param
(
	[Parameter(Mandatory = $true)] [System.String] $SourceID,
	[Parameter(Mandatory = $true)] [System.String] $ManagedEntityID,
	[Parameter(Mandatory = $true)] [System.String] $SubscriptionID,
	[Parameter(Mandatory = $true)] [System.String] $WorkspaceID,
	[Parameter(Mandatory = $true)] [System.String] $ClientID,
	[Parameter(Mandatory = $true)] [System.String] $AuthorityURI,
	[Parameter(Mandatory = $true)] [System.String] $ResourceURI,
	[Parameter(Mandatory = $true)] [System.String] $Username,
	[Parameter(Mandatory = $true)] [System.String] $Password,
	[Parameter(Mandatory = $false)] [System.String] $ProxyURI = $null,
	[Parameter(Mandatory = $false)] [System.String] $ExcludeByName = $null,
	[Parameter(Mandatory = $false)] [System.String] $ExcludeByDisplayName = $null,
	[Parameter(Mandatory = $false)] [System.String] $ExcludeByKind = $null,
	[Parameter(Mandatory = $false)] [System.String] $ExcludeBySeverity = $null,
	[Parameter(Mandatory = $false)] [System.String] $IncludeByName = $null,
	[Parameter(Mandatory = $false)] [System.String] $IncludeByDisplayName = $null,
	[Parameter(Mandatory = $false)] [System.String] $IncludeByKind = $null,
	[Parameter(Mandatory = $false)] [System.String] $TraceLevel = 5
)

[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'


$SCRIPTNAME = 'QND.Azure.Sentinel.Workspace.Rule.Discovery'
$SCRIPTVERSION = '1.5_2020.08.11'

$SCRIPTWORKFLOWNAME = $MyInvocation.InvocationName
$SCRIPTWORKFLOWID = $WorkspaceID
$SCRIPTRUNAS = (whoami).ToString().ToUpper()
$SCRIPTDATETIME = [System.DateTime]::Now

$SCRIPTLOGSOURCE = 'QND Azure Sentinel Discovery'
$SCRIPTLOG = 'Operations Manager'

$SCRIPTLOGSEVERITY = $TraceLevel


if (![System.Diagnostics.EventLog]::SourceExists($SCRIPTLOGSOURCE)) {[System.Diagnostics.EventLog]::CreateEventSource($SCRIPTLOGSOURCE, $SCRIPTLOG)}


#Trace Level Costants
$TRACE_NONE = 0
$TRACE_ERROR = 1
$TRACE_WARNING = 2
$TRACE_INFO = 3
$TRACE_VERBOSE = 4
$TRACE_DEBUG = 5

#Event Type Constants
$EVENT_TYPE_SUCCESS = 0
$EVENT_TYPE_ERROR = 1
$EVENT_TYPE_WARNING = 2
$EVENT_TYPE_INFORMATION = 4
$EVENT_TYPE_AUDITSUCCESS = 8
$EVENT_TYPE_AUDITFAILURE = 16

#Standard Event IDs
$EVENT_ID_FAILURE = 4000		#errore generico nello script
$EVENT_ID_SUCCESS = 1101
$EVENT_ID_START = 1102
$EVENT_ID_STOP = 1103
$EVENT_ID_DETAILS = 1104
$EVENT_ID_CONNECTIVITY = 1105

#TypedPropertyBag
$AlertDataType = 0
$EventDataType = 2
$PerformanceDataType = 2
$StateDataType = 3

Function Write-Arguments
{
	Param ([Parameter(Mandatory = $true)] [System.Object] $InputObject)
	Begin
	{
		$Message = ''
		$ShadowRegex = 'Password|Credential|Secure|Secret|Cred|Pass'
	}
	Process
	{
		foreach ($Key in $InputObject.BoundParameters.Keys)
		{
			if ($Key -imatch $ShadowRegex) {$Message = [System.String]::Format('{0}[{1}, ...] ', @($Message, $Key))}
			else {if (![System.String]::IsNullOrEmpty($InputObject.BoundParameters[$Key])) {$Message = [System.String]::Format('{0}[{1}, {2}] ', @($Message, $Key, $InputObject.BoundParameters[$Key]))}}
		}
		$Message = [System.String]::Format('{0}[Runas, {1}]', @($Message, $SCRIPTRUNAS))
		Write-Event -ID $EVENT_ID_START -Type $EVENT_TYPE_INFORMATION -Message $Message -Severity $TRACE_INFO
	}
}

Function Create-Event
{
	Param
	(
		[Parameter(Mandatory = $true)] [System.Int32] $ID,
		[Parameter(Mandatory = $true)] [System.Int32] $Type,
		[Parameter(Mandatory = $true)] [System.String] $Message,
		[Parameter(Mandatory = $false)] [System.String[]] $Parameters = $null
	)
	Begin
	{
		$RealType = switch ($Type)
		{
			$EVENT_TYPE_SUCCESS {[System.Diagnostics.EventLogEntryType]::Information}
			$EVENT_TYPE_ERROR {[System.Diagnostics.EventLogEntryType]::Error}
			$EVENT_TYPE_WARNING {[System.Diagnostics.EventLogEntryType]::Warning}
			$EVENT_TYPE_INFORMATION {[System.Diagnostics.EventLogEntryType]::Information}
			$EVENT_TYPE_AUDITSUCCESS {[System.Diagnostics.EventLogEntryType]::SuccessAudit}
			$EVENT_TYPE_AUDITFAILURE {[System.Diagnostics.EventLogEntryType]::FailureAudit}
			default {[System.Diagnostics.EventLogEntryType]::Information}
		}
	}
	Process
	{
		$Event = [System.Diagnostics.EventInstance]::new($ID, 1, $RealType)
		$EventLog = [System.Diagnostics.EventLog]::new($SCRIPTLOG)
		$EventLog.Source = $SCRIPTLOGSOURCE
		$EventLog.WriteEvent($Event, (@($Message) + $Parameters))
	}
}

Function Write-Event
{
	Param
	(
		[Parameter(Mandatory = $true)] [System.Int32] $ID,
		[Parameter(Mandatory = $true)] [System.Int32] $Type,
		[Parameter(Mandatory = $true)] [System.String] $Message,
		[Parameter(Mandatory = $true)] [System.Int32] $Severity
	)
	Process
	{
		Write-Verbose ("Logging event. " + $SCRIPTNAME + " EventID: " + $ID + " eventType: " + $Type + " Version:" + $SCRIPTVERSION + " --> " + $Message)
		if ($Severity -le $SCRIPTLOGSEVERITY)
		{
			Write-Host ("Logging event. " + $SCRIPTNAME + " EventID: " + $ID + " eventType: " + $Type + " Version:" + $SCRIPTVERSION + " --> " + $Message)
			$Message = [System.String]::Format('{0} ({1}) [{2}] -> {3}.{4}{4}{5}', @($SCRIPTNAME, $SCRIPTVERSION, $SCRIPTWORKFLOWNAME, $SCRIPTWORKFLOWID, [System.Environment]::NewLine, $Message))
			Create-Event -ID $ID -Type $Type -Message $Message -Parameters @($SCRIPTNAME, $SCRIPTVERSION, $SCRIPTWORKFLOWNAME, $SCRIPTWORKFLOWID)
		}
	}
}

Function Exit-EmptyDiscovery
{
	Param
	(
		[Parameter(Mandatory = $true)] [System.String] $SourceID,
		[Parameter(Mandatory = $true)] [System.String] $ManagedEntityID,
		[Parameter(Mandatory = $false)] [System.Management.Automation.SwitchParameter] $Differential
	)
	Begin
	{
		$DiscoveryData = $SCRIPTMOMAPI.CreateDiscoveryData(0, $SourceID, $ManagedEntityID)
		if ($Differential)
		{
			# incremental discovery data
			$DiscoveryData.IsSnapshot = $false
			$Message = 'Exiting with null non snapshot (incremental) discovery data.'
		}
		else {$Message = 'Exiting with empty discovery data.'}
	}
	Process
	{
		Write-Event -ID $EVENT_ID_FAILURE -type $EVENT_TYPE_WARNING -Message $Message -Severity $TRACE_INFO
		$DiscoveryData
		if ($SCRIPTLOGSEVERITY -eq $TRACE_DEBUG) {$SCRIPTMOMAPI.Return($DiscoveryData)} # cmdline debug. nothing inside OpsMgr Agent.
	}
}


Function Import-Resource
{
	Param
	(
		[Parameter(Mandatory = $true)] [System.String] $ModuleName,
		[Parameter(Mandatory = $false)] [System.Object[]] $ArgumentList = $null
	)
	Begin
	{
		$StateDirectory = [System.IO.Path]::Combine((Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\HealthService\Parameters' -Name 'State Directory'), 'Resources')
		$ModuleBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ModuleName)
	}
	Process
	{	
		if (Get-Module -Name $ModuleBaseName) {return}
		if ([System.IO.Directory]::Exists($StateDirectory)) {$ModuleFullName = ([System.IO.Directory]::EnumerateFiles($StateDirectory, $ModuleName, [System.IO.SearchOption]::AllDirectories))[0]}
		if ([System.String]::IsNullOrEmpty($ModuleFullName)) {$ModuleFullName = [System.IO.Path]::Combine($PSScriptRoot, $ModuleName)}
		if ([System.IO.File]::Exists($ModuleFullName)) {Import-Module -Name $ModuleFullName -ArgumentList $ArgumentList -ErrorAction ([System.Management.Automation.ActionPreference]::Stop)}
		else {throw [System.IO.FileNotFoundException]::new([System.String]::Format("Cannot find module '{0}' because it does not exist.", $ModuleFullName))}
	}
}

Function Invoke-RestApi
{
	Param
	(
		[Parameter(Mandatory = $true)] [System.String] $Uri,
		[Parameter(Mandatory = $true)] [System.Object] $Authentication = $null
	)
	Begin
	{
		$nextlink = $null
		$return = @()
	}
	Process
	{
		do
		{
			Write-Event -ID $EVENT_ID_DETAILS -Type $EVENT_TYPE_SUCCESS -Message ([System.String]::Format("Abount to query '{0}'", $uri)) -Severity $TRACE_VERBOSE
			$response = Invoke-QNDAzureRestRequest -Uri $Uri -AuthToken ($Authentication.CreateAuthorizationHeader()) -NextLink $nextlink -TimeoutSeconds 300 -ErrorAction ([System.Management.Automation.ActionPreference]::Stop)
			$nextlink = $response.NextLink
			if ($response.GotValue) {$return += $response.Values}
			if ($nextlink) {$nextlink = $nextlink.Replace('+', '%2B')}
		}
		while ($nextlink)
		
		return $return
	}
}

# Main
try
{
	$SCRIPTMOMAPI = New-Object -ComObject 'MOM.ScriptAPI'
	Write-Arguments -InputObject $MyInvocation

	try
	{
		Import-Resource -ModuleName 'QNDAdal.psm1' -ArgumentList @($false)
		Import-Resource -ModuleName 'QNDAzure.psm1' -ArgumentList @($false)
	}
	catch
	{
		Write-Event -ID $EVENT_ID_FAILURE -Type $EVENT_TYPE_ERROR -Message ([System.String]::Format('Unable to load required module. {0}', $_.Exception)) -Severity $TRACE_ERROR
		exit 1
	}

	try
	{
		if (![System.String]::IsNullOrEmpty($ProxyURI)) {Write-Event -ID $EVENT_ID_FAILURE -Type $EVENT_TYPE_WARNING -Message 'WARNING: Current version does not support proxy authentication.' -Severity $TRACE_WARNING}
		$Credential = [System.Management.Automation.PSCredential]::new($Username, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
		$Authentication = Get-AdalAuthentication -ResourceURI $ResourceURI -Authority $AuthorityURI -ClientId $ClientID -Credential $Credential
	}
	catch
	{
		Write-Event -ID $EVENT_ID_FAILURE -Type $EVENT_TYPE_ERROR -Message ([System.String]::Format('Unable to validate Azure AD Authentication. {0}', $_.Exception)) -Severity $TRACE_ERROR
		exit 1
	}

	$DiscoveryData = $SCRIPTMOMAPI.CreateDiscoveryData(0, $SourceID, $ManagedEntityID)
	

	$Rules = @(Invoke-RestApi -Uri ([System.String]::Format('{0}/{1}/providers/Microsoft.SecurityInsights/alertRules?api-version=2020-01-01', @($ResourceURI, $WorkspaceID))) -Authentication $Authentication)

	foreach ($Rule in $Rules)
	{
		Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message "$($Rule.properties.displayName) enabled $($Rule.properties.enabled)" -Severity $TRACE_VERBOSE
		if ($Rule.properties.enabled -ieq 'true')
		{
			Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message "$($Rule.properties.displayName) ExcludeByName $($Rule.name) filter $($ExcludeByName)" -Severity $TRACE_VERBOSE
			if ([System.String]::IsNullOrEmpty($ExcludeByName) -or ($Rule.name -cnotmatch $ExcludeByName))
			{
				Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message "$($Rule.properties.displayName) ExcludeByDisplayName $($Rule.properties.displayName) filter $($ExcludeByDisplayName)" -Severity $TRACE_VERBOSE
				if ([System.String]::IsNullOrEmpty($ExcludeByDisplayName) -or ($Rule.properties.displayName -cnotmatch $ExcludeByDisplayName))
				{
					Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message "$($Rule.properties.displayName) ExcludeByKind $($Rule.kind) filter $($ExcludeByKind)" -Severity $TRACE_VERBOSE
					if ([System.String]::IsNullOrEmpty($ExcludeByKind) -or ($Rule.kind -cnotmatch $ExcludeByKind))
					{
						$Severity = 'High'
						if ($Rule.properties.severity)
						{
							$Severity = $Rule.properties.severity
						} elseif ($Rule.properties.severitiesFilter)
						{
							if ($Rule.properties.severitiesFilter -contains 'High')
							{
								$Severity = 'High'
							} elseif ($Rule.properties.severitiesFilter -contains 'Medium') 
							{
								$Severity = 'Medium'								
							} elseif ($Rule.properties.severitiesFilter -contains 'Low') 
							{									
								$Severity = 'Low'
							} elseif ($Rule.properties.severitiesFilter -contains 'Informational') 
							{									
								$Severity = 'Informational'
							}
						}
						Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message "$($Rule.properties.displayName) ExcludeBySeverity $($Severity) filter $($ExcludeBySeverity)" -Severity $TRACE_VERBOSE
						if ([System.String]::IsNullOrEmpty($ExcludeBySeverity) -or ($Severity -cnotmatch $ExcludeBySeverity))
						{
							Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message "$($Rule.properties.displayName) IncludeByName $($Rule.name) filter $($IncludeByName)" -Severity $TRACE_VERBOSE
							if ([System.String]::IsNullOrEmpty($IncludeByName) -or ($Rule.name -cmatch $IncludeByName))
							{
								Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message "$($Rule.properties.displayName) IncludeByDisplayName $($Rule.properties.displayName) filter $($IncludeByDisplayName)" -Severity $TRACE_VERBOSE
								if ([System.String]::IsNullOrEmpty($IncludeByDisplayName) -or ($Rule.properties.displayName -cmatch $IncludeByDisplayName))
								{
									Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message "$($Rule.properties.displayName) IncludeByKind $($Rule.kind) filter $($IncludeByKind)" -Severity $TRACE_VERBOSE
									if ([System.String]::IsNullOrEmpty($IncludeByKind) -or ($Rule.kind -cmatch $IncludeByKind))
									{
						
										$ClassInstance = $DiscoveryData.CreateClassInstance("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']$")

										$ClassInstance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", ([System.String]::Format('Azure Sentinel Workspace Rule ({0})', $Rule.properties.displayName)))
										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']/Id$", $Rule.id)
										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']/Name$", $Rule.name)
										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']/Kind$", $Rule.kind)							

										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']/Severity$", $Severity)

										if ([System.String]::IsNullOrEmpty($Rule.properties.description)) {$description = 'undefined'} else {$description = $Rule.properties.description}
										if ([System.String]::IsNullOrEmpty($Rule.properties.alertRuleTemplateName)) {$template = 'undefined'} else {$template = $Rule.properties.alertRuleTemplateName}

										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']/Description$", $description)
										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']/Template$", $template)
										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']/WorkspaceId$", $WorkspaceID)
										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Rule.Class']/SubscriptionId$", $SubscriptionID)
										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Workspace.Class']/Id$", $WorkspaceID)
										$ClassInstance.AddProperty("$MPElement[Name='QND.Azure.Sentinel.Class']/SubscriptionId$", $SubscriptionID)
										$ClassInstance.AddProperty("$MPElement[Name='Azure!Microsoft.SystemCenter.MicrosoftAzure.Subscription']/SubscriptionId$", $SubscriptionID)
		
										$DiscoveryData.AddInstance($ClassInstance)

										$Message = [System.String]::Format('Azure Sentinel Workspace Rule {0} successfully discovered for workspace {1} for subscription {2} [ID:{3}]', @($Rule.name, $WorkspaceID, $SubscriptionID, $Rule.id))
										Write-Event -ID $EVENT_ID_SUCCESS -Type $EVENT_TYPE_INFORMATION -Message $Message -Severity $TRACE_VERBOSE
									}
								}
							}
						}
					}
				}
			}
		}
	}


	$DiscoveryData
	if ($SCRIPTLOGSEVERITY -eq $TRACE_DEBUG) {$SCRIPTMOMAPI.Return($DiscoveryData)}

	Write-Event -ID $EVENT_ID_STOP -Type $EVENT_TYPE_INFORMATION -Message ([System.String]::Format('Completed successfully in {0} seconds.', (([System.DateTime]::Now) - $SCRIPTDATETIME).TotalSeconds)) -Severity $TRACE_INFO
	Create-Event -ID $EVENT_ID_CONNECTIVITY -Type $EVENT_TYPE_INFORMATION -Message ([System.String]::Format('QND Azure Sentinel Workspace Rule [{0}]', $WorkspaceID))
}
catch
{
	$Message = [System.String]::Format('{0}{1}{2}', @($_.Exception, [System.Environment]::NewLine, $_.ScriptStackTrace))
	Write-Event -ID $EVENT_ID_FAILURE -Type $EVENT_TYPE_ERROR -Message $Message -Severity $TRACE_ERROR
}