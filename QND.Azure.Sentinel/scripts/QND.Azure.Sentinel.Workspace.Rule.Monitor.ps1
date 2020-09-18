#*************************************************************************
#
#
# SCRIPT	QND.Azure.Sentinel.Workspace.Rule.monitor.ps1
# AUTHOR	PROGEL SpA
# VERSION	1.2_2020.07.28
# PURPOSE	
#
#
# CHANGELOG
#	2019.12.10 1.0 [FGa] - First release.
#	2020.07.23 1.1 [FGa] - Catch statement on incident entity exception
#	2020.07.28 1.2 [FG] - Fixed Rule Filtering and updated api-version
#
#
# (c) Copyright 2020, PROGEL SpA, All Rights Reserved. Proprietary and confidential to PROGEL SpA.
#
#
#*************************************************************************

Param
(
	[Parameter(Mandatory = $true)] [System.String] $SubscriptionID,
	[Parameter(Mandatory = $true)] [System.String] $WorkspaceID,
	[Parameter(Mandatory = $true)] [System.String] $ClientID,
	[Parameter(Mandatory = $true)] [System.String] $AuthorityURI,
	[Parameter(Mandatory = $true)] [System.String] $ResourceURI,
	[Parameter(Mandatory = $true)] [System.String] $Username,
	[Parameter(Mandatory = $true)] [System.String] $Password,
	[Parameter(Mandatory = $false)] [System.String] $ProxyURI = $null,
	[Parameter(Mandatory = $false)] [System.String] $TraceLevel = 5
)

[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'


$SCRIPTNAME = 'QND.Azure.Sentinel.Workspace.Rule.Monitor'
$SCRIPTVERSION = '1.2_2020.07.28'

$SCRIPTWORKFLOWNAME = $MyInvocation.InvocationName
$SCRIPTRUNAS = (whoami).ToString().ToUpper()
$SCRIPTDATETIME = [System.DateTime]::Now

$SCRIPTLOGSOURCE = 'QND Azure Sentinel Monitor'
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
			Write-Host ("Logging event. " + $SCRIPTNAME + " EventID: " + $ID + " eventType: " + $Type + " Version:" + $SCRIPTVERSION + " --&gt; " + $Message)
			$Message = [System.String]::Format('{0} ({1}) [{2}] -&gt; {3}{3}{4}', @($SCRIPTNAME, $SCRIPTVERSION, $SCRIPTWORKFLOWNAME, [System.Environment]::NewLine, $Message))
			Create-Event -ID $ID -Type $Type -Message $Message -Parameters @($SCRIPTNAME, $SCRIPTVERSION, $SCRIPTWORKFLOWNAME)
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


Function Exit-Bag
{
	Param
	(
		[Parameter(Mandatory = $true)] [System.Object] $InputObject,
		[Parameter(Mandatory = $true)] [System.String] $Key
	)
	Process
	{
		try
		{
			$PropertyBag = $SCRIPTMOMAPI.CreatePropertyBag()
			foreach ($Property in $InputObject.Keys) {$PropertyBag.AddValue($Property, $InputObject[$Property])}
			$PropertyBag
		}
		catch
		{
			Write-Event -ID $EVENT_ID_FAILURE -Type $EVENT_TYPE_WARNING -Message ([System.String]::Format('WARNING: Failed to create property bag [{0}]. {1}', @($InputObject[$Key], $_.Exception))) -Severity $TRACE_VERBOSE
		}
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

	$Rules = @(Invoke-RestApi -Uri ([System.String]::Format('{0}/{1}/providers/Microsoft.SecurityInsights/alertRules?api-version=2020-01-01', @($ResourceURI, $WorkspaceID))) -Authentication $Authentication)


	$Incidents = @(Invoke-RestApi -Uri ([System.String]::Format('{0}/{1}/providers/Microsoft.SecurityInsights/Incidents?api-version=2020-01-01', @($ResourceURI, $WorkspaceID))) -Authentication $Authentication)

	$BagsList = @()
	$MatchedRules = @()

	foreach ($IncidentGroup in @($Incidents | Group-Object -Property {$_.properties.title}))
	{
		$LastOccurence = @($IncidentGroup.Group | where {$_.properties.status -ine 'Closed'} | Sort-Object -Property {$_.properties.createdTimeUtc} -Descending)[0]
		
		if ($LastOccurence) {} else {
			$LastOccurence = @($IncidentGroup.Group | where {$_.properties.status -ieq 'Closed'} | Sort-Object -Property {$_.properties.createdTimeUtc} -Descending)[0]
		}


		try
		{
			$LastOccurenceEntities = @()
			$Incidentsrelations = Invoke-RestApi -Uri ([System.String]::Format('{0}/{1}/providers/Microsoft.SecurityInsights/Incidents/{2}/relations?api-version=2020-01-01', @($ResourceURI, $WorkspaceID, $LastOccurence.name))) -Authentication $Authentication
			
			$incidentAlerts = $Incidentsrelations | where { $_.properties.relatedResourceKind -eq 'SecurityAlert' } 
			foreach ($incidentAlert in $incidentAlerts)
			{
				# not found the same on the new provider :(
				$LastOccurenceEntities +=Invoke-RestApi -Uri ([System.String]::Format('{0}/{1}?api-version=2019-01-01-preview', @($ResourceURI, $incidentAlert.properties.relatedResourceId))) -Authentication $Authentication
			}
			if ($LastOccurenceEntities)
			{
				$LastOccurenceEntity = @($LastOccurenceEntities | Sort-Object -Property {$_.properties.createdTimeUtc} -Descending)[0]
			} else 	{
				$LastOccurenceEntity = $null
			}
		}
		catch
		{
			$LastOccurenceEntity = $null
		}
		
		#$CalcRuleID = $LastOccurenceEntity.properties.alertType.SubString($LastOccurenceEntity.properties.alertType.IndexOf('_') + 1)
		foreach ($RuleID in @($LastOccurence.properties.relatedAnalyticRuleIds))
		{
			$BagsList += New-Object -TypeName PSCustomObject -Property @{
			  SubscriptionID = $SubscriptionID
				WorkspaceID = $WorkspaceID
				RuleID = $RuleID
				IncidentID = $LastOccurence.id
				IncidentStatus = $LastOccurence.properties.status
				IncidentCaseNumber = $LastOccurence.properties.incidentNumber
				IncidentCreatedTime = $LastOccurence.properties.createdTimeUtc
				IncidentAlertId = $(if ($null -eq $LastOccurenceEntity) {'unknown'} else {$LastOccurenceEntity.id})
				IncidentAlertCreatedTime = $(if ($null -eq $LastOccurenceEntity) {'unknown'} else {$LastOccurenceEntity.properties.timeGenerated})
		  }
	
		}
	}


	foreach ($BagsListItem in @($BagsList | Group-Object -Property Ruleid))
	{
		$LastBag = @($BagsListItem.Group | where {$_.IncidentStatus -ine 'Closed'} | Sort-Object -Property {$_.IncidentCreatedTime} -Descending)[0]
		
		if ($LastBag) {} else {			
			$LastBag = @($BagsListItem.Group | where {$_.IncidentStatus -ieq 'Closed'} | Sort-Object -Property {$_.IncidentCreatedTime} -Descending)[0]
		}
		
		$Bag = @{
				SubscriptionID = $LastBag.SubscriptionID
				WorkspaceID = $LastBag.WorkspaceID
				RuleID = $LastBag.RuleID
				IncidentID = $LastBag.IncidentID
				IncidentStatus = $LastBag.IncidentStatus
				IncidentCaseNumber = $LastBag.IncidentCaseNumber
				IncidentCreatedTime = $LastBag.IncidentCreatedTime
				IncidentAlertId = $LastBag.IncidentAlertId
				IncidentAlertCreatedTime = $LastBag.IncidentAlertCreatedTime
		}
		$MatchedRules += $BagsListItem.Name
		Create-Event -ID $EVENT_ID_CONNECTIVITY -Type $EVENT_TYPE_INFORMATION -Message ([System.String]::Format('QND Azure Sentinel Workspace Rule Monitor [{0}]', $BagsListItem.Name))
		Exit-Bag -InputObject $Bag -Key RuleID

	}

	foreach ($Rule in $Rules)
	{
		if ($Rule.id -notin $MatchedRules)
		{		
			$Bag = @{
					SubscriptionID = $SubscriptionID
					WorkspaceID = $WorkspaceID
					RuleID = $rule.id
					IncidentID = 'none'
					IncidentStatus = 'none'
					IncidentCaseNumber = 'none'
					IncidentCreatedTime = 'none'
					IncidentAlertId = 'none'
					IncidentAlertCreatedTime = 'none'
			}
			write-host "NoMatch"
		}
		else
		{
			write-host "Match"

		}
		
		Create-Event -ID $EVENT_ID_CONNECTIVITY -Type $EVENT_TYPE_INFORMATION -Message ([System.String]::Format('QND Azure Sentinel Workspace Rule Monitor [{0}]', $Rule.id))
		Exit-Bag -InputObject $Bag -Key RuleID
	}
	

	Write-Event -ID $EVENT_ID_STOP -Type $EVENT_TYPE_INFORMATION -Message ([System.String]::Format('Completed successfully in {0} seconds.', (([System.DateTime]::Now) - $SCRIPTDATETIME).TotalSeconds)) -Severity $TRACE_INFO	
}
catch
{
	$Message = [System.String]::Format('{0}{1}{2}', @($_.Exception, [System.Environment]::NewLine, $_.ScriptStackTrace))
	Write-Event -ID $EVENT_ID_FAILURE -Type $EVENT_TYPE_ERROR -Message $Message -Severity $TRACE_ERROR
}