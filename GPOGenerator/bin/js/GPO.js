function parseIpPortProto( filter )
{
	var port='Any';
	var ip='Any';
	var proto='Any';
	var tmp = '';
	if( filter.indexOf(':') !== -1 ){// "$IPForInternet:*/TCP",
		tmp = filter.split(':')
		if( tmp[0] !== '*' && tmp[0] !== '' ){
			ip = tmp[0];
		}					
		filter = tmp[1];
	}
	tmp = filter.split('/');
	if( tmp[0] !== '*' && tmp[0] !== '' ){
		port = tmp[0];
	}
	if( tmp[1] !== '*' && tmp[1] !== '' ){
		proto = tmp[1];
	}
	return {'ip':ip,'port':port,'proto':proto};
}


function getGPOName( name, category, prefix, shortPrefix )
{
	if( prefix ){
		if( shortPrefix ){
			return '['+prefix+']['+category+']('+shortPrefix+') '+name;
		}else{
			return '['+prefix+']['+category+'] '+name;
		}		
	}else{
		if( shortPrefix ){
			return '['+category+']('+shortPrefix+') '+name;
		}else{
			return '['+category+'] '+name;
		}
	}
}
function onCheckboxChange()
{
	var release=[];
	var prefix=document.getElementById('prefix').value;

	for( var category in gpoYamlRules )
	{
		for( var gpoId in gpoYamlRules[category] )
		{
			var gpo = gpoYamlRules[category][gpoId];
			var gpoName = getGPOName(gpoId, category, prefix, gpo['ShortPrefix']);
			console.log('Creating '+gpoName+'...');

			var comment = '';
			if( gpo['Comment'] ){
				comment = ' -Comment "##################################`r`n`r`n'+gpo['Comment'].trim().replace(new RegExp('"','g'),'`"').replace(new RegExp('\\$','g'),'`$').replace(new RegExp('\r','g'),'').replace(new RegExp('\n','g'),'`r`n')+'"'
			}
			
			release += '###########################################################################################\n';
			release += '# '+gpoName+'\n';
			release += '###########################################################################################\n';
			var hasGpoInf = false;
			
			//#########################################################################################
			if( gpo['Script'] ){
				release += gpo['Script'];
			}
			if( (gpo['Script'] && Object.keys(gpo).length > 1) || (!gpo['Script'] && Object.keys(gpo).length >= 1) ){
				release += 'New-GPO -Name "'+gpoName.replace('"','')+'"'+comment+' | %{'+'\n';
			}

			//#########################################################################################
			for( var hkey in gpo['Hive'] )
			{
				for( var hval in gpo['Hive'][hkey] )
				{
					var tmp=gpo['Hive'][hkey][hval].split(':');
					var valType=tmp[0];
					var val=tmp.slice(1).join(':').replace(new RegExp('"','g'),'`"');
					if( valType.toLowerCase() !== 'dword' ){
						val = '"'+val+'"';
					}
					release += '	$_ | Set-GPRegistryValue -Key "'+hkey.replace('"','')+'" -ValueName "'+hval.replace('"','')+'" -Value '+val+' -Type '+valType+' >$null\n';
				}
			}
			
			if( gpo['Tasks'] ){
				release += '	$gpoId="{{{0}}}" -f $_.Id.ToString();\n';
				release += '	$gpoName=$_.DisplayName\n';
				var tasks = {'Machine':'','User':''};
				for( var taskName in gpo['Tasks'] )
				{
					var taskType = (gpo['Tasks'][taskName]['Type']&& ['ImmediateTask','Task'].includes(gpo['Tasks'][taskName]['Type']))?gpo['Tasks'][taskName]['Type']:'ImmediateTask';// ImmediateTask or Task
					var taskCmd = gpo['Tasks'][taskName]['Command']?gpo['Tasks'][taskName]['Command']:'powershell';
					var taskCmdArg = gpo['Tasks'][taskName]['CommandArguments']?gpo['Tasks'][taskName]['CommandArguments']:'-exec Bypass -Nop -Command "whoami | out-file %TEMP%\\example.log"';
					var taskAs = gpo['Tasks'][taskName]['RunAs']?gpo['Tasks'][taskName]['RunAs']:'S-1-5-18';// S-1-5-18
					var taskCtx = (gpo['Tasks'][taskName]['Context'] && (gpo['Tasks'][taskName]['Context'] === 'User' || gpo['Tasks'][taskName]['Context'] == 'Machine'))?gpo['Tasks'][taskName]['Context']:'Machine';// User or Machine
					var taskTimer = gpo['Tasks'][taskName]['StartEveryDayAt']?gpo['Tasks'][taskName]['StartEveryDayAt']:'9';
					var taskAction = (gpo['Tasks'][taskName]['taskAction'] && ['C','R','U','D'].includes(gpo['Tasks'][taskName]['taskAction']))?gpo['Tasks'][taskName]['taskAction']:'R';// R=Replace, C=Create, U=Update, D=Delete
					var deleteExpiredTaskAfter = '';
					var taskProperties = '';
					var clsid = '';
					if( taskType === 'ImmediateTask' ){
						clsid = '9756B581-76EC-4169-9AFC-0CA8D43ADB5F';
						deleteExpiredTaskAfter = '<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>';
						taskProperties = 'userContext="0" removePolicy="0"';
						taskTriggers = '<TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger>'
					}else{
						clsid = 'D8896631-B747-47a7-84A6-C155337F3BC8';
						taskTriggers = '<CalendarTrigger><StartBoundary>$((Get-Date).AddDays(1).ToString("yyyy-MM-ddT{0:d2}:00:00" -f '+taskTimer+'))</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>';
					}
					tasks[taskCtx] += '<'+taskType+'V2 clsid="{'+clsid+'}" name="[GPO] '+taskName+'" image="0" changed="$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))" uid="{D98A502B-7563-4A3D-A4EA-5B4EE8E63364}" '+taskProperties+'><Properties action="'+taskAction+'" name="[GPO] '+taskName+'" runAs="'+taskAs+'" logonType="S4U"><Task version="1.2"><RegistrationInfo><Author>$($env:USERDOMAIN)\\$($env:USERNAME)</Author><Description>This task need to run with '+taskAs+' // GPO Id: $gpoId // GPO Name: $gpoName</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>'+taskAs+'</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT5M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT2H</ExecutionTimeLimit><Priority>7</Priority>'+deleteExpiredTaskAfter+'<RestartOnFailure><Interval>PT5M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>'+taskCmd+'</Command><Arguments>'+taskCmdArg+'</Arguments></Exec></Actions><Triggers>'+taskTriggers+'</Triggers></Task></Properties></'+taskType+'V2>\n';
				}
				for( ctx in tasks )
				{
					if( tasks[ctx] && tasks[ctx] !== '' ){
						release += '	$gpoPath="C:\\Windows\\SYSVOL\\domain\\Policies\\$gpoId\\'+ctx+'\\Preferences\\ScheduledTasks";\n';
						release += '	mkdir "$gpoPath" >$null\n';
						release += '	( @"\n';
						release += '<?xml version="1.0" encoding="utf-8"?>\n';
						release += '<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">';
						release += tasks[ctx];
						release += '</ScheduledTasks>\n';
						release += '"@ ).Trim() | Out-File -Encoding ASCII "$gpoPath\\ScheduledTasks.xml"\n';
						release += '	Get-AdObject -Filter "(objectClass -eq \'groupPolicyContainer\') -and (name -eq \'$gpoId\')" | Set-ADObject -Replace @{gPC'+ctx+'ExtensionNames="[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"};\n';
					}
				}
			}
			
			//#########################################################################################
			if( gpo['Fw'] ){
				release += '	$GpoSessionName = Open-NetGPO -PolicyStore ("{0}\\{1}" -f $env:USERDNSDOMAIN,$_.DisplayName)'+'\n';
				var netFirewallProfile=false;
				if( 'Enabled' in gpo['Fw'] || 'NotifyOnListen' in gpo['Fw'] || 'DefaultOutboundAction' in gpo['Fw'] || 'DefaultInboundAction' in gpo['Fw'] || 'AllowInboundRules' in gpo['Fw'] || 'AllowLocalFirewallRules' in gpo['Fw'] || 'AllowLocalIPsecRules' in gpo['Fw'] || 'AllowUnicastResponseToMulticast' in gpo['Fw'] || 'LogAllowed' in gpo['Fw'] || 'LogBlocked' in gpo['Fw'] || 'LogIgnored' in gpo['Fw'] || 'LogFileName' in gpo['Fw'] || 'LogMaxSizeKilobytes' in gpo['Fw'] ){
					netFirewallProfile=true;
					release += '	Set-NetFirewallProfile -GPOSession $GpoSessionName -All';
				}
				if( 'LogFileName' in gpo['Fw'] ){
					release += ' -LogFileName "'+gpo['Fw']['LogFileName']+'"';
				}
				for( var fwOpt of ['Enabled','NotifyOnListen','DefaultOutboundAction','DefaultInboundAction','AllowInboundRules','AllowLocalFirewallRules','AllowLocalIPsecRules','AllowUnicastResponseToMulticast','LogAllowed','LogBlocked','LogIgnored','LogMaxSizeKilobytes'] )
				{
					if( gpo['Fw'][fwOpt] !== undefined ){
						release += ' -'+fwOpt+' '+gpo['Fw'][fwOpt];
					}
				}
				if( netFirewallProfile ){
					release += ' >$null\n';
				}

			
				//#########################################################################################
				for( var actDir of ['Outbound-Block','Outbound-Allow','Inbound-Block','Inbound-Allow'] )
				{
					if( gpo['Fw'][actDir] ){
						var tmp = actDir.split('-');
						var direction=tmp[0];
						var action=tmp[1];
						var portDirection = 'RemotePort';
						if( direction === 'Inbound' ){
							portDirection = 'LocalPort';
						}
						if( typeof gpo['Fw'][actDir] === 'string' ){
							var ipp = parseIpPortProto(gpo['Fw'][actDir]);
							release += '	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] '+gpoName.replace('"','')+'" -Group "[GPO]'+gpoName.replace('"','')+'" -Action '+action+' -Direction '+direction;
							if( ipp['port'] !== 'Any' ){
								release += ' -'+portDirection+' '+ipp['port'];
							}
							if( ipp['proto'] !== 'Any' ){
								release += ' -Protocol '+ipp['proto'];
							}
							if( ipp['ip'] !== 'Any' ){
								if( direction === 'Inbound' ){
									release += ' -RemoteAddress '+ipp['ip'];
								}else{
									release += ' -LocalAddress '+ipp['ip'];
								}
							}
							release += ' >$null\n';
						}else{
							var ipp = '';
							for( var fwName in gpo['Fw'][actDir] )
							{
								if( typeof gpo['Fw'][actDir][fwName] === 'object' ){
									var template = '	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] '+fwName.replace('"','')+'" -Group "[GPO]'+gpoName.replace('"','')+'" -Action '+action+' -Direction '+direction;
									
									if( gpo['Fw'][actDir][fwName]['Program'] === undefined || typeof gpo['Fw'][actDir][fwName]['Program'] === 'string' ){
										release += template;
										for( var fwArgs in gpo['Fw'][actDir][fwName] )
										{
											release += ' -'+fwArgs+' '+gpo['Fw'][actDir][fwName][fwArgs];
										}
										release += ' >$null\n';
									}else{
										for( var fwArgs in gpo['Fw'][actDir][fwName] )
										{
											if( fwArgs !== 'Program' ){
												template += ' -'+fwArgs+' '+gpo['Fw'][actDir][fwName][fwArgs];
											}
										}
										for( var proc of gpo['Fw'][actDir][fwName]['Program'] )
										{
											release += template+' -Program "'+proc+'" >$null\n';
										}
									}
								}else{
									ipp = parseIpPortProto(gpo['Fw'][actDir][fwName]);
									release += '	New-NetFirewallRule -Enabled True -Profile Any -ErrorAction Continue -GPOSession $GpoSessionName -DisplayName "[GPO] '+fwName.replace('"','')+'" -Group "[GPO]'+gpoName.replace('"','')+'" -Action '+action+' -Direction '+direction;
									if( ipp['port'] !== 'Any' ){
										release += ' -'+portDirection+' '+ipp['port'];
									}
									if( ipp['proto'] !== 'Any' ){
										release += ' -Protocol '+ipp['proto'];
									}
									if( ipp['ip'] !== 'Any' ){
										if( direction === 'Inbound' ){
											release += ' -RemoteAddress '+ipp['ip'];
										}else{
											release += ' -LocalAddress '+ipp['ip'];
										}
									}
									release += ' >$null\n';
								}
							}
						}
					}
				}
				release += '	Save-NetGPO -GPOSession $GpoSessionName >$null'+'\n'
			}
			
			//#########################################################################################
			if( 'Service General Setting' in gpo || 'Event Audit' in gpo || 'Privilege Rights' in gpo || 'Group Membership' in gpo ){
				release += '	$gpoId=$_.Id.ToString();\n';
				release += '	$gpoId="{$gpoId}";\n';
				release += '	$gpoPath="C:\\Windows\\SYSVOL\\domain\\Policies\\$gpoId\\Machine\\Microsoft\\Windows NT\\SecEdit"\n';
				release += '	mkdir "$gpoPath" >$null\n';
				release += '	$inf =  "[Unicode]`r`n";\n';
				release += '	$inf += "Unicode=yes`r`n";\n';
				hasGpoInf = true;
			}
			
			//#########################################################################################
			var keyInf='Service General Setting';
			if( gpo[keyInf] ){
				release += '	$inf += "['+keyInf+']`r`n"\n';
				for( var serv in gpo[keyInf] )
				{
					release += '	$inf += \'"'+serv+'",'+gpo[keyInf][serv]+',""\'+"`r`n";\n';
				}
			}
			//#########################################################################################
			var keyInf='Event Audit';
			if( gpo[keyInf] ){
				release += '	$inf += "['+keyInf+']`r`n"\n';
				for( var serv in gpo[keyInf] )
				{
					release += '	$inf += \''+serv+' = '+gpo[keyInf][serv]+'\'+"`r`n";\n';
				}
			}
			
			//#########################################################################################
			for( var keyInf of ['Privilege Rights','Group Membership'] )
			{
				if( gpo[keyInf] !== undefined ){
					release += '	$inf += "['+keyInf+']`r`n"\n';
					for( var serv in gpo[keyInf] )
					{
						release += '	$inf += "'+serv+' = "';
						for( var uI=0,users=gpo[keyInf][serv].replace(' ','').split(','),uLen=users.length; uI<uLen; ++uI )
						{
							users[uI] = users[uI].trim();
							if( users[uI].indexOf('S-1') !== -1 || users[uI].indexOf('$UID__DOMAIN') !== -1 ){
								release += '+"*'+users[uI].replace('*','')+',"';
							}else{
								release += '+"*"+((New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, "'+users[uI]+'")).Translate([System.Security.Principal.SecurityIdentifier]).Value)+","'
							}
						}
						release += '+"`r`n";\n';
					}
				}
			}
			//#########################################################################################
			if( hasGpoInf ){
				release += '	$inf += "[Version]`r`n";\n';
				release += '	$inf += \'signature="$CHICAGO$"\'+"`r`n";\n';
				release += '	$inf += "Revision=1`r`n";\n';
				release += '	$inf > "$gpoPath\\GptTmpl.inf"\n';
				// To view gPCMachineExtensionNames
				// ([adsisearcher]'(objectCategory=groupPolicyContainer)').FindAll() | where { $_.Path.ToLower().Contains('102b0584-330c-4ac4-bd1b-4581a5160f7b') } | select  -ExpandProperty Properties
				// List GUID extensions https://www.infrastructureheroes.org/microsoft-infrastructure/active-directory/guid-list-of-group-policy-client-extensions/
				// {827D319E-6EAC-11D2-A4EA-00C04F79F83A}	Security
				// {803E14A0-B4FB-11D0-A0D0-00A0C90F574B}	Computer Restricted Groups
				// {CAB54552-DEEA-4691-817E-ED4A4D1AFC72}	Preference Tool CSE GUID Scheduled Tasks
				// {AADCED64-746C-4633-A97C-D61349046527}	Preference CSE GUID Scheduled Tasks
				release += '	Get-AdObject -Filter "(objectClass -eq \'groupPolicyContainer\') -and (name -eq \'$gpoId\')" | Set-ADObject -Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"};\n';
			}
		
			//#########################################################################################
			if( (gpo['Script'] && Object.keys(gpo).length > 1) || (!gpo['Script'] && Object.keys(gpo).length >= 1) ){
				release += '	$_'+'\n';
				release += '}';
			}
			
			//#########################################################################################
			if( gpo['GPLink'] ){
				if( gpo['GPLink'].includes(' -Enforced') ){
					release += ' | New-GPLink -target "'+gpo['GPLink'].replace(' -Enforced','')+'" -LinkEnabled Yes -Enforced Yes'+'\n';
				}else {
					release += ' | New-GPLink -target "'+gpo['GPLink']+'" -LinkEnabled Yes'+'\n';
				}			
			}else{
				release += '\n'
			}
			release += '\n\n'
		}
	}
	if( !release ){
		document.getElementById('release').innerText = '';
	}else{
		release = release.replace(new RegExp('\\$LDAP_DN','g'),"$(([ADSI]'LDAP://RootDSE').defaultNamingContext.Value)")
		document.getElementById('release').innerHTML=hljs.highlightAuto(release).value;
	}
}

var prefix=document.getElementById('prefix');
prefix.addEventListener('change', onCheckboxChange, false);
prefix.addEventListener('keyup', function(e){if(e.keyCode === 13){onCheckboxChange();}}, false);
onCheckboxChange();