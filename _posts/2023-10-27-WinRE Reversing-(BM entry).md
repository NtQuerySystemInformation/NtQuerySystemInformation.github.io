---
layout: post
title: "Reversing WinRE for fun (old work)"
categories: rev
---

**This is some work I did for Black Mass Volume 2. I wanted to fix some parts displayed in the original work so I decided to make this blog entry for posterity.**  
   
**Only the main body is presented here, if you want to see the complete article with some other cool ones, check the main book** [here](https://www.amazon.com/VX-Underground-Black-Mass-2/dp/B0CJBP84D4)

# Why you shouldn’t trust the default WinRE local reinstall 

## 1.0: Introduction

Hello everybody, in this entry I am going to talk about a very easy way to survive payloads across default WinRE reinstallations using the `“Delete all files”` option of a home computer. 
This is so easy in fact anybody can do it without reversing anything, if you have looked enough around MSDN documentation.  

That would make this paper not worth writing, but I wanted to partially reverse the component that handled it, and this is the result of it, after some long periods of time staring at IDA.  

Finally, I want to point out that some parts were left out/optimized with significant modifications due to space. One example of these optimizations was done for ATL containers that had similar memory layout such as `CStringT` and `CSimpleStringT`, and here `CStringT` (specifically `CStringW`) will be used interchangeably for readability reasons.  
On the other hand, symbols that were excessively long in size were also optimized out.

If you want to see some of my rebuilded structures/classes so you can continue reverse engineering other features of your interest, I will post a link with a SDK-like header file at the end of the entry that you can apply directly to IDA and you can modify on your will.

## 1.1:  Brief background information. 

WinRE is, in informal terms, a “small” Windows OS (a.k.a WinPE) which is stored in a WIM disk image file inside a partition which is meant to boot up from it when your core OS is malfunctioning.  
  
In terms of the WIM file used for storing it, there is native windows binaries for manipulating it such as DISM so coding one parser is not necessary for modifying or extracting the different executables as needed. For further technical details refer to the references section.  
Describing the entire internals of this environment (WinPE variant) is not the main objective of this paper. Instead we will focus on describing how the different recovery options are selected under the hood, and the most important interactions with the recovered OS that can lead to surviving reset (where you will see it is incredibly easy in the default configuration).
However, the core question arises: How do you find the core binaries involved in this process?  
  
While the most reasonable approach would have been debugging, I decided to explore around the mounted WIM itself with the core files at first, looking for specific binaries that could be interesting, and googling them.  
 
This did not yield any results until I found the following image with an exception error.

<br>
<div style="text-align:center;">
  <img src="/assets/images/img1.png">
</div>
<br>

This error was particularly interesting because it gave away one specific binary after clicking the “Reset this PC” option: `RecEnv.exe`. Following it, I retrieved particular interesting modules
involved, which were `RecEnv.exe`, `sysreset.exe`, and `ResetEngine.dll`, but these are just some of them which we will focus on throughout the entire entry.   

However, at first this looked just like a simple coincidence, so I had to test how valid these modules were for the recovery process.
The easiest way to approach it was using the WinRE command prompt and create a process with some reversed argument parameters from the binaries recovered, specially `sysreset.exe`, which was the one that took my most attention.
I have to say the results were very interesting, as you can see by some of the screenshots below, which matched with the type of result I was expecting and I was interested in.

<br>
<div style="text-align:center;">
  <img src="/assets/images/img2.png">
</div>
<br>

<br>
<div style="text-align:center;">
  <img src="/assets/images/img3.png">
</div>
<br>

<br>
<div style="text-align:center;">
  <img src="/assets/images/img4.png" alt="Main debugging trace.">
</div>   
<br>
 
I want to point out an additional aspect that helped me out analyze statically the execution flow, and that I found later on: Log files.They contain a lot of the details of the execution environment that are stored at the end of the whole recovery process inside a folder named `$SysReset`, where each subdirectory has relevant information.  
   
In this sense, I only used mainly two file logs from this directory: `Logs/setuperr.log` and `Logs/setupact.log`.  
The main functions for logging to these files are `Logging::Trace` or `Logging::TraceErr`.
For this work, it was specially used setupact.log for debugging some of my payload script issues and mapping different blocks of code that were executed, which aid at getting a better big picture of the whole process.  
  
Initially I considered using hooks to log stack traces of particularly interesting functions, but for most of the work shown here, any additional tooling was not needed.
Without anything further to add, we can focus on describing better how some of the WinRE execution process details are staged and performed successfully.

## 1.2.1. Reverse engineering WinRE binaries for execution scheduling internals.

While at first I looked around binaries such as `RecEnv.exe` and `sysreset.exe`, I traced the execution of the modules statically in the following way:

<div style="text-align:center;">
  <p><strong>RecEnv.exe -> sysreset.exe -> ResetEngine.dll</strong></p>
</div>

In this sense, the engine core execution process can be described from this point, particularly with `ResetEngine.dll`, and exports such as `ResetExecute` or `ResetPrepareSession`.
The reason is the manipulation of an object named `Session`, which members are of huge interest for further understanding how the engine prepares itself for executing the different options available.

{% highlight cpp %}
struct Session
{
	CAtlArray m_arrayProperties;
	BoolProperty m_ConstructCheck; 
	BoolProperty m_ReadyCheck; 
	WorkingDirs* m_WorkingDirs; 
	BYTE bytes_not_relevant_members[64]; //not relevant for current context
	CString m_TargetDriveLetter;
	Options* m_Options;
	SystemInfo* m_SystemInfo; 
	DWORD m_IndexPhaseExecution; 
	DWORD GapBytes; 
	ExecState* m_ExecState; 
	OperationQueue* m_OperationQueueOfflineOps; //Offline operations
	OperationQueue* m_OperationQueueOnlineOps; //Online operations
	BYTE bytes_not_relevant_members2[12]; //not relevant for current context
}
{% endhighlight %}

The main reason for this is because this object contains a member of type `OperationQueue`, which is basically a typedef of `CAtlArray` for each operation object to be executed, tied to a particular derived `Scenario` type.  
Such scenarios are initialized thanks to `ResetPrepareSession`, and each of their operations related to it are executed properly with `ResetExecute`.

{% highlight cpp %}
struct __cppobj DerivedScenario : Scenario 
{
	void* m_Telemetry;
	ScenarioType* m_ScenarioType;.
	void* m_CloudImgObjPtr;
	void* m_PayloadInfoPtr;
	Options* m_OptionsObjPtr;
	SystemInfo* m_SystemInfoPtr;
};
{% endhighlight %}

Describing further the functionality inside `ResetPrepareSession`, the method `Session::Construct` stands out by calling `Scenario::Create` and `Scenario::Initialize`, these methods will create a different derived `Scenario` object, where there is a maximum of 13 types, being the one that matters the most to us, `ResetScenario`.  
Additionally, the vtable from the base class is replaced with the one from the derived class type, effectively overriding it for functionality specifics of that case. 
Most derived scenarios have the same size, however, for the bare metal scenario cases, additional disk info information members are added.

On the other hand, the Operation objects are queued to the `OperationQueue` thanks to the internal method per derived scenario type: `InternalConstruct`. It is important the results are applied for online and offline operations. This method is also in charge of initializing the `ExecState` object, which will see later on how it is relevant for our reverse engineering effort.

{% highlight cpp %}
dwResult = OperationQueue::Create(OperationQueueOffline); 
if ( dwResult >= 0 ){
	dwResult = OperationQueue::Create(OperationQueueOnline); 
if ( dwResult >= 0 ){
		vtableDerivedScenario = DerivedScenarioObj->vTableScenario; //Overridden by derived type.
		dwResult = vtableDerivedScenario->InternalConstruct(DerivedScenarioObj, ExecStatePtr, OperationQueueOffline,  OperationQueueOnline);
		if ( dwResult >= 0 ){
			 *OperationQueueOfflineOperations = OperationQueueOffline;
			 *OperationQueueOnlineOperations = OperationQueueOnline;
		}
	}
}
	
//Excerpt: Code snippet per Scenario to build OperationQueue objects inside Scenario::Construct.	
{% endhighlight %}

The `InternalConstruct` method redirects to an internal `DoConstruct` function.   
Inside of this function, `Operation::Create`, passes a `CStringW` which is highlighted by the code as the `OperationTypeID` member used as a key to an `CAtlMap<CStringW, struct OperationMetadata>`.   
Specifically, once the specific type is found, the derived Operation is built calling `OperationMetadata m_FactoryMethod` member, which is basically a `DerivedOperation` constructor.

{% highlight cpp %}
struct OperationMetadata
{
	CString m_OperationTypeID;			          //1.-ATL wchar_t container for operation type ID.
	void* m_FactoryMethod; 			             //2.-Main method for building derived Operation.
};

OpNode = CAtlMap<CStringW,OperationMetadata>::GetNode(m_OperationTypeIdArg, &iBinArg,&nHashArg,&prevNode);
OpMetadataObj = &OpNode->m_value;			     //Finding node from input Operation ID name.
FactoryMethod = OpMetadataObj->m_FactoryMethod;
DerivedOpObjPtr = FactoryMethod(); 		         //Calling factory method for derived Operation
*DerivedOperationObjPtr = DerivedOpObjPtr;

//Excerpt: Code snippet to build derived operation objects inside Operation::Create, using Factory method.
{% endhighlight %}

Additionally, just like with the `Scenario` class, the derived Operation object also replaces its base Operation vtable for executing specific functionalities to the operation.  
Below you can see the base Operation structure for each possible operation to be executed.

{% highlight cpp %}
struct Operation 			   //Base operation class/struct.
{
	  VtableOperation *VtableOperation; //Replaced by derived type.
	  CAtlArray m_ArrayProperties; 
	  CString m_OperationName; 
	  BoolProperty m_ExecutedProperty;
	  Session* m_SessionObjPtr;
	  void* m_TelemetryObjPtr;
};
{% endhighlight %}

Regarding ResetExecute, the internal function `Session::ExecuteOffline` redirects to `Executer::Execute`, which eventually leads to each queued derived operation’s `InternalExecute` method.

{% highlight cpp %}
PushButtonReset::Logging::Trace(0, L"Operation validity check passed, will execute");
DerivedOpObj->m_SessionObj = SessionObjCommands;
DerivedOpObj->m_TelemetryObjPtr = TelemetryObjPtr;
dwResult = (DerivedOpObj->VtableOperation->InternalExecute)(DerivedOpObj, ExecStateObjPtr, ArgObject);
DerivedOpObj->m_SessionObj = 0i64;
DerivedOpObj->m_TelemetryObjPtr = 0i64;
if( dwResult >= 0 ) {
		DerivedOperation->m_ExecutedProperty.bCheck = 1;
} else{
	Logging::TraceErr(2i64, dwResult, "PushButtonReset::Operation::Execute", "base\\reset\\engine\\exec\\src\\operation.cpp", 580, L"Internal failure in subtype execution routine");
}

//Excerpt: Code snippet showing InternalExecute per derived Operation inside Executer::Execute 
//(Notice how the members mainly passed as arguments to InternalExecute come from the base Operation type)
{% endhighlight %}

While there is other functions besides the ones just mentioned that are also involved in this process, I consider important to add only that there will also be a call to `Operation::ApplyEffects` after this code snippet, which basically executes the derived operation’s `InternalApply` method that may contain important initializations that will be used in the entire execution process, as it will be seen below.  

Staying on topic, there is a particular registry value that is used across the `ResetEngine.dll` binary, named TargetOS, which is set in `HKLM\SOFTWARE\Microsoft\RecoveryEnvironment` in the WinRE environment.   
Such registry value is extremely important because it will be used for the initialization of different members inside some of the most important classes used in the recovery process. 

One example of this can be found when we look at `m_OldOSRoot`, `m_NewOsRoot` and `m_TargetVolumeRoot` members, part of the `ExecState` class. What can be pointed out in this sense is that this object is initialized through the DerivedScenario’s `InternalConstruct` method mentioned above, which can be seen as a parameter to the method in the code snippet.  

Talking more specifically about these members mentioned, it can be pointed out that `m_OldOSRoot` and `m_TargetVolumeRoot` are initialized using `m_TargetVolume` from the Derived Scenario object, which in turn comes from the `Session` object, which is initialized from this registry value as an argument to `ResetCreateSession`.
However, at a certain point of execution all these members are set/used after the execution of one of the operations queued, specifically `OpExecSetup`, when the `InternalApply` method is called in the scheduled execution, as shown below.

{% highlight cpp %}
if (!ExecState->m_HaveOldOs.bCheck) //path mostly taken.
{ 
	ATL::CStringW(&OldWindowsDir, L"Windows.old"); 
	Path::Combine(m_TargetVolumeRoot, &OldWindowsDir, &ExecStateObj->m_OldOSRoot.CStringPath);
}
ExecStateObj->m_HaveNewOS.bCheck = 1; 
CStringW::operator=(&ExecState->m_NewOSRoot.CStringPath,&m_TargetVolumeRoot);

//Excerpt: Setting up m_NewOsRoot and m_OldOsRoot after OpExecSetup InternalApply execution.
{% endhighlight %}

**This raises the question: Why specifically this Windows.old subdirectory is set up for the m_OldOsRoot member?**

This is mainly a consequence of the `InternalExecute` method of the same `OpExecSetup` operation, specifically using `SetupPlatform.dll` when the function `CRelocateOS::DoExecute` is called.

We will not deep dive into the implementation of this aspect, since it’s not relevant enough for this paper, however, to put it briefly, it migrates some of the different subdirectories and it’s files of the `“Old OS”` under `“<DriveLetter>:\Windows.old\”`, being this a temporary directory used for the recovery process itself.
We will see exactly which migrated subdirectories from here are relevant to us in the next section.

Now that we know everything is derived from this registry value, how is this registry value even set for the WinRE environment to interact with the OS volume?. 

What I found out is that RecEnv.exe is in charge of this through `CRecoveryEnvironment::ChooseOs`. While tracing this function dynamically, the internal function `CBootCfg::GetAssociatedOs` can be highlighted. 

In this sense, what can be particularly pointed out from this method is the creation of a struct instance labeled as SRT_OS_INFO which populates it’s members inside `CBootCfg::_PopulateOsInfoForObject`. If you just wonder why this matters: it’s first member is used for initializing this registry value.

On the other hand, before calling `_PopulateOsInfoForObject`, there are interactions with the system BCD store from where the proper BCD object handle will be used to retrieve further data. From this point, a particular selection is done based on checks, which mainly focuses on matching GUIDs for finding the “Associated OS”, a.k.a our to-be recovered OS. This is mainly done inside `CBootCfg::_IsAssociatedOs`.

After this particular check has been satisfied, The `_PopulateOsInfoForObject` method will eventually call `CBootCfg::_GetWinDir`, and from here, using `BcdQueryObject`, a `_BCDE_DEVICE` struct is used for retrieving the "volume's global root path", using during my debugging sessions, the method `CBootCfg::_GetPathFromBcdePath`.

This path will then be used with `Utils::ForceDriveLetterForVolumeMountPoint` to retrieve a proper drive letter to interact with the volume and then, using `BcdGetElementDataWithFlags`, a relative WinDir Path string `(/Windows)` is retrieved using another BCD object handle related to the GUID associated OS check, and then both are concatenated to form: `<DriveLetter>:/Windows`, which is the end result used for the `TargetOS` registry value. 

You might be asking… but isn't the engine itself using a drive letter, instead of this directory path? 

To answer this we just have to keep in mind that at the moment when `sysreset.exe` calls `ResetCreateSession`, `Path::GetDrive` is used inside of `GetTargetDrive` to extract only the drive letter from the data set in the `TargetOS` registry value, working out the rest of the steps as described above.

Another aspect that I have to point out is that everything described here has been explained exclusively from the WinRE environment execution flow perspective for ease, since there are different ways to set this 
“Reset this PC” option (one of them for example could be through Settings, but all of them have the same results for our payload).

Now, we can ask the most important question after all the explanations done so far: **What additional details can be pointed out for abusing this specific scenario as needed?**   
For that, I have to show you more implementation details regarding the `ResetScenario`, which answer this question in much more detail.

## 1.2.2: ResetScenario: reversing specific derived operation objects for surviving reset.

Once we have described exactly how operations and each scenario are constructed by `ResetEngine.dll`, let’s focus on `ResetScenario::InternalConstruct`.

In this sense, this method redirects to an internal function `ResetScenario::DoConstruct`, which will be adding the Operation struct using `OperationQueue::Enqueue`.  
For this scenario, only the offline operation queue is set and the overall list of all the operations being executed can be seen below. (Remember that online operations are not set in this case).

	Offline operation queue: 24 operations (CAtlArray)
		0: Clear storage reserve (OpClearStorageReserve)
		1: Delete OS uninstall image (OpDeleteUninstall).
		2: Set remediation strategy: roll back to old OS (OpSetRemediationStrategy).
		3: Set 'In-Progress' environment key (OpMarkInProgress).
		4: Back up WinRE information (OpSaveWinRE)
		5: Archive user data files (OpArchiveUserData)
		6: Reconstruct Windows from packages (OpExecSetup)
		7: Save flighted build number to new OS (OpSaveFlight)
		8: Persist install type in new OS registry (OpSetInstallType)
		9: Notify OOBE not to prompt for a product key (OpSkipProductKeyPrompt)
		10: Migrate setting-related files and registry data (OpMigrateSettings)
		11: Migrate AppX Provisioned Apps (OpMigrateProvisionedApps)
		12: Migrate OEM PBR extensions (OpMigrateOEMExtensions)
		13: Set 'In-Progress' environment key (OpMarkInProgress)
		14: Restore boot manager settings (OpRestoreBootSettings)
		15: Restore WinRE information (OpRestoreWinRE)
		16: Install WinRE on target OS (OpInstallWinRE)
		17: Execute OEM extensibility command (OpRunExtension)
		18: Show data wipe warning, then continue (OpSetRemediationStrategy).
		19: Delete user data files (OpDeleteUserData) 
		20: Delete old OS files (OpDeleteOldOS).
		21: Delete Encryption Opt-Out marker in OS volume (OpDeleteEncryptionOptOut):
		22: Trigger WipeWarning remediation if a marker file is set (OpTriggerWipeWarning):
		23: Set remediation strategy: ignore and continue (OpSetRemediationStrategy)
 	
Now, we have to focus particularly on the specific operations that are more relevant to us, having in mind the execution order of the `OperationQueue` array that is being shown and our main objective, which is achieving any sort of filesystem persistence mechanism (surviving files and achieving code execution).

The first thing I had to focus on while trying to survive in such an environment is finding where exceptions to deletion could be happening inside the construction of the Operation queue.
Because of this, I considered initially operations such as `OpDeleteUserData` and `OpArchiveUserData`, since they seem relevant, but end up not being useful at all since they copy and delete the data they move, which is mainly `$SysReset’s stored old OS folders and files. (The path would be <DriveLetter>:\$SysReset\OldOs)`

Because of this, I focused instead on operations related to migration, such as `OpMigrateOEMExtensions`. This derived `Operation` object basically inherits everything from BaseOperation and doesn’t have any additional relevant members, so what is most interesting from it is of course, `OpMigrateOemExtensions::InternalExecute`. 

At this point, we can say code speaks more than words, the optimized code snippet is shown below:  

{% highlight cpp %}
Path::Combine(&ExecState->m_OldOSRoot.CStringPath, L"Recovery", &OldOsRecoveryPath); //Creating Recovery folder path with Old Os argument
Path::Combine(&ExecState->m_NewOSRoot.CStringPath, L"Recovery", &NewOsRecoveryPath); //Creating Recovery folder path with New Os argument.
if (!Directory::Exists(&NewOsRecoveryPath))
{ 				
	Logging::Trace(0, L"MigrateOEMExtensions: Creating recovery folder");    
	(...)
	Path::AddAttributes(&NewOsRecoveryPath);
	Directory::CopySecurity(&OldOsRecoveryPath, &NewOsRecoveryPath);   	 
}
NewOsRoot = &ExecState->m_NewOSRoot.CStringPath;
OldOsRoot = &ExecState->m_OldOSRoot.CStringPath;
TargetVolRoot = &ExecState->m_TargetVolumeRoot.CStringPath;
PbrMigrateOEMProvPackages(TargetVolRoot, OldOsRoot, NewOsRoot); //Moving packages files.
PbrMigrateOEMScripts(TargetVolRoot, OldOsRoot, NewOsRoot); //Moving scripts, core target function.
PbrMigrateOEMAutoApply(TargetVolRoot, OldOsRoot, NewOsRoot); //Moving autoapply files.
{% endhighlight %}

From all the functions that may be interesting, the one that interests me the most to cover is `PbrMigrateOEMScripts`. You might be asking why? It is pretty simple, this is the function that basically is in charge of moving files inside the `<DriveLetter>:\Recovery\OEM` folder from `OldOs (Windows.Old folder)`, to the `newOs (<DriveLetter>)`.

{% highlight cpp %}
Path::Combine(m_OldOsRoot, L"Recovery\\OEM", &OldRecOemPath);
Path::Combine(m_NewOsRoot,  L"Recovery\\OEM", &NewRecOemPath);
Logging::Trace(0, L"MigrateOEMExtensions: Migrating OEM scripts from [%s] to [%s]", OldRecOemPath.m_pchData, NewRecOemPath.m_pchData);
if (Directory::Exists(&OldRecOemPath) && !Directory::Exists(&NewRecOemPath)) 
{
	//(...)
	Directory::Move(&OldRecOemPath, &NewRecOemPath, 1u); 
}

//Excerpt: Optimized PbrMigrateOEMScripts snippet to move entire directory from old to new OS (with Directory::Move)
{% endhighlight %}

{% highlight cpp %}
Path::GetDirectory(NewOsRecoveryOemPath, &ParentDirRecovery);
if ( Directory::Exists(&ParentDirRecovery))
{
		Path::GetShortName(OldOsRecoveryOemPath, &ShortNameRecOemPath);
			Path::GetCanonical(OldOsRecoveryOemPath, &CanonicalRecOemPathOld);
		Path::GetCanonical(NewOsRecoveryOemPath, &CanonicalRecOemPathNew);
		dwFlags = !argFlag; 
		if( MoveFileExW(CanonicalRecOemPathOld, CanonicalRecOemPathNew, dwFlags))
		{
			if (ADJ(ShortNameRecOemPath.m_pchData)->nDataLength > 0) {
				Path::SetShortName(NewOsRecoveryOemPath, &ShortNameRecOemPath);
		}
	}
}

//Excerpt: Optimized Directory::Move snippet related to moving subdirectories and files.
{% endhighlight %}

This code effectively shows how the engine itself moves arbitrary files from the `“OldOS” (Windows.Old)` to the `“NewOS” (<DriveLetter>)`, as long as they are inside this folder: `Recovery\OEM`.
This however is not enough for achieving any sort of code execution to the target recovered OS, since we are limited to this directory for storage and there is no direct reliable interaction from which the recovered OS can use the migrated payload from this particular directory.

This is where an additional Operation in the queue can be chained together for exactly this purpose: `OpRunExtension`.

{% highlight cpp %}
struct __cppobj OpRunExtension : Operation
{
	BoolProperty m_IsRequired;
	StringProperty m_PhaseExecution;
	PathProperty m_ExtensibilityDir;
	StringProperty m_CommandPath;
	StringProperty m_Arguments;
	IntProperty m_Duration;
	IntProperty m_Timeout;
	PathProperty m_RecoveryImageLocation;
	BoolProperty m_WipeDataCheck;
	BoolProperty m_PartitionDiskCheck;
};
{% endhighlight %}

To show how exactly it matters to our intention, we have to look out for implementation details inside `OpRunExtension::InternalExecute`.

Mainly there are functions that are in charge of setting the necessary environment, where we can point out mainly `OpRunExtension::SetEnvironmentVariables` and of course, `OpRunExtension::RunCommand`.
The latter is the most important function of this particular derived Operation in our context, but I will describe both

{% highlight cpp %}
OpRunExtension::ExecuteCompatWorkarounds(RunExtensionObj);
dwCodeError = Path::Combine(&ExecStateObj->m_TargetVolumeRoot.CStringPath, L"Windows", &TargetWinDir);
if (dwCodeError >= 0){
	 OpRunExtension::SetEnvironmentVariables(RunExtensionObj, &TargetWinDir.m_pchData);
	 OpRunExtension::RunCommand(RunExtensionObj);
	 (...)
}

//Excerpt: Optimized OpRunExtension::InternalExecute understanding the overall execution flow.
{% endhighlight %}

First, `OpRunExtension::SetEnvironmentalVariables` is not too important, but it’s core functionality is manipulating different registry values under `HKLM\SOFTWARE\Microsoft\RecoveryEnvironment`.

Some of those values include `RecoveryImage`, `AllVolumesFormatted`, `DiskRepartitioned` and even `TargetOs`, but this is only created if it doesn’t exist, which is usually not the case as far as my tests have shown.

On the other hand, `OpRunExtension::RunCommand` is much more interesting for our purposes. 
For this aspect, we have to explain particular things related to the `OpRunExtension` object.
During the execution of `ResetScenario’s DoConstruct/InternalConstruct methods`, there are particular members that are initialized here, and most of them come from an object labeled as `“Extensibility”`

{% highlight cpp %}
if ( Extensibility::HasCommandFor(ExtensibilityObjectPtr, 3u) //Reset End phase checks.
{
	   Logging::Trace(0, L"Reset: OEM extension is available for ResetEnd");
	   Extensibility::GetCommand(ExtensibilityObjPointer, 3u, &ExtensibilityDir, &ScriptPath, &Arguments, &dwSeconds);
	   ArgsString = PayloadInfo::GetImage(&Arguments);
	   ScriptPath = PayloadInfo::GetImage(&ScriptPath);
	   OemFolderPath = PayloadInfo::GetImage(&ExtensibilityDir);
	   Logging::Trace(0, L"Reset: OEM extension command defined in [%s] for phase 2 is [%s] [%s] ([%u] seconds)", OemFolderPath, ScriptPath, ArgsString, (DWORD)dwSeconds);
	   ATL::CStringW(&OperationNameStr, L"RunExtension");
	   Operation::Create(&OperationNameStr, OpRunExtensionObjPtr);
	   BoolProperty::operator=(&OpRunExtensionObjPtr->m_IsRequired, 0i64);
	   ATL::CStringW(&m_PhaseExec, L"ResetEnd");
	   PathProperty::operator=(&OpRunExtensionObjPtr->m_PhaseExecution, &m_PhaseExec);
	   PathProperty::operator=(&OpRunExtensionObjPtr->m_ExtensibilityDir, &ExtensibilityDir);
	   PathProperty::operator=(&OpRunExtensionObjPtr->m_CommandPath, &ScriptPath);
	   PathProperty::operator=(&OpRunExtensionObjPtr->m_Arguments, &Arguments);
	   IntProperty::operator=(&OpRunExtensionObjPtr->m_Duration, dwDurationSeconds);
	   IntProperty::operator=(&OpRunExtensionObjPtr->m_Timeout, 3600);
	   BoolProperty::operator=(&OpRunExtensionObjPtr->m_WipeDataCheck, 0i64);
	   BoolProperty::operator=(&OpRunExtensionObjPtr->m_PartitionDiskCheck, 0i64);
	   OperationQueue::Enqueue(OperationQueueOffline, OpRunExtensionObjPtr);
}

//Excerpt: Optimized ResetScenario::DoConstruct snippet to understand OpRunExtension member initialization.
{% endhighlight %}

To explain how this Extensibility object is initialized, we need to focus on the proper method used for this precise purpose and the members of classes involved in it.

The answer to this is simple, and it is basically inside `ResetScenario::InternalConstruct`, using the `SystemInfo` object with the member I labeled as `m_TargetOEMResetConfigPath`.  
This is basically the path to `ResetConfig.xml`, which has to be stored in the `Recovery\OEM` directory from the `“OldOs”`.

{% highlight cpp %}
StringInOemExtensibility=CStringW::CloneData(ResetScenarioObj->m_SystemInfoPtr->m_TargetOEMResetConfigPath.CString.m_pchData);
if ( StringInOemExtensibility->nDataLength > 0 ){
	Logging::Trace(0, L"Reset: Loading OEM extensions");
	Extensibility::Load(&StringInOemExtensibility, ExtensibilityObj);
	//(...)
}
//Excerpt: Optimized ResetScenario::InternalConstruct snippet, which shows the usage of the SystemInfo member, used for referring to the ResetConfig.xml path inside Extensibility::Load.
{% endhighlight %}

If we focus on this `ResetConfig.xml` file path and how it is used, we can say that reverse engineering the XML parsing itself is not particularly interesting, but in a brief description it can be said that this `Extensibility` object using the method `Extensibility::ParseCommand` with `XmlNode::GetAttribute` and `XmlNode::GetChildText`, checks for values that are documented here.  
Specially, there is some parsed information regarding `Run/Path` XML elements that will be stored under the `Extensibility` object first member, which is of `CAtlMap<enum RunPhase, struct RunCommand>` type, particularly matching the `enum RunPhase` key and then modifying the proper RunCommand structure with the parsed information from the `XMLNode` object.  

If you wonder what all this means, it is just an overcomplicated way to say that we have to focus on three particular XML elements: `RunPhase, Run and Path`, at their proper execution phase to trigger some possible code execution.  
For our purpose, we only care for `RunPhase == FactoryReset_AfterImageApply`, which is represented in the implementation as the `enum PhaseEnd` with DWORD value `0x3`.  

However, while we know how to set up the environmental aspects of our payload so the WinRE engine works around it, we still don’t know how exactly the payload will be executed.  
To answer this, after explaining some of the workings around the setup for core objects related to `OpRunExtension`, we have to return again to the `RunCommand` method, which builds a command line string with arguments.

{% highlight cpp %}
PbrMountScriptDirectory(&this->m_ExtensibilityDir.CStringPath, &ScriptDirectory);
Logging::Trace(0, L"RunExtension: Resolved script directory [%s] to [%s]",  this->m_ExtensibilityDir.CStringPath.m_pchData, ScriptDirectory.m_pchData);
Path::Combine(&ScriptDirectory, &this->m_CommandPath.CStringMember, &ScriptFileCommand);
ATL::CStringW::Format(&ScriptFileName, L"%s %s", ScriptFileCommand.m_pchData, this->m_Arguments.CStringMember.m_pchData);
Logging::Trace(0, L"RunExtension: About to execute [%s]", ScriptFileName.m_pchData);
(...)
dwResultCode = Command::Execute(&ScriptFileName, unused_arg, CommandObjPointer);
if ( dwResultCode >= 0 ){
		dwCodeResult = Command::Wait(CommandObjPtr,this->m_Timeout.m_int_for_property);
		if ( dwCodeResult < 0 ){
			dwResultCode = 0x800705B4;
			if ( dwCodeResult == 0x800705B4 ){
				Logging::Trace(1u, L"RunExtension: The command timed out");
				Command::Cancel(pCommandObj);
				//(...)
				Logging::Trace(1u, L"RunExtension: The command was terminated");
			}
		}
		else{
			Logging::Trace(0, L"RunExtension: The command completed");
			dwErrorCode = 0;
			dwResultCode = Command::GetExitCode(CommandObj, &dwErrorCode);
			if (dwResultCode >= 0){
				if ( dwErrorCode ){
					Logging::Trace(0, L"RunExtension: The command failed: Exit Code: [%u]", dwErrorCode);
				}
			}
		}
}	
//Excerpt: Optimized OpRunExtension::RunCommand for overall execution flow.
{% endhighlight %}

If we inspect `Command::Execute`, the most important snippet of code that matters for our purposes is the following one:

{% highlight cpp %}

memset_0(&ProcessInfo, 0, sizeof(ProcessInfo));
ProcessInfo.cb = 104;
ProcessInfo.dwFlags = 256;
ProcessInfo.hStdInput = Input;
ProcessInfo.hStdOutput = commandObj;
ProcessInfo.hStdError = commandObj;
memset(&lpProcessInformation, 0, sizeof(lpProcessInformation));
CreateProcessW(0i64, CommandLineOutput->m_pchData, 0i64, 0i64, 1, 0x8000000u, 0i64, 0i64, &ProcessInfo, &lpProcessInformation);

{% endhighlight %}

This is where the brainstorming started:   
Since we have code execution within this environment and we know the operation scheduling order from static analysis, we can be sure that our stored payloads will be migrated from our “OldOs” to any “NewOs” OEM directory, thanks to `OpMigrateOemExtensions` and additionally, using a script file or a custom binary with particular arguments, we can also “arbitrarily” migrate from this “NewOS” OEM folder to a “NewOS” reliable directory from where we are sure we can trigger filesystem persistence, thanks to `OpRunExtension` and the `TargetOS` registry value that the environment itself provides us to interact with the to-be recovered OS volume.  
  
This idea is the first thing that of course seemed plausible when considering the execution done by the described operations of our interest, and maybe also looked way too easy in terms of application, but at the end of my tests, there were a lot of considerations that I had in mind at the end of experiments, which you will see in the next section.


# 1.2.3: Practical limitations regarding the environment for payload’s usage:

From this point onwards, everything described here is based on the results of the experiments I did for testing my payload, rather than reverse engineering specific binaries.

In this sense, the OOBE phase is the next step which is in charge of creating the new user while using the newly modified OS volume, hence why every single change done through the recovery process is shown after the OOBE wizard has finished.

However, due to the execution flow up until this point, it is implied that the new user specific folders can’t be accessed, since the payload migration had to be done before even starting this step.
This is mentioned based on the log files described at the beginning of this work.

Taking in mind these logical assumptions, the statement that I can migrate my payload “arbitrarily” for code execution is not actually correct, since I can’t copy it to the new user’s specific target directories such as `\Users\<NewUsername>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`.

Similarly, it can be pointed out that there is also constraints related to restrictive DACLs for shared directories in a multiuser system such as `ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`, which of course difficults from where we can trigger our payload from the recovered OS.

**So what is a simple solution to this problem with the mentioned constraints?**

Simple, an old fashioned dll hijacking payload, particularly one that was reliable (a binary that is guaranteed to be loaded after the reinstallation, inside the system root directory “Drive Letter:\Windows”.)

Of course there are possibly other ways to achieve code execution by having access to this particular directory, but for this specific PoC, this was the main route that I took.

Staying on topic, there are a lot of such DLLs that could be used for this precise purpose, but the one I decided to pick up as an example was `cscapi.dll`, used by `explorer.exe`.
(Special thanks to dodo for pointing me out to this dll). 

I specially crafted some simple dll that spawned a shell, some `ResetConfig.xml` and of course, the script to be executed which triggers the migration of the payload as well, all stored inside `Recovery\OEM`.

Eventually all the process described in the sections above will be executed and we will get a command prompt after the OOBE phase for the new account created.

The payload testing phase was quite interesting, but to put it briefly, it is recommended avoiding anything non-command line based.

Finally, all of this can actually be figured out by just looking at MSDN documentation regarding ResetConfig.xml and Push-Button Reset related information, which is what I initially started to do before working on the actual reversing process to understand particular undocumented things from this environment to interact better with the result recovered OS.

The basic strategy was:
`“Poking around things until something particular interesting appears”.`