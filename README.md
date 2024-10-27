## Indirect Branch Tracking (IBT)
Legitimate functions or branch-targets must begin with an `ENDBRANCH` instruction (`ENDBR32` or `ENDBR64`). If an indirect call or jump lands on anything that is not end_branch, the hardware raises the `Control Protection (CP)` flag.

Direct calls/jumps are unaffected by IBT since they're assumed safe.
## Shadow Stacks (SS)
The Shadow Stack is used to check the integrity of the call-return chain in order to prevent ROP attacks.

When a function is called, the return address is pushed onto the Shadow Stack (hardware protected). Upon return, the processor verifies that the address popped form the user's stack matches.

## Strict Mode
If strict mode is not enabled on the system and the target binary is not `CETCOMPAT`, all failed checks will be ignored and the program will execute normally, similar to `CFG Protections` but unlike CFG, CET will continue to execute operational checks during runtime.

## CETCOMPAT
If the `OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]->GuardFlags` does have the `CETCOMPAT` flagged, `RtlFindDynamicEnforcedAddressInRanges` will be called to check if the target is inside one of the CET-compatible address ranges upon jmp/call.

If the range is invalid, or for some reason the process shouldn't crash (not CET-compatible or audit mode is enabled), then `KiFixupControlProtectionUserModeReturnMismatch` to insert the target address into the shadow stack as an exclusion.

## High Level Flow

```cpp
typedef struct _EPROCESS {
    // <...>
    struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;  
    struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;  
    /* 0x0b28 */ struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges;  
    unsigned long DisabledComponentFlags;
    // <...>
} EPROCESS, *PEPROCESS;


```

The `DynamicEnforcedCetCompatibleRanges` struct contains an `RTL_AVL_TREE` and an `EX_PUSH_LOCK`. New ranges are inserted into the tree through a call to `NtSetInformationProcess` with the new information class `ProcessDynamicEnforcedCetCompatibleRanges (0x66)`

The caller supplies a pointer to a `PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION` struct that contains the address ranges to insert into or remove from the AVL Tree.

```cpp
typedef struct _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE {  
    ULONG_PTR BaseAddress;  
    SIZE_T Size;  
    DWORD Flags;  
} PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE, *PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE;

typedef struct _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION {  
    WORD NumberOfRanges; 
    WORD Reserved;  
    DWORD Reserved2;  
    PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE Ranges;  
} PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION, *PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION;
```

Of course, there's also a wrapper for this and `NtSetInformationProcess` is not necessary:
```cpp
BOOL  
SetProcessDynamicEnforcedCetCompatibleRanges(  
    _In_ HANDLE ProcessHandle,  
    _In_ WORD NumberOfRanges,  
    _In_ PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE Ranges  
)  
{  
    NTSTATUS status;  
    PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION dynamicEnforcedAddressRanges;  
    dynamicEnforcedAddressRanges.NumberOfRanges = NumberOfRanges;  
    dynamicEnforcedAddressRanges.Ranges = Ranges;  
    status = NtSetInformationProcess(ProcessHandle,  
        ProcessDynamicEnforcedCetCompatibleRanges,  
        &dynamicEnforcedAddressRanges,  
        sizeof(PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION));  

    if (NT_SUCCESS(status)) {  
        return TRUE;  
    }  
    BaseSetLastNTError(status);  
    return FALSE;  
}
```
## Problem??
It's pretty clear that if a process can declare ranges for itself with CET then an attacker can do this for any ranges they're interested in using for return-oriented programming (ROP). However, this is why `CetDynamicApisOutOfProcOnly` was added.

It only allows a process to add dynamic CET compatible ranges for remote processes and not themselves, because ROP cannot touch outside the attacker's process space and wouldn't be useful, so it's an easy buy-one get-one for developers.

Of course, Counterfeit Object-Oriented Programming (COOP) is still a viable bypass to CET, but this greatly increases the level of complexity for exploit-development and reduces the  attack surface dramatically.

More about Counterfeit Object-Oriented Programming in another section...


### sources:
   - https://windows-internals.com/cet-updates-dynamic-address-ranges/