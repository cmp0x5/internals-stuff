#############################################################################################
##
## OALABS - Debugging Fundimentals For Reverse Engineers
##
## Lab 2 - Understanding threads
##
## Usage: module_2_threads.py <target.exe>
##
#############################################################################################

import sys
import os
import time
import ctypes
import msvcrt
import pefile

from dbglib import win32types
from dbglib import win32process
from dbglib import win32memory
from dbglib import win32debug

# Globals for easy access to target information
target_process_handle = None

# Function to handle CREATE_THREAD_DEBUG_EVENT
def handle_event_create_thread(pEvent):
    print(f"\nCREATE_THREAD_DEBUG_EVENT")
    # All debug events contain 
    # - the target Process ID
    # - the thread ID for the thread where the event was raised 
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    # The create thread event also contains a CREATE_THREAD_DEBUG_INFO struct
    target_thread_info = pEvent.u.CreateThread
    target_thread_handle = target_thread_info.hThread
    target_thread_start_address = target_thread_info.lpStartAddress

    # Get the thread context and print the registers
    target_thread_context = win32process.GetThreadContext(target_thread_handle)
    print(f"Thread CONTEXT")                 
    print(f"\t Dr0: {hex(target_thread_context.Dr0)}")    
    print(f"\t Dr1: {hex(target_thread_context.Dr1)}")    
    print(f"\t Dr2: {hex(target_thread_context.Dr2)}")    
    print(f"\t Dr3: {hex(target_thread_context.Dr3)}")    
    print(f"\t Dr6: {hex(target_thread_context.Dr6)}")    
    print(f"\t Dr7: {hex(target_thread_context.Dr7)}")    
    print(f"\t Edi: {hex(target_thread_context.Edi)}")    
    print(f"\t Esi: {hex(target_thread_context.Esi)}")    
    print(f"\t Ebx: {hex(target_thread_context.Ebx)}")    
    print(f"\t Edx: {hex(target_thread_context.Edx)}")    
    print(f"\t Ecx: {hex(target_thread_context.Ecx)}")    
    print(f"\t Eax: {hex(target_thread_context.Eax)}")    
    print(f"\t Ebp: {hex(target_thread_context.Ebp)}")    
    print(f"\t Eip: {hex(target_thread_context.Eip)}")    
    print(f"\t SegCs: {hex(target_thread_context.SegCs)}")    
    print(f"\t EFlags: {hex(target_thread_context.EFlags)}")    
    print(f"\t Esp: {hex(target_thread_context.Esp)}")    
    print(f"\t SegSs: {hex(target_thread_context.SegSs)}")   

    # Because we handled the event return a status of DBG_CONTINUE
    return win32types.DBG_CONTINUE


# Function to handle EXIT_THREAD_DEBUG_EVENT
def handle_event_exit_thread(pEvent):
    print(f"\nEXIT_THREAD_DEBUG_EVENT")
    # Because we handled the event return a status of DBG_CONTINUE
    return win32types.DBG_CONTINUE
    
def print_main_from_create_process(pEvent):
    print(f"\nCREATE_PROCESS_DEBUG_EVENT")
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    target_process_info = pEvent.u.CreateProcessInfo
    target_thread_handle = target_process_info.hThread
    target_thread_context = win32process.GetThreadContext(target_thread_handle)
    print(f"Thread CONTEXT")                 
    print(f"\t Eax: {hex(target_thread_context.Eax)}")    
    print(f"\t Ebx: {hex(target_thread_context.Ebx)}")    
    print(f"\t Ecx: {hex(target_thread_context.Ecx)}")    
    print(f"\t Edx: {hex(target_thread_context.Edx)}")    
    print(f"\t Esi: {hex(target_thread_context.Esi)}")    
    print(f"\t Edi: {hex(target_thread_context.Edi)}")    
    print(f"\t Eip: {hex(target_thread_context.Eip)}")    
    print(f"\t Esp: {hex(target_thread_context.Esp)}")   
    print(f"\t Ebp: {hex(target_thread_context.Ebp)}")        
    print(f"\t SegSs: {hex(target_thread_context.SegSs)}")
    print(f"\t SegCs: {hex(target_thread_context.SegCs)}")    
    print(f"\t EFlags: {hex(target_thread_context.EFlags)}")   
    print(f"\t Dr0: {hex(target_thread_context.Dr0)}")    
    print(f"\t Dr1: {hex(target_thread_context.Dr1)}")    
    print(f"\t Dr2: {hex(target_thread_context.Dr2)}")    
    print(f"\t Dr3: {hex(target_thread_context.Dr3)}")    
    print(f"\t Dr6: {hex(target_thread_context.Dr6)}")    
    print(f"\t Dr7: {hex(target_thread_context.Dr7)}")    


def main():
    # Global access
    global target_process_handle
    # Get path to target exe
    target_path = sys.argv[1]
    print(f"Debugging target:{target_path}")

    # Create target process
    pStartupInfo = win32types.STARTUPINFO()
    pProcessInfo = win32types.PROCESS_INFORMATION()
    proc_status = ctypes.windll.kernel32.CreateProcessW(target_path,
                                                        None,
                                                        None,
                                                        None,
                                                        False,
                                                        # DEBUG_PROCESS flags tell the kernel 
                                                        # we will be debugging the created process
                                                        win32types.DEBUG_PROCESS,
                                                        None,
                                                        None,
                                                        ctypes.byref(pStartupInfo),
                                                        ctypes.byref(pProcessInfo))

    # If there is an error creating the process exit
    if not proc_status:
        print(f"Cannot create target process:{ctypes.WinError().strerror}")
        sys.exit(1)

    # The PROCESS_INFORMATION struct and STARTUPINFO struct returned from CreateProcessW()
    # contain important information about the target process including: 
    # - a handle to the process with full debug permissions
    # - the process ID
    # - a handle to the main thread
    target_process_handle = pProcessInfo.hProcess
    target_pid = pProcessInfo.dwProcessId
    target_main_thread_id = pProcessInfo.dwThreadId

    # Print the information we have received from CreateProcessW()
    print(f"Target process created (PID:{pProcessInfo.dwProcessId})")


    # This is our debug event loop
    # We keep processing debug events until the target has exited
    # The debug loop can also be terminated by pressing ENTER 
    print(f"Press ENTER to quit debug loop...")
    while True:
        # Create a DEBUG_EVENT struct to be populated with event information
        pEvent = win32types.DEBUG_EVENT()

        # Set the default debug status to DBG_EXCEPTION_NOT_HANDLED
        # This will be passed to ContinueDebugEvent() if the event is not handled 
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED

        # Wait for a debug event from the target
        # We timeout every 100 ms to allow the loop a chance to check if 
        # the user has pressed ENTER
        if ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(pEvent), 100):
            if pEvent.dwDebugEventCode == win32types.CREATE_PROCESS_DEBUG_EVENT:
                dwStatus = print_main_from_create_process(pEvent)
            # If WaitForDebugEvent() returns TRUE we have a debug event to process
            # Check if the event is related to creating or exiting threads
            elif pEvent.dwDebugEventCode == win32types.CREATE_THREAD_DEBUG_EVENT:
                # Pass event to handler and return status
                dwStatus = handle_event_create_thread(pEvent)
            elif pEvent.dwDebugEventCode == win32types.EXIT_THREAD_DEBUG_EVENT:
                # Pass event to handler and return status
                dwStatus = handle_event_exit_thread(pEvent)
            

            # Continue target process
            ctypes.windll.kernel32.ContinueDebugEvent(pEvent.dwProcessId, pEvent.dwThreadId, dwStatus)

        # If WaitForDebugEvent() returns FALSE it timed out
        # Check for ENTER key on console 
        if msvcrt.kbhit():
            if msvcrt.getwche() == '\r':
                break





if __name__ == '__main__':
    main()
