#############################################################################################
##
## OALABS - Debugging Fundimentals For Reverse Engineers
##
## Lab 1 - Understanding debug events 
##
## Usage: module_1_debug_events.py <target.exe>
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

# Function to handle CREATE_PROCESS_DEBUG_EVENT
def handle_event_create_process(pEvent):
    print(f"\nCREATE_PROCESS_DEBUG_EVENT")
    # All debug events contain 
    # - the target Process ID
    # - the thread ID for the thread where the event was raised 
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    # The event also contains a CREATE_PROCESS_DEBUG_INFO struct
    target_process_info = pEvent.u.CreateProcessInfo
    target_file_handle = target_process_info.hFile
    target_process_handle = target_process_info.hProcess
    target_image_base = target_process_info.lpBaseOfImage
    target_start_address = target_process_info.lpStartAddress
    print(f"Target loaded at {hex(target_image_base)}")
    print(f"Target Entry Point at {hex(target_start_address)}")
    # Because we handled the event return a status of DBG_CONTINUE
    return win32types.DBG_CONTINUE
    
def handle_event_exit_process(pEvent):
    print(f"\nEXIT_PROCESS_DEBUG_EVENT")
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    target_process_info = pEvent.u.ExitProcess
    target_exit_code = target_process_info.dwExitCode
    print(f"Exit Code is {target_exit_code}")
    return target_process_info


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
            # If WaitForDebugEvent() returns TRUE we have a debug event to process
            # Check if the event is CREATE_PROCESS_DEBUG_EVENT
            if pEvent.dwDebugEventCode == win32types.CREATE_PROCESS_DEBUG_EVENT:
                # Pass event to handler and return status
                dwStatus = handle_event_create_process(pEvent)

            # Continue target process
            ctypes.windll.kernel32.ContinueDebugEvent(pEvent.dwProcessId, pEvent.dwThreadId, dwStatus)

        # If WaitForDebugEvent() returns FALSE it timed out
        # Check for ENTER key on console 
        if msvcrt.kbhit():
            if msvcrt.getwche() == '\r':
                dwStatus = handle_event_exit_process(pEvent)
                break





if __name__ == '__main__':
    main()
