'''
--------------------------------------------------------------------------------
Class:          ECE 4309 Cybersecurity
Group Number:   2
Group Members:  Jess Leal
                Jaemin Kim
                Huaishu Huang
                Lino Mercado-Esquivias

Description:    For a program description, run the program and select the 
                "program description" option.

Future Work:    1) Add more virus signatures to signature_scan() function.
                2) Finish heuristic scan function.
                3) Add real_time_protection() function.
                4) Scan portable executables not just python scripts.
--------------------------------------------------------------------------------
'''

# modules
import re
import os
import glob
import signal
import platform
import subprocess
from colors import *
from typing import List

def main():
    # clear terminal
    clear_terminal = set_clear_command()
    os.system(clear_terminal)

    # main menu
    while True:
        print("Welcome to BitBarrier. Select an option from below.")
        print("1.    Print program description")
        print("2.    Perform scan")
        print("3.    Enable real-time protection")
        print("q     Exit program")
        user_response = input("Please enter your selection: ")
        if user_response.strip() == '1':
            os.system(clear_terminal)
            print_program_description()
            os.system(clear_terminal)
        elif user_response.strip() == '2':
            os.system(clear_terminal)
            scan()
            input()
            os.system(clear_terminal)
        elif user_response.strip() == '3':
            os.system(clear_terminal)
            # real_time_protection()
        elif user_response.strip() == 'q':
            os.system(clear_terminal)
            print("Program ended.")
            exit(0)

# print program description
def print_program_description():
    # poll git details
    date_crated = "2024-11-07"
    try:
        command = ["git", "log", "-1", "--format=%ad", "--date=short"]
        date_modified = subprocess.check_output(command, text=True).strip()
    except subprocess.CalledProcessError:
        date_modified = "unknown"
    try:
        command = ["git", "describe", "--tags"]
        version = subprocess.check_output(command, text=True).strip()
    except subprocess.CalledProcessError:
        version = "unknown"

    # print program description    
    program_description = f"""
    PROGRAM DESCRIPTION:    
        BitBarrier {version} is a program that is meant to defend against 
        our own virus as well as other publicly available viruses.
        Date Created:   {date_crated}
        Date Modified:  {date_modified}
    """.strip()
    print(program_description)
    input("Press any key to continue... ")

# perform a scan for viruses
def scan():
    # infected_files = signature_scan_directory('/')
    infected_files = signature_scan_directory("/home/lino/Documents/ECE_4305/ECE4309_Final_Project")
    clense_infected_files(infected_files)
    suspicious_files = heuristic_scan()

# scans directory and returns a list of infected files
def signature_scan_directory(path) -> List[str]:
    infected_files = []

    # scan current directory
    for current_directory, subdirectories, files in os.walk(path):

        # scan files in current directory
        for file in files:
            if file.endswith(".py"):  
                file_path = os.path.join(current_directory, file)
                infected_file = signature_scan_file(file_path)
                if infected_file:
                    infected_files.append(infected_file)

    return infected_files

# returns file path if file is infected; returns None otherwise
def signature_scan_file(file):
    # read file
    file_is_infected = False
    with open(file, "r") as f:
        file_code = f.readlines()
    
    # check for virus signatures
    for line in file_code:
        if re.search(r"^\s*# MALICIOUS SEGMENT BEGIN\s*$", line):
            file_is_infected = True
            break
        # insert other virus signatures here
    
    # return infected files
    if file_is_infected:
        print(RED + f"File {file} is infected" + RESET)
        return os.path.abspath(file)
    else:
        return None

# clenses a list of infected files
def clense_infected_files(infected_files):
    for file in infected_files:
        # don't clense the virus file itself
        if file.endswith("self_replicating_virus.py"):
            continue
        clensed_code = []
        # read file
        with open(file, "r") as f:
            file_code = f.readlines()

        # prepare clensed file
        file_is_infected = False
        inside_malicious_segment = False
        for line in file_code:
            if line.strip() == "# MALICIOUS SEGMENT BEGIN":
                inside_malicious_segment = True
                file_is_infected = True
            elif line.strip() == "# MALICIOUS SEGMENT END":
                inside_malicious_segment = False
                continue
            if not inside_malicious_segment:
                clensed_code.append(line)
        
        # clense file
        with open(file, "w") as f:
            f.writelines(clensed_code)
            print(GREEN + f"File {file} has been clensed" + RESET)

# checks files for suspicious changes and returns a list of suspicious files
def heuristic_scan() -> List[str]:
    suspicious_files = []
    # iterate through all python programs in the current directory
    current_directory_files = glob.glob("*.py")
    for file in current_directory_files:
        file_size = os.path.getsize(file)
        date_modified = os.path.getmtime(file)
    return suspicious_files

# set command to clear the terminal depending on the operating system
def set_clear_command():
    if platform.system() == "Windows":
        return "cls"
    else:
        return "clear"

# handle kill signal by exiting gracefully
def kill_signal_handler(signal_number, frame):
    clear_terminal = set_clear_command()
    os.system(clear_terminal)
    print("Program ended.")
    exit(0)

signal.signal(signal.SIGINT, kill_signal_handler)

if __name__ == "__main__":
    main()