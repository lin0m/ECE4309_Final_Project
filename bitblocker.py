'''
--------------------------------------------------------------------------------
Class:          ECE 4309 Cybersecurity
Group Number:   2
Group Members:  Jess Leal
                Jaemin Kim
                Huaishu Huang
                Lino Mercado-Esquivias

Description:    BitBlocker is an antivirus designed to fight the BitCrusher
                virus.

Future Work:    1) Add more virus signatures to signature_scan() function.
                2) Real time protection can't detect virus pid because it's
                   too fast. Fix this somehow.
                3) Scan portable executables not just python scripts.
--------------------------------------------------------------------------------
'''

# modules
import re
import os
import sys
import glob
import signal
import platform
import subprocess
from colors import *
from time import sleep
from typing import List
from inotify_simple import INotify, flags

def main():
    # clear terminal
    clear_terminal = set_clear_command()
    os.system(clear_terminal)
    
    # variables
    program_details = poll_git()
    version = program_details[0]
    date_modified = program_details[1]
    root_directory = '/'
    home_directory = os.path.expanduser("~")
    documents_folder = os.path.join(home_directory, "Documents")
    current_directory = os.getcwd()

    # main menu
    while True:
        print(f"Welcome to BitBarrier {version} ({date_modified} release). Select an option from below.")
        print("1.    Scan current directory")
        print("2.    Quick scan")
        print("3.    Full scan")
        print("4.    Enable real-time protection")
        print("q     Exit program")
        user_response = input("Please enter your selection: ")
        if user_response.strip() == '1':
            os.system(clear_terminal)
            scan(current_directory)
            input()
            os.system(clear_terminal)
        elif user_response.strip() == '2':
            os.system(clear_terminal)
            scan(documents_folder)
            input()
            os.system(clear_terminal)
        elif user_response.strip() == '3':
            os.system(clear_terminal)
            scan(root_directory)
            input()
            os.system(clear_terminal)
        elif user_response.strip() == '4':
            os.system(clear_terminal)
            real_time_protection(current_directory)
        elif user_response.strip() == 'q':
            os.system(clear_terminal)
            print("Program ended.")
            exit(0)
        else:
            os.system(clear_terminal)

# poll git details
def poll_git() -> List:
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
    return [version, date_modified, date_crated]

# perform a scan for viruses
def scan(path):
    # check if folder exists
    if not os.path.isdir(path):
        print(f"Could not scan {path}. Folder does not exist.")
        return
    
    # perform scan
    infected_files = signature_scan_directory(path)
    clense_infected_files(infected_files)

# scans directory and returns a list of infected files
def signature_scan_directory(path) -> List[str]:
    infected_files = []

    # recursivley scan all files and subdirectories inside the current directory
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
    # skip the virus itself
    if file.endswith("bitcrusher.py"):
        return None
    # read file
    file_is_infected = False
    try:
        with open(file, "r") as f:
            file_code = f.readlines()
    except Exception as e:
        return None
    
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
    infection_count = len(infected_files)
    clense_count = 0
    for file in infected_files:
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
        clense_count += 1
        print_progress_bar(clense_count, infection_count)
        sleep(1)
    print(BOLD + GREEN + f"\n{infection_count} files have been clensed" + RESET)

# print progress bar showing clensing progress
def print_progress_bar(iteration, total, length=50, fill='█'):
    percent = f"{100 * (iteration / total):.1f}"
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\rProgress |{bar}| {percent}% Complete')
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write('\n')

# checks files for suspicious changes and returns a list of suspicious files
def real_time_protection(path):
    print("Running real time protection...")
    inotify = INotify()
    watch_flags = flags.ACCESS | flags.MODIFY | flags.CREATE | flags.DELETE
    watch_descriptor = inotify.add_watch(path, watch_flags)

    while True:
        for event in inotify.read():
            if event.mask & flags.MODIFY:
                print(f"Modified file: {event.name}")
                try:
                    # Get the process interacting with the file using lsof
                    pid_output = subprocess.check_output(["lsof", event.name]).decode().splitlines()
                    
                    if pid_output:  # If there's any output from lsof
                        for line in pid_output:
                            if "python" in line:  # Check if the process is related to Python
                                print(f"Process modifying {event.name}: {line}")
                    else:
                        print(f"No processes are interacting with {event.name}")
                except subprocess.CalledProcessError as e:
                    # Handle case where no process is found
                    print(f"No processes found for {event.name}. Error: {e}")
                except Exception as e:
                    # General error handling
                    print(f"An error occurred: {e}")

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