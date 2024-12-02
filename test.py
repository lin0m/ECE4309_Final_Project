import os
from time import sleep

def main():
    while True:
        print(f"Select an option from below.")
        print("1.    Open")
        print("2.    Modify")
        print("q     Exit program")
        user_response = input("Please enter your selection: ")
        if user_response.strip() == '1':
            open_file()
        elif user_response.strip() == '2':
            modify_file()
        elif user_response.strip() == 'q':
            print("Program ended.")
            exit(0)

def open_file():
    file = open("test.txt", 'r')
    print("File opened")
    sleep(1)
    file_lines = file.readlines()
    for line in file_lines:
        print(line)
    print("File read")
    sleep(1)
    file.close()
    print("File closed")
    sleep(1)

def modify_file():
    file = open("test.txt", 'w')
    print("File opened")
    sleep(1)
    file.write("ABCDEFG")
    print("File modified")
    sleep(1)
    file.close()
    print("File closed")
    sleep(1)

if __name__ == "__main__":
    main()