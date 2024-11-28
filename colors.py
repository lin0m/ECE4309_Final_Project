'''
--------------------------------------------------------------------------------
Description:    Color Macros
                Supplementary file containing macros for text color using ANSI 
                esccape sequences. To preview a limited selection of colors
                with no background, run this script. To view all combinations
                of text and background colors visit: 
                https://media.geeksforgeeks.org/wp-content/uploads/adfesfw-1024x394.jpg
                or the parent page:
                https://www.geeksforgeeks.org/print-colors-python-terminal/.
                Not all colors may be displayed in certain IDEs.
--------------------------------------------------------------------------------
'''

# style
RESET       = "\033[0m"
BOLD        = "\033[01m"
DISABLE     = "\033[02m"
UNDERLINE   = "\033[04m"
REVERSE     = "\033[07m"
INVISIBLE   = "\033[08m"
STRIKE_THROUGH = "\033[09m"

# text (foreground) color
BLACK       = "\033[30m"
RED         = "\033[31m"
GREEN       = "\033[32m"
ORANGE      = "\033[33m"
BLUE        = "\033[34m"
PURPLE      = "\033[35m"
CYAN        = "\033[36m"
LIGHT_GRAY  = "\033[37m"
DARK_GRAY   = "\033[90m"
LIGHT_RED   = "\033[91m"
LIGHT_GREEN = "\033[92m"
YELLOW      = "\033[93m"
LIGHT_BLUE  = "\033[94m"
PINK        = "\033[95m"
LIGHT_CYAN  = "\033[96m"

# background color
BLACK_BCKGND        = "\033[40m"
RED_BCKGND          = "\033[41m"
GREEN_BCKGND        = "\033[42m"
ORANGE_BCKGND       = "\033[43m"
BLUE_BCKGND         = "\033[44m"
PURPLE_BCKGND       = "\033[45m"
CYAN_BCKGND         = "\033[46m"
LIGHT_GRAY_BCKGND   = "\033[47m"

# print some sample colors
def main():
    print(BOLD + LIGHT_RED + ORANGE_BCKGND + "RED ON YELLOW" + RESET)
    print(BLACK       + "BLACK      " + RESET)
    print(LIGHT_GRAY  + "LIGHT_GRAY " + RESET)
    print(DARK_GRAY   + "DARK_GRAY  " + RESET)
    print(RED         + "RED        " + RESET)
    print(LIGHT_RED   + "LIGHT_RED  " + RESET)
    print(GREEN       + "GREEN      " + RESET)
    print(LIGHT_GREEN + "LIGHT_GREEN" + RESET)
    print(ORANGE      + "ORANGE     " + RESET)
    print(YELLOW      + "YELLOW     " + RESET)
    print(BLUE        + "BLUE       " + RESET)
    print(LIGHT_BLUE  + "LIGHT_BLUE " + RESET)
    print(PURPLE      + "PURPLE     " + RESET)
    print(PINK        + "PINK       " + RESET)
    print(CYAN        + "CYAN       " + RESET)
    print(LIGHT_CYAN  + "LIGHT_CYAN " + RESET)

if __name__ == "__main__":
    main()