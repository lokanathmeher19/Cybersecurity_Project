"""Command-line interface for password strength checker."""

import getpass
import sys
from typing import Any
from colorama import init, Fore, Style
from checker import PasswordChecker
from utils import get_password_strength_recommendations


# Initialize colorama for cross-platform colored output
init(autoreset=True)


def print_header() -> None:
    """Print application header."""
    print("\n" + "="*60)
    print(Fore.CYAN + "        PASSWORD STRENGTH CHECKER" + Style.RESET_ALL)
    print(Fore.CYAN + "    Cybersecurity Educational Tool v1.0" + Style.RESET_ALL)
    print("="*60 + "\n")


def get_strength_color(strength: str) -> str:
    """Get color code for strength level."""
    colors: dict[str, str] = {
        "Weak": Fore.RED,
        "Fair": Fore.YELLOW,
        "Good": Fore.LIGHTGREEN_EX,
        "Strong": Fore.GREEN,
        "Very Strong": Fore.LIGHTGREEN_EX
    }
    return colors.get(strength, Fore.WHITE)


def print_result(result: dict[str, Any]) -> None:
    """
    Print password strength check result in formatted output.
    
    Args:
        result (dict): Result dictionary from checker
    """
    strength_color = get_strength_color(result["strength"])
    
    print("\n" + "-"*60)
    print(Fore.YELLOW + "RESULTS:" + Style.RESET_ALL)
    print("-"*60)
    
    # Print strength level with color
    print(f"Strength Level: {strength_color}{result['strength']}{Style.RESET_ALL}")
    
    # Print visual bar
    print(f"Strength Bar:   {result['visual']}")
    
    # Print feedback
    print(f"\n{Fore.CYAN}Analysis:{Style.RESET_ALL}")
    for line in result["feedback"].split("\n"):
        if line.strip():
            print(f"  {line}")
    
    # Print recommendations if any
    if result["recommendations"]:
        print(f"\n{Fore.LIGHTRED_EX}Recommendations:{Style.RESET_ALL}")
        for i, rec in enumerate(result["recommendations"], 1):
            print(f"  {i}. {rec}")
    else:
        print(f"\n{Fore.GREEN}✓ No improvements needed!{Style.RESET_ALL}")
    
    # Print general security tips
    print(f"\n{Fore.LIGHTCYAN_EX}Security Tips:{Style.RESET_ALL}")
    for tip in get_password_strength_recommendations(result["score"]):
        print(f"  • {tip}")
    
    print("-"*60 + "\n")


def main() -> None:
    """Main function for CLI interface."""
    try:
        print_header()
        
        checker = PasswordChecker()
        
        while True:
            try:
                # Get password input securely
                password = getpass.getpass(
                    Fore.LIGHTYELLOW_EX + "Enter a password to check (or 'quit' to exit): " + Style.RESET_ALL
                )
                
                # Check for exit command
                if password.lower() == 'quit':
                    print(Fore.CYAN + "Thank you for using Password Strength Checker!" + Style.RESET_ALL)
                    break
                
                # Check password
                result = checker.check_password(password)
                
                # Print results
                print_result(result)
                
                # Ask if user wants to check another
                another = input(
                    Fore.LIGHTYELLOW_EX + "Check another password? (yes/no): " + Style.RESET_ALL
                ).strip().lower()
                
                if another not in ['yes', 'y']:
                    print(Fore.CYAN + "Thank you for using Password Strength Checker!" + Style.RESET_ALL)
                    break
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Input cancelled.{Style.RESET_ALL}")
                break
                
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
