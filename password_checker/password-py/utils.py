"""Utility functions for password checking."""

import math
import string
from typing import List


# Common passwords list (subset of most common passwords)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustme", "dragon", "baseball", "111111", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "princess", "welcome", "jesus",
    "ninja", "mustache", "password123", "admin", "root", "toor", "pass", "test"
}


def is_common_password(password: str) -> bool:
    """
    Check if password is in the common passwords list.
    
    Args:
        password (str): Password to check
        
    Returns:
        bool: True if password is common, False otherwise
    """
    return password.lower() in COMMON_PASSWORDS


def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy of a password.
    
    Entropy = log2(charset^length)
    Higher entropy = more secure password
    
    Args:
        password (str): Password to analyze
        
    Returns:
        float: Entropy in bits
    """
    if not password:
        return 0.0
    
    # Determine character set size
    charset_size = 0
    
    if any(char in string.ascii_lowercase for char in password):
        charset_size += 26
    if any(char in string.ascii_uppercase for char in password):
        charset_size += 26
    if any(char.isdigit() for char in password):
        charset_size += 10
    if any(char in string.punctuation for char in password):
        charset_size += 33
    
    if charset_size == 0:
        return 0.0
    
    entropy = len(password) * math.log2(charset_size)
    return entropy


def get_password_strength_recommendations(score: int) -> List[str]:
    """
    Get general recommendations based on score.
    
    Args:
        score (int): Current password strength score
        
    Returns:
        list: List of general recommendations
    """
    recommendations = [
        "Always use a unique password for important accounts",
        "Consider using a password manager to store complex passwords",
        "Enable two-factor authentication (2FA) when available",
        "Change passwords periodically (every 3-6 months)",
        "Avoid sharing passwords through email or chat"
    ]
    
    if score < 50:
        recommendations.insert(0, "URGENT: This password is weak. Use it only for non-critical accounts.")
    
    return recommendations
