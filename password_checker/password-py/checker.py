"""Core password strength checking module."""

from typing import Dict, List, Tuple, Any
from utils import is_common_password, calculate_entropy


class PasswordChecker:
    """Analyzes password strength and provides security recommendations."""
    
    def __init__(self) -> None:
        """Initialize the password checker."""
        self.min_length = 8
        self.max_score = 100
        
    def check_password(self, password: str) -> Dict[str, Any]:
        """
        Analyze password strength and return detailed report.
        
        Args:
            password (str): The password to check
            
        Returns:
            dict: Contains score, strength level, feedback, and recommendations
        """
        if not password:
            return self._create_report(0, "Weak", "Password is empty.", 
                                       ["Enter a password to check"])
        
        score: int = 0
        feedback: List[str] = []
        recommendations: List[str] = []
        
        # Length checks
        length_feedback, length_score, length_rec = self._check_length(password)
        feedback.append(length_feedback)
        score += length_score
        recommendations.extend(length_rec)
        
        # Character type checks
        uppercase_score, uppercase_rec = self._check_uppercase(password)
        score += uppercase_score
        if uppercase_rec:
            feedback.append("✓ Contains uppercase letters")
        else:
            recommendations.append("Add uppercase letters (A-Z)")
        
        lowercase_score, lowercase_rec = self._check_lowercase(password)
        score += lowercase_score
        if lowercase_rec:
            feedback.append("✓ Contains lowercase letters")
        else:
            recommendations.append("Add lowercase letters (a-z)")
        
        numbers_score, numbers_rec = self._check_numbers(password)
        score += numbers_score
        if numbers_rec:
            feedback.append("✓ Contains numbers")
        else:
            recommendations.append("Add numbers (0-9)")
        
        special_score, special_rec = self._check_special_chars(password)
        score += special_score
        if special_rec:
            feedback.append("✓ Contains special characters")
        else:
            recommendations.append("Add special characters (!@#$%^&*)")
        
        # Pattern checks
        sequential_score, _ = self._check_sequential_patterns(password)
        if sequential_score == 0:
            recommendations.append("Avoid sequential patterns (abc, 123, phone numbers)")
        else:
            feedback.append("✓ No obvious sequential patterns")
        score += sequential_score
        
        # Serial/Phone number checks
        serial_score, _ = self._check_numeric_sequences(password)
        if serial_score == 0:
            recommendations.append("Avoid serial numbers or phone numbers (0987654321, 1234567890)")
        else:
            feedback.append("✓ No serial/phone number patterns")
        score += serial_score
        
        repeated_score, _ = self._check_repeated_chars(password)
        if repeated_score == 0:
            recommendations.append("Minimize repeating characters")
        else:
            feedback.append("✓ Minimal repeated characters")
        score += repeated_score
        
        # Common password check
        if is_common_password(password):
            feedback.append("⚠ This is a commonly used password")
            recommendations.append("Choose a less common password")
            score -= 30
        
        # Entropy calculation
        entropy = calculate_entropy(password)
        entropy_feedback = f"Entropy: {entropy:.2f} bits"
        feedback.append(entropy_feedback)
        
        # Normalize score
        score = max(0, min(self.max_score, score))
        
        # Determine strength level
        strength_level = self._determine_strength_level(score)
        
        return self._create_report(score, strength_level, "\n".join(feedback), 
                                   recommendations)
    
    def _check_length(self, password: str) -> Tuple[str, int, List[str]]:
        """Check password length."""
        length = len(password)
        feedback = f"Length: {length} characters"
        
        if length < 8:
            return feedback, -20, ["Use at least 8 characters"]
        elif length < 12:
            return feedback, 0, []
        elif length < 16:
            return feedback, 10, []
        else:
            return feedback, 20, []
    
    def _check_uppercase(self, password: str) -> Tuple[int, bool]:
        """Check for uppercase letters."""
        has_uppercase = any(char.isupper() for char in password)
        return (10 if has_uppercase else 0, has_uppercase)
    
    def _check_lowercase(self, password: str) -> Tuple[int, bool]:
        """Check for lowercase letters."""
        has_lowercase = any(char.islower() for char in password)
        return (10 if has_lowercase else 0, has_lowercase)
    
    def _check_numbers(self, password: str) -> Tuple[int, bool]:
        """Check for numbers."""
        has_numbers = any(char.isdigit() for char in password)
        return (10 if has_numbers else 0, has_numbers)
    
    def _check_special_chars(self, password: str) -> Tuple[int, bool]:
        """Check for special characters."""
        special_chars = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
        has_special = any(char in special_chars for char in password)
        return (15 if has_special else 0, has_special)
    
    def _check_sequential_patterns(self, password: str) -> Tuple[int, bool]:
        """Check for sequential patterns like 'abc' or '123'."""
        sequential_patterns = [
            'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk',
            'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst',
            'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
            '123', '234', '345', '456', '567', '678', '789', '890'
        ]
        
        password_lower = password.lower()
        for pattern in sequential_patterns:
            if pattern in password_lower:
                return 0, False
        
        return 5, True
    
    def _check_numeric_sequences(self, password: str) -> Tuple[int, bool]:
        """Check for serial numbers and phone number patterns."""
        # Common phone number and serial patterns
        numeric_patterns = [
            '0123456789',  # Full ascending sequence
            '9876543210',  # Full descending sequence
            '1234567890',  # Common numeric pattern
            '0987654321',  # Reverse numeric pattern
            '01234567',    # Phone-like ascending
            '87654321',    # Phone-like descending
            '1234567',     # Short ascending
            '7654321',     # Short descending
        ]
        
        for pattern in numeric_patterns:
            if pattern in password:
                return 0, False
        
        # Also check for common phone number formats
        phone_pattern_checks = [
            '1111111', '2222222', '3333333', '4444444', '5555555',
            '6666666', '7777777', '8888888', '9999999', '0000000'
        ]
        
        for pattern in phone_pattern_checks:
            if pattern in password:
                return 0, False
        
        return 5, True
    
    def _check_repeated_chars(self, password: str) -> Tuple[int, bool]:
        """Check for excessive repeated characters."""
        max_repeat = max(password.count(char) for char in set(password)) if password else 0
        
        if max_repeat > len(password) // 2:
            return 0, False
        
        return 5, True
    
    def _determine_strength_level(self, score: int) -> str:
        """Determine password strength level based on score."""
        if score < 31:
            return "Weak"
        elif score < 51:
            return "Fair"
        elif score < 71:
            return "Good"
        elif score < 86:
            return "Strong"
        else:
            return "Very Strong"
    
    def _create_report(self, score: int, strength: str, feedback: str, 
                      recommendations: List[str]) -> Dict[str, Any]:
        """Create a structured password strength report."""
        return {
            "score": score,
            "strength": strength,
            "feedback": feedback,
            "recommendations": recommendations,
            "visual": self._create_visual_bar(score)
        }
    
    def _create_visual_bar(self, score: int) -> str:
        """Create a visual strength indicator."""
        filled = int(score / 10)
        empty = 10 - filled
        return "█" * filled + "░" * empty + f" ({score}/100)"
