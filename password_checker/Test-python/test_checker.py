"""Unit tests for password strength checker."""

import pytest
from src.checker import PasswordChecker
from src.utils import is_common_password, calculate_entropy


class TestPasswordChecker:
    """Test cases for PasswordChecker class."""
    
    @pytest.fixture
    def checker(self) -> PasswordChecker:
        """Create a PasswordChecker instance for tests."""
        return PasswordChecker()
    
    # Test length checks
    def test_empty_password(self, checker: PasswordChecker) -> None:
        """Test with empty password."""
        result = checker.check_password("")
        assert result["strength"] == "Weak"
        assert result["score"] == 0
    
    def test_short_password(self, checker: PasswordChecker) -> None:
        """Test with short password."""
        result = checker.check_password("Pass1")
        assert result["score"] < 50
        assert "Length: 5 characters" in result["feedback"]
    
    def test_long_password(self, checker: PasswordChecker) -> None:
        """Test with long password bonus."""
        result = checker.check_password("MyS3cur3P@ssw0rdH3re123")
        assert result["score"] > 50
        assert "Length: 23 characters" in result["feedback"]
    
    # Test character type checks
    def test_uppercase_detection(self, checker: PasswordChecker) -> None:
        """Test uppercase letter detection."""
        result = checker.check_password("ABCDEFGH")
        assert "uppercase" in result["feedback"].lower()
    
    def test_lowercase_detection(self, checker: PasswordChecker) -> None:
        """Test lowercase letter detection."""
        result = checker.check_password("abcdefgh")
        assert "lowercase" in result["feedback"].lower()
    
    def test_number_detection(self, checker: PasswordChecker) -> None:
        """Test number detection."""
        result = checker.check_password("12345678")
        assert "numbers" in result["feedback"].lower()
    
    def test_special_char_detection(self, checker: PasswordChecker) -> None:
        """Test special character detection."""
        result = checker.check_password("Pass@123!")
        assert "special" in result["feedback"].lower()
    
    # Test pattern checks
    def test_sequential_pattern_detection(self, checker: PasswordChecker) -> None:
        """Test detection of sequential patterns."""
        result = checker.check_password("abcdefghij123456")
        assert "sequential" in result["feedback"].lower() or "sequential" in str(result["recommendations"]).lower()
    
    def test_no_sequential_patterns(self, checker: PasswordChecker) -> None:
        """Test password without sequential patterns."""
        result = checker.check_password("MyP@ssw0rd")
        assert result["score"] > 0
    
    def test_numeric_sequence_detection(self, checker: PasswordChecker) -> None:
        """Test detection of numeric sequences like phone numbers."""
        result = checker.check_password("Pass1234567890")
        assert "serial" in result["feedback"].lower() or "serial" in str(result["recommendations"]).lower()
    
    def test_reverse_numeric_sequence(self, checker: PasswordChecker) -> None:
        """Test detection of reverse numeric sequences."""
        result = checker.check_password("MyPass0987654321")
        assert "serial" in result["feedback"].lower() or "serial" in str(result["recommendations"]).lower()
    
    def test_no_numeric_sequences(self, checker: PasswordChecker) -> None:
        """Test password without numeric sequences."""
        result = checker.check_password("MyP@ss59w0rd")
        assert result["score"] > 0
    
    def test_repeated_numbers_detection(self, checker: PasswordChecker) -> None:
        """Test detection of repeated number patterns."""
        result = checker.check_password("Pass1111111")
        assert "serial" in result["feedback"].lower() or "serial" in str(result["recommendations"]).lower()
    
    # Test strength levels
    def test_weak_password(self, checker: PasswordChecker) -> None:
        """Test weak password detection."""
        result = checker.check_password("abc")
        assert result["strength"] == "Weak"
    
    def test_fair_password(self, checker: PasswordChecker) -> None:
        """Test fair password detection."""
        result = checker.check_password("SecurePass123")
        assert result["strength"] in ["Fair", "Good", "Strong"]
    
    def test_strong_password(self, checker: PasswordChecker) -> None:
        """Test strong password detection."""
        result = checker.check_password("MySecure@Pass2024")
        assert result["strength"] in ["Strong", "Very Strong"]
    
    def test_very_strong_password(self, checker: PasswordChecker) -> None:
        """Test very strong password detection."""
        result = checker.check_password("X$9mK#2qL@7bPn$wR!vF4cT123xyz")
        assert result["strength"] in ["Good", "Strong", "Very Strong"]
    
    # Test common passwords
    def test_common_password_penalty(self, checker: PasswordChecker) -> None:
        """Test that common passwords get penalized."""
        result = checker.check_password("password")
        assert "common" in result["feedback"].lower()
    
    # Test result structure
    def test_result_structure(self, checker: PasswordChecker) -> None:
        """Test that result has required fields."""
        result = checker.check_password("TestPass123!")
        assert "score" in result
        assert "strength" in result
        assert "feedback" in result
        assert "recommendations" in result
        assert "visual" in result
        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100


class TestCommonPasswordDetection:
    """Test cases for common password detection."""
    
    def test_common_password_detected(self) -> None:
        """Test detection of common password."""
        assert is_common_password("password") == True
        assert is_common_password("123456") == True
        assert is_common_password("qwerty") == True
    
    def test_uncommon_password(self) -> None:
        """Test that uncommon passwords are not flagged."""
        assert is_common_password("MyUniqu3P@ss") == False
        assert is_common_password("X9mK2qL7bPn") == False
    
    def test_case_insensitive(self) -> None:
        """Test case insensitive common password detection."""
        assert is_common_password("PASSWORD") == True
        assert is_common_password("Password") == True


class TestEntropy:
    """Test cases for entropy calculation."""
    
    def test_entropy_calculation(self) -> None:
        """Test entropy calculation."""
        entropy = calculate_entropy("password")
        assert entropy > 0
        assert isinstance(entropy, float)
    
    def test_empty_string_entropy(self) -> None:
        """Test entropy of empty string."""
        entropy = calculate_entropy("")
        assert entropy == 0.0
    
    def test_high_entropy(self) -> None:
        """Test that complex password has higher entropy."""
        entropy_simple = calculate_entropy("abcdefgh")
        entropy_complex = calculate_entropy("P@ssw0rd!")
        assert entropy_complex > entropy_simple
    
    def test_longer_password_higher_entropy(self) -> None:
        """Test that longer password has more entropy."""
        entropy_short = calculate_entropy("Pass1")
        entropy_long = calculate_entropy("Pass1234567890")
        assert entropy_long > entropy_short


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
