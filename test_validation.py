# test_validation.py
def validate_port(port_str):
    """Validates port number or range"""
    # Handle None or empty string
    if port_str is None or port_str == '':
        return True, None  # Empty is OK
    
    # Convert to string and strip whitespace
    port_str = str(port_str).strip()
    
    # Empty after strip
    if not port_str:
        return True, None
    
    # Single port
    if ':' not in port_str:
        # Check if it's a valid number
        if not port_str.isdigit():
            return False, f"Port '{port_str}' must be a number"
        
        try:
            port = int(port_str)
        except ValueError:
            return False, f"Port '{port_str}' is not a valid number"
        
        if port < 1 or port > 65535:
            return False, f"Port {port} must be between 1 and 65535"
        
        return True, None
    
    # Port range (1024:2048)
    try:
        parts = port_str.split(':')
        if len(parts) != 2:
            return False, "Port range must be in format START:END (e.g., 1024:2048)"
        
        # Check if both parts are numeric
        start_str = parts[0].strip()
        end_str = parts[1].strip()
        
        if not start_str.isdigit():
            return False, f"Port range start '{start_str}' must be a number"
        if not end_str.isdigit():
            return False, f"Port range end '{end_str}' must be a number"
        
        start = int(start_str)
        end = int(end_str)
        
        # Validate range
        if start < 1 or start > 65535:
            return False, f"Port range start {start} must be between 1 and 65535"
        if end < 1 or end > 65535:
            return False, f"Port range end {end} must be between 1 and 65535"
        if start > end:
            return False, f"Port range start ({start}) must be less than or equal to end ({end})"
        
        return True, None
    except ValueError as e:
        return False, f"Invalid port range format: {str(e)}"

# Test cases
test_cases = [
    ("80", True, "Valid single port"),
    ("443", True, "Valid single port"),
    ("1024:2048", True, "Valid port range"),
    ("80:70", False, "Invalid range (start > end)"),
    ("99999999", False, "Port too large"),
    ("0", False, "Port too small"),
    ("abc", False, "Not a number"),
    ("80:abc", False, "Range with non-numeric end"),
    ("-1", False, "Negative port"),
    ("", True, "Empty string (allowed)"),
    (None, True, "None (allowed)"),
    ("1:65535", True, "Full valid range"),
    ("65536", False, "Port > 65535"),
]

print("Testing port validation:")
print("-" * 80)
for test_input, expected_valid, description in test_cases:
    valid, error = validate_port(test_input)
    status = "✅ PASS" if valid == expected_valid else "❌ FAIL"
    print(f"{status} | Input: {repr(test_input):15} | Expected: {expected_valid:5} | Got: {valid:5} | {description}")
    if error and not expected_valid:
        print(f"       Error message: {error}")
print("-" * 80)
