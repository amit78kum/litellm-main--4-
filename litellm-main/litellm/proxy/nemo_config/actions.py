import re
from typing import Optional, Dict, Any
from nemoguardrails.actions import action


# ============================================
# Jailbreak Detection
# ============================================
@action(is_system_action=True)
async def detect_jailbreak_attempt(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Detect common jailbreak attempt patterns
    Returns True if jailbreak attempt detected, False otherwise
    """
    if not context:
        return False
    
    user_message = context.get("user_message", "")
    if not user_message:
        return False
    
    # Common jailbreak patterns
    jailbreak_patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"forget\s+(all\s+)?instructions",
        r"you\s+are\s+now",
        r"new\s+role\s*:",
        r"pretend\s+(you\s+are|to\s+be)",
        r"act\s+as\s+(if|though)",
        r"DAN\s+mode",
        r"developer\s+mode",
        r"jailbreak",
        r"bypass\s+your\s+(programming|instructions|guidelines)",
        r"sudo\s+mode",
        r"admin\s+mode",
        r"god\s+mode",
        r"unrestricted\s+mode",
        r"ignore\s+your\s+(ethics|guidelines|rules)",
    ]
    
    message_lower = user_message.lower()
    
    for pattern in jailbreak_patterns:
        if re.search(pattern, message_lower):
            print(f"⚠️  Jailbreak pattern detected: {pattern}")
            return True
    
    return False


# ============================================
# PII Detection
# ============================================
@action(is_system_action=True)
async def contains_pii(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Check if message contains Personally Identifiable Information
    Returns True if PII detected, False otherwise
    """
    if not context:
        return False
    
    user_message = context.get("user_message", "")
    if not user_message:
        return False
    
    # PII patterns
    patterns = {
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "phone_us": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        "phone_intl": r'\b\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    }
    
    for pii_type, pattern in patterns.items():
        if re.search(pattern, user_message):
            print(f"⚠️  PII detected: {pii_type}")
            return True
    
    # Check for common PII keywords
    pii_keywords = [
        "social security",
        "ssn is",
        "credit card",
        "card number",
        "cvv",
        "password is",
        "my password",
        "bank account",
        "routing number"
    ]
    
    message_lower = user_message.lower()
    for keyword in pii_keywords:
        if keyword in message_lower:
            print(f"⚠️  PII keyword detected: {keyword}")
            return True
    
    return False


# ============================================
# Harmful Intent Detection
# ============================================
@action(is_system_action=True)
async def detect_harmful_intent(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Detect harmful or malicious intent in user message
    Returns True if harmful intent detected, False otherwise
    """
    if not context:
        return False
    
    user_message = context.get("user_message", "")
    if not user_message:
        return False
    
    # Harmful intent patterns
    harmful_patterns = [
        # Violence and harm
        r"how\s+to\s+(hurt|harm|attack|injure|kill)",
        r"ways\s+to\s+(hurt|harm|attack|injure)",
        r"methods\s+(to|for)\s+(hurt|harm|kill)",
        
        # Illegal activities
        r"how\s+to\s+(hack|crack|break\s+into|steal)",
        r"bypass\s+security",
        r"exploit\s+(vulnerability|system)",
        r"illegal\s+ways",
        
        # Malicious code
        r"(create|generate|write)\s+(malware|virus|ransomware)",
        r"exploit\s+code",
        r"phishing\s+(email|template)",
        r"backdoor\s+code",
        
        # Self-harm
        r"how\s+to\s+(commit\s+suicide|kill\s+myself|end\s+my\s+life)",
        r"suicide\s+methods",
        r"painless\s+death",
    ]
    
    message_lower = user_message.lower()
    
    for pattern in harmful_patterns:
        if re.search(pattern, message_lower):
            print(f"⚠️  Harmful intent pattern detected: {pattern}")
            return True
    
    return False


# ============================================
# Harmful Content Detection (Output)
# ============================================
@action(is_system_action=True)
async def is_harmful_content(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Check if bot response contains harmful content
    Returns True if harmful content detected, False otherwise
    """
    if not context:
        return False
    
    bot_message = context.get("bot_message", "")
    if not bot_message:
        # Also check last_bot_message for compatibility
        bot_message = context.get("last_bot_message", "")
    
    if not bot_message:
        return False
    
    # Harmful content keywords
    harmful_keywords = [
        "violence", "violent", "attack", "hurt", "harm", "kill", "murder",
        "suicide", "self-harm", "cutting",
        "illegal", "crime", "criminal",
        "hack", "exploit", "malware", "virus",
        "drug", "cocaine", "heroin", "meth",
        "weapon", "bomb", "explosive",
        "discriminate", "racist", "sexist"
    ]
    
    message_lower = bot_message.lower()
    
    # Check for harmful keywords in instruction context
    for keyword in harmful_keywords:
        if keyword in message_lower:
            # Context-aware check - look for instructional phrases
            instruction_patterns = [
                f"how to {keyword}",
                f"ways to {keyword}",
                f"steps to {keyword}",
                f"to {keyword} someone",
                f"{keyword} by",
            ]
            for pattern in instruction_patterns:
                if pattern in message_lower:
                    print(f"⚠️  Harmful content detected: {keyword} in instruction context")
                    return True
    
    return False


# ============================================
# Sensitive Data Detection (Output)
# ============================================
@action(is_system_action=True)
async def contains_sensitive_data(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Check if bot response accidentally leaked sensitive data
    Returns True if sensitive data detected, False otherwise
    """
    if not context:
        return False
    
    bot_message = context.get("bot_message", "")
    if not bot_message:
        bot_message = context.get("last_bot_message", "")
    
    if not bot_message:
        return False
    
    # Check for data leak patterns
    patterns = {
        "api_key": r'(api[_-]?key|apikey)[\s:=]+[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?',
        "password": r'(password|passwd|pwd)[\s:=]+[\'"]?[^\s\'"]{8,}[\'"]?',
        "token": r'(token|access[_-]token)[\s:=]+[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?',
        "private_key": r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
    }
    
    for data_type, pattern in patterns.items():
        if re.search(pattern, bot_message, re.IGNORECASE):
            print(f"⚠️  Sensitive data leak detected: {data_type}")
            return True
    
    return False


# ============================================
# Policy Violation Detection
# ============================================
@action(is_system_action=True)
async def violates_policy(context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Check if response violates general policies
    Returns True if policy violation detected, False otherwise
    """
    if not context:
        return False
    
    bot_message = context.get("bot_message", "")
    if not bot_message:
        bot_message = context.get("last_bot_message", "")
    
    if not bot_message:
        return False
    
    # Policy violation patterns
    violations = [
        r"I can help you (hack|steal|break into)",
        r"Here's how to (hurt|harm|attack)",
        r"To bypass security",
        r"Step \d+: (hack|exploit|steal)",
    ]
    
    message_lower = bot_message.lower()
    
    for pattern in violations:
        if re.search(pattern, message_lower):
            print(f"⚠️  Policy violation detected: {pattern}")
            return True
    
    return False


# ============================================
# Custom Logging Action
# ============================================
@action()
async def log_guardrail_event(
    event_type: str,
    message: str,
    context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log guardrail events for monitoring and analysis
    """
    print(f"\n{'='*60}")
    print(f"GUARDRAIL EVENT: {event_type}")
    print(f"Message: {message}")
    if context:
        print(f"Context: {context}")
    print(f"{'='*60}\n")