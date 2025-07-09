import re

CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

def strip_illegal_json_control_chars(s):
    """
    Strips illegal control characters from a string before JSON serialization.
    Keeps legitimate whitespace like newlines and tabs.
    """
    if isinstance(s, str):
        return CONTROL_CHAR_REGEX.sub('', s)
    return s

def strip_non_printable(value: str) -> str:
    """
    Removes non-printable characters from a string, allowing common printable
    characters including letters, numbers, punctuation, space, tab, and newline.
    """
    if not isinstance(value, str):
        return value
    # Keep common printable ASCII characters, tab, newline, carriage return.
    # This regex matches characters that are NOT in the allowed set.
    # Allowed:
    #   \x20-\x7E : Standard printable ASCII (space to ~)
    #   \n       : Newline
    #   \r       : Carriage return
    #   \t       : Tab
    #   Unicode letters, numbers, punctuation, and symbols if needed,
    #   but for this context, sticking to ASCII-like printables might be safer
    #   to avoid issues with specific database collations or display environments.
    #   The current regex focuses on removing ASCII control characters other than tab/newline/cr.
    return re.sub(r'[^\x20-\x7E\n\r\t]', '', value)

def sanitize_string(value):
    """Applies all sanitization rules to a string."""
    if not isinstance(value, str):
        return value
    value = strip_non_printable(value)
    value = strip_illegal_json_control_chars(value)
    return value