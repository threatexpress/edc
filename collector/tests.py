from django.test import TestCase
from .utils import strip_non_printable

class UtilsTestCase(TestCase):
    def test_strip_non_printable_and_control_chars(self):
        # Test case 1: String with various control characters (except \t, \n, \r)
        # Includes \x00 (null), \x01 (start of heading), \x1F (unit separator), \x7F (delete)
        test_string_1 = "Hello\x00World\x01Test\x1FString\x7F123"
        expected_1 = "HelloWorldTestString123"
        self.assertEqual(strip_non_printable(test_string_1), expected_1)

        # Test case 2: String with allowed whitespace (\t, \n, \r)
        test_string_2 = "Hello\tWorld\nTest\rString 123"
        expected_2 = "Hello\tWorld\nTest\rString 123" # These should be preserved
        self.assertEqual(strip_non_printable(test_string_2), expected_2)

        # Test case 3: String with mixed printable, control chars, and allowed whitespace
        test_string_3 = "Line1\n\x02Line2\t\x0BSome\x0Ctext\r\x1EEnd"
        expected_3 = "Line1\nLine2\tSometext\rEnd"
        self.assertEqual(strip_non_printable(test_string_3), expected_3)

        # Test case 4: String with only printable characters
        test_string_4 = "This is a clean string."
        expected_4 = "This is a clean string."
        self.assertEqual(strip_non_printable(test_string_4), expected_4)

        # Test case 5: Empty string
        test_string_5 = ""
        expected_5 = ""
        self.assertEqual(strip_non_printable(test_string_5), expected_5)

        # Test case 6: String with characters outside typical printable ASCII but not control chars
        # For example, characters like accented letters or symbols if they were to be stripped.
        # The current regex [^\x20-\x7E\n\r\t] would strip these.
        test_string_6 = "Héllo Wörld ± § ©" # Unicode characters
        expected_6 = "Hllo Wrld   " # Based on current regex, these are stripped. é,ö,±,§,© removed. Spaces preserved.
        self.assertEqual(strip_non_printable(test_string_6), expected_6)

        # Test case 7: String that is not a string (e.g., integer)
        test_string_7 = 12345
        expected_7 = 12345 # Should return the value as is
        self.assertEqual(strip_non_printable(test_string_7), expected_7)

        # Test case 8: String with only control characters (excluding \t, \n, \r)
        test_string_8 = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F"
        expected_8 = ""
        self.assertEqual(strip_non_printable(test_string_8), expected_8)

    def test_model_cleaning_integration(self):
        # This is a more complex test and would require setting up model instances.
        # For now, focusing on the utility function itself.
        # If models have specific fields that need testing with control characters,
        # those tests would go here or in model-specific test cases.
        pass
