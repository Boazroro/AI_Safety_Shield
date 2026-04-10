from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine

# Custom recognizer for Israeli mobile phone numbers.
# Matches formats: 05X-XXXXXXX or 05XXXXXXXXX (e.g. 050-1234567, 0521234567)
israeli_mobile_pattern = Pattern(
    name="israeli_mobile_pattern",
    regex=r"\b05[0-9]-?\d{7}\b",
    score=0.85,
)
israeli_mobile_recognizer = PatternRecognizer(
    supported_entity="IL_PHONE_NUMBER",
    patterns=[israeli_mobile_pattern],
    supported_language="en",
)

# Deny-list recognizer for internal company secrets.
# Any exact match against the list is classified as COMPANY_SECRET.
company_secret_recognizer = PatternRecognizer(
    supported_entity="COMPANY_SECRET",
    deny_list=["Teva", "Duda", "Apple", "Google"],
    supported_language="en",
)

print("Loading AI models...")
analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(israeli_mobile_recognizer)
analyzer.registry.add_recognizer(company_secret_recognizer)
anonymizer = AnonymizerEngine()

# Sensetive text
secret_text = "My name is Boaz, I work at Teva, and my phone number is 050-1234567."

# Idetifires of words
results = analyzer.analyze(text=secret_text, entities=["PERSON", "ORGANIZATION", "PHONE_NUMBER", "IL_PHONE_NUMBER", "COMPANY_SECRET"], language='en')

# Information censorship
anonymized_result = anonymizer.anonymize(text=secret_text, analyzer_results=results)

print("\n--- RESULTS ---")
print("Original:", secret_text)
print("Safe for Cloud:", anonymized_result.text)