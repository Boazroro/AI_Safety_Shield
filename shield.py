from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

print("Loading AI models...")
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Sensetive text
secret_text = "My name is Boaz, I work at Teva, and my phone number is 050-1234567."

# Idetifires of words
results = analyzer.analyze(text=secret_text, entities=["PERSON", "ORGANIZATION", "PHONE_NUMBER"], language='en')

# Information censorship
anonymized_result = anonymizer.anonymize(text=secret_text, analyzer_results=results)

print("\n--- RESULTS ---")
print("Original:", secret_text)
print("Safe for Cloud:", anonymized_result.text)