import os
from dotenv import load_dotenv
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from google import genai

# Load environment variables from .env file
load_dotenv()

# --- CUSTOM RECOGNIZERS SETUP ---

# Custom recognizer for Israeli mobile phone numbers
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

# Deny-list recognizer for internal company secrets
company_secret_recognizer = PatternRecognizer(
    supported_entity="COMPANY_SECRET",
    deny_list=["Teva", "Duda", "Apple", "Google", "Base44"],
    supported_language="en",
)

# --- INITIALIZATION ---

print("Loading AI safety models...")
analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(israeli_mobile_recognizer)
analyzer.registry.add_recognizer(company_secret_recognizer)
anonymizer = AnonymizerEngine()

# --- MAIN EXECUTION ---

# Input text containing sensitive information
secret_text = "My name is Boaz, I work at Teva, and my phone number is 050-1234567."

# Analyze text for both built-in and custom entities
results = analyzer.analyze(
    text=secret_text, 
    entities=["PERSON", "ORGANIZATION", "PHONE_NUMBER", "IL_PHONE_NUMBER", "COMPANY_SECRET"], 
    language='en'
)

# Redact/Anonymize the detected sensitive information
anonymized_result = anonymizer.anonymize(text=secret_text, analyzer_results=results)

print("\n--- REDACTION RESULTS ---")
print("Original:", secret_text)
print("Safe for Cloud:", anonymized_result.text)

# --- AI INTEGRATION ---

try:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY is missing in your .env file.")

    # Initialize the Google GenAI Client
    client = genai.Client(api_key=api_key)

    # Sending the anonymized text to the newest Gemini 2.5 model
    # We use 2.5-flash as it's the most stable/available in your latest list
    response = client.models.generate_content(
        model="gemini-2.5-flash", 
        contents=anonymized_result.text,
        config={
            "system_instruction": "You are a helpful assistant. The user might provide redacted text with tags like <PERSON> or <COMPANY_SECRET>. Please respond naturally while respecting these placeholders."
        }
    )

    print("\n--- AI RESPONSE (Based on Clean Data) ---")
    print(response.text)

except Exception as e:
    print(f"\n[Gemini API Error] {e}")