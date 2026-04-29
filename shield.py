import os
import re
import streamlit as st
from dotenv import load_dotenv
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, EntityRecognizer, RecognizerResult
from presidio_analyzer.recognizer_registry import RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from google import genai

# --- UI & PAGE CONFIGURATION ---
st.set_page_config(page_title="AI Safety Shield", page_icon="🛡️", layout="centered")

load_dotenv()

# --- CUSTOM PII RECOGNIZERS ---

# Recognizer for Israeli mobile formats (e.g., 05x-xxxxxxx or 05xxxxxxxx)
israeli_mobile_pattern = Pattern(
    name="israeli_mobile_pattern", 
    regex=r"\b05[0-9]-?\d{7}\b", 
    score=0.85
)
israeli_mobile_recognizer = PatternRecognizer(
    supported_entity="IL_PHONE_NUMBER", 
    patterns=[israeli_mobile_pattern], 
    supported_language="en"
)

# Deny-list recognizer for internal corporate identifiers/secrets
company_secret_recognizer = PatternRecognizer(
    supported_entity="COMPANY_SECRET", 
    deny_list=["Teva", "Duda", "Apple", "Google", "Base44"], 
    supported_language="en"
)

# Advanced Israeli ID Recognizer using the Luhn Checksum algorithm
class IsraeliIdRecognizer(EntityRecognizer):
    CANDIDATE_PATTERN = re.compile(r"\b\d{8,9}\b")
    SUPPORTED_ENTITY = "ISRAELI_ID"

    def __init__(self):
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY], 
            supported_language="en", 
            name="IsraeliIdRecognizer"
        )

    def load(self):
        pass 

    @staticmethod
    def _luhn_check(id_str: str) -> bool:
        """
        Validates Israeli ID numbers using a Luhn-variant checksum.
        Pads to 9 digits, alternates multipliers, and verifies divisibility by 10.
        """
        id_str = id_str.zfill(9)
        total = 0
        for i, ch in enumerate(id_str):
            n = int(ch)
            if i % 2 == 1: 
                n *= 2
                if n > 9: n -= 9
            total += n
        return total % 10 == 0

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        for match in self.CANDIDATE_PATTERN.finditer(text):
            if self._luhn_check(match.group()):
                results.append(
                    RecognizerResult(
                        entity_type=self.SUPPORTED_ENTITY, 
                        start=match.start(), 
                        end=match.end(), 
                        score=0.95
                    )
                )
        return results

# --- RESOURCE INITIALIZATION ---

@st.cache_resource
def init_privacy_engines():
    """
    Initializes and caches the Presidio engines to optimize performance.
    Registers custom patterns and the checksum-based ID recognizer.
    """
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()
    registry.add_recognizer(israeli_mobile_recognizer)
    registry.add_recognizer(company_secret_recognizer)
    registry.add_recognizer(IsraeliIdRecognizer())
    
    return AnalyzerEngine(registry=registry), AnonymizerEngine()

analyzer, anonymizer = init_privacy_engines()

# --- MAIN STREAMLIT INTERFACE ---

st.title("🛡️ AI Safety Shield")
st.markdown("### Enterprise-Grade Data Sanitization Proxy")
st.write("Redact PII and sensitive organizational data locally before cloud ingestion.")

# User interaction zone
user_input = st.text_area("Input Prompt:", 
                          placeholder="Enter text (e.g., My name is Boaz, ID 123456782, contact 050-1234567)...",
                          height=150)

if st.button("Protect & Process"):
    if user_input.strip():
        # Step 1: Local PII Analysis and Redaction
        with st.status("🔒 Scanning and redacting sensitive data...", expanded=True) as status:
            analysis_hits = analyzer.analyze(
                text=user_input, 
                entities=["PERSON", "ORGANIZATION", "PHONE_NUMBER", "IL_PHONE_NUMBER", "COMPANY_SECRET", "ISRAELI_ID"],
                language='en'
            )
            
            redacted_result = anonymizer.anonymize(
                text=user_input, 
                analyzer_results=analysis_hits
            )
            
            st.write("**Redacted Payload (Safe for Cloud):**")
            st.code(redacted_result.text)
            status.update(label="Local Sanitization Complete", state="complete")

        # Step 2: Cloud Inference via Gemini API
        with st.spinner("🤖 Communicating with Gemini 2.5 Flash..."):
            try:
                # Retrieve API key from environment
                api_key = os.getenv("GEMINI_API_KEY")
                if not api_key:
                    st.error("Missing GEMINI_API_KEY. Please check your .env file.")
                else:
                    client = genai.Client(api_key=api_key)
                    response = client.models.generate_content(
                        model="gemini-2.5-flash", 
                        contents=redacted_result.text,
                        config={
                            "system_instruction": "You are a secure AI assistant. Provide helpful responses while maintaining placeholder tags like <PERSON>."
                        }
                    )
                    
                    st.subheader("AI Response")
                    st.success(response.text)
                    
            except Exception as e:
                st.error(f"Upstream API Error: {e}")
    else:
        st.warning("Please enter valid text to process.")