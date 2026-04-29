# AI Safety Shield 🛡️
### A Secure PII Sanitization Pipeline for LLM Integration

AI Safety Shield is a local proxy service designed to intercept sensitive data (PII) before it leaves the organization's network. It redacts identified entities and forwards a sanitized payload to cloud-based AI models (Gemini 2.5 Flash), ensuring data privacy while maintaining AI utility.

## 🚀 Key Features
- **Local PII Redaction:** Uses Microsoft Presidio for robust, on-premise entity recognition.
- **Israeli ID Validation:** Custom implementation of the **Luhn Algorithm** for high-confidence Israeli ID detection.
- **Enterprise Deny-Lists:** Built-in recognizers for custom corporate secrets and identifiers.
- **Performance Monitoring:** Real-time tracking of Local vs. Cloud latency.
- **Audit Reporting:** Generates detailed sanitization logs with JSON export capability.

## 🛠️ Tech Stack
- **Language:** Python
- **Privacy Engines:** Microsoft Presidio (Analyzer & Anonymizer)
- **AI Integration:** Google GenAI SDK (Gemini 2.5 Flash)
- **Framework:** Streamlit (Data Dashboard)
- **Data Handling:** Pandas

## 🏗️ Architecture
1. **Ingestion Layer:** Accepts raw text or .txt file uploads.
2. **Analysis Layer:** Scans text for PERSON, ORGANIZATION, IL_ID, PHONE, etc.
3. **Redaction Layer:** Replaces sensitive entities with secure tags (e.g., `<PERSON>`).
4. **Inference Layer:** Forwards sanitized text to Gemini API for secure response.

## 🔧 Installation
1. Clone the repository.
2. Install dependencies: `pip install streamlit presidio-analyzer presidio-anonymizer google-genai python-dotenv pandas`.
3. Configure your `.env` file with `GEMINI_API_KEY`.
4. Run the app: `python -m streamlit run shield.py`.
