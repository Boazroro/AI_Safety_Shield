# AI Safety Shield

A local proxy that redacts personal information from text before it's sent to an LLM API.

The idea: you want to use a cloud model like Gemini, but the text you're sending might contain names, phone numbers, or Israeli ID numbers you don't want leaving your network. AI Safety Shield runs the redaction step locally first and only sends the sanitized version to the model, with an audit log of exactly what was caught.

## How it works

1. You paste text (or upload a `.txt` file) into the Streamlit app.
2. A local Presidio analyzer scans it for PERSON, ORGANIZATION, and PHONE_NUMBER entities, plus three custom recognizers: an Israeli mobile number pattern, a deny-list for flagging custom terms (e.g. internal project names), and an Israeli ID validator using a Luhn-variant checksum.
3. Matches are replaced with tags like `<PERSON>`.
4. Only the redacted text is sent to Gemini 2.5 Flash, and the response is shown with the tags still in place.

## Stack
- Python, Streamlit
- Microsoft Presidio (analyzer + anonymizer)
- Google GenAI SDK (Gemini 2.5 Flash)
- Pandas for the audit log

## Running it
```bash
pip install streamlit presidio-analyzer presidio-anonymizer google-genai python-dotenv pandas
# add GEMINI_API_KEY to .env
python -m streamlit run shield.py
```

## Known limitations
- Detection relies on Presidio's default models plus the three custom recognizers above, and isn't tuned for edge cases a production filter would need to handle.
- Single-file app: no persistence between sessions.
