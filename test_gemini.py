# test_gemini.py — full file, standalone diagnostic

import os
from dotenv import load_dotenv
load_dotenv()
from google import genai

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")

client = genai.Client()
try:
    r = client.models.generate_content(model=MODEL, contents="say ok")
    print("SUCCESS:", r.text)
except Exception as e:
    print("REAL ERROR:", repr(e))