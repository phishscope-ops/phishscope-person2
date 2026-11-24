"""Run: uvicorn main:app --host 0.0.0.0 --port 8000"""
from scanner_p2.api import create_app

app = create_app()
