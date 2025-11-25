# AI Summary and recommendation using Google's Gemini

import json
from google import genai
from google.genai import types

from modules.utils.load_configs import DEV_ENV

def summarize_with_ai(session: str) -> dict:
    ai_client = genai.Client(api_key=DEV_ENV["api_keys"]["gemini"])
    with open(f"{DEV_ENV['report_paths']['full_scan']}\\{session}.json", "r") as f:
        report = json.load(f)
        _data = {"union": report["data"]["union"], "intersection": report["data"]["intersection"],"rules": report["data"]["rules"]}
        _tech = {"fingerprinted": report["plugins"]["fingerprinted"], "patchable": report["plugins"]["patchable"]}

        vuln_response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
              system_instruction="You are a cybersecurity specialist"
            ),
            contents=["Can you summarize the findings in this report.", "Can you recommend solutions on how to mitigate these problems", json.dumps(_data)]
        )

        tech_response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                system_instruction="You are a cybersecurity specialist"
            ),
            contents=["Can you summarize the findings in this report.", "Can you recommend solutions on how to mitigate these problems", json.dumps(_tech)]
        )
        return {
            "summary": {
                "vulnerabilities": vuln_response.text,
                "techniques": tech_response.text,
            }
        }