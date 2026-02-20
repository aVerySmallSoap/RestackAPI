# AI Summary and recommendation using Google's Gemini

import json
import os
from google import genai
from google.genai import types
from loguru import logger

from modules.utils.load_configs import DEV_ENV

def summarize_with_ai(session: str) -> dict:
    ai_client = genai.Client(api_key=DEV_ENV["api_keys"]["gemini"])
    report_path = os.path.join(DEV_ENV['report_paths']['full_scan'], f"{session}.json")
    with open(report_path, "r") as f:
        try:
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
                    system_instruction="You are a cybersecurity specialist. Ignore if there are empty technology fields"
                ),
                contents=["Can you summarize the findings in this report.", "If there are problems, can you recommend solutions to mitage them", json.dumps(_tech)]
            )
        except Exception as e:
            logger.error("Something happened!\n{}", e)
            return {}
        return {
            "summary": {
                "vulnerabilities": vuln_response.text,
                "tech": tech_response.text,
            }
        }