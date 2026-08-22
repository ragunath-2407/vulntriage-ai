from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from dotenv import load_dotenv
import os
import json

load_dotenv()

app = FastAPI(title="VulnTriage AI")


# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# Featherless AI
# --------------------------------------------------

client = OpenAI(
    base_url="https://api.featherless.ai/v1",
    api_key=os.getenv("FEATHERLESS_API_KEY")
)


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.get("/")
def home():

    return {
        "message": "VulnTriage AI is running!"
    }


# --------------------------------------------------
# Priority scoring
# --------------------------------------------------

def calculate_priority(vulnerability):

    cvss = float(vulnerability.get("cvss", 0))
    epss = float(vulnerability.get("epss", 0))

    kev = str(
        vulnerability.get("kev", "No")
    ).lower() == "yes"

    exposure = str(
        vulnerability.get("exposure", "Internal")
    ).lower()

    service_importance = float(
        vulnerability.get("service_importance", 1)
    )


    # CVSS contribution
    cvss_score = cvss / 10


    # EPSS is already 0-1
    epss_score = epss


    # KEV significantly increases priority
    kev_score = 1 if kev else 0


    # Internet exposure
    if exposure == "internet":
        exposure_score = 1.0

    elif exposure == "external":
        exposure_score = 0.8

    elif exposure == "internal":
        exposure_score = 0.4

    else:
        exposure_score = 0.2


    # Service importance
    importance_score = service_importance / 5


    # Final priority score
    priority_score = (
        cvss_score * 0.30
        + epss_score * 0.25
        + kev_score * 0.20
        + exposure_score * 0.15
        + importance_score * 0.10
    )


    return round(priority_score * 10, 2)


# --------------------------------------------------
# Severity
# --------------------------------------------------

def get_severity(cvss):

    cvss = float(cvss)

    if cvss >= 9:
        return "Critical"

    elif cvss >= 7:
        return "High"

    elif cvss >= 4:
        return "Medium"

    else:
        return "Low"


# --------------------------------------------------
# Main triage endpoint
# --------------------------------------------------

@app.post("/api/triage")
def triage(data: dict):

    organization = data.get(
        "organization",
        {}
    )

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )


    if not vulnerabilities:

        return {
            "error": "No vulnerability records were provided."
        }


    # ----------------------------------------------
    # Calculate priority for every vulnerability
    # ----------------------------------------------

    ranked = []

    for vulnerability in vulnerabilities:

        score = calculate_priority(
            vulnerability
        )

        vulnerability["priority_score"] = score

        vulnerability["severity"] = get_severity(
            vulnerability.get("cvss", 0)
        )

        ranked.append(vulnerability)


    # ----------------------------------------------
    # Sort highest priority first
    # ----------------------------------------------

    ranked.sort(
        key=lambda x: x["priority_score"],
        reverse=True
    )


    # ----------------------------------------------
    # Select top 5
    # ----------------------------------------------

    top5 = ranked[:5]


    # ----------------------------------------------
    # Prepare AI input
    # ----------------------------------------------

    ai_input = {
        "organization": organization,
        "top_vulnerabilities": top5
    }


    prompt = f"""
You are VulnTriage AI, a cybersecurity vulnerability
prioritization assistant.

Your job is to explain the five highest-priority
vulnerabilities for an organisation.

ORGANISATION:

{json.dumps(organization, indent=2)}

TOP VULNERABILITIES:

{json.dumps(top5, indent=2)}


For each vulnerability provide:

1. Vulnerability name
2. Priority
3. Severity
4. Why it matters to THIS organisation
5. Important factors
6. Safe next action
7. Recommended remediation direction


Consider:

- Technology
- Technology version
- Internet/external exposure
- Service importance
- CVSS
- KEV status
- EPSS probability
- Calculated priority score


Use the following priority levels:

P1 - Immediate
P2 - Urgent
P3 - Planned
P4 - Monitor


IMPORTANT SAFETY RULE:

Only recommend defensive and remediation actions.

Do not provide exploit code,
attack instructions,
payloads,
or instructions for compromising systems.


Return a concise security-management-friendly answer.
"""


    # ----------------------------------------------
    # Ask Featherless AI
    # ----------------------------------------------

    try:

        response = client.chat.completions.create(

            model="deepseek-ai/DeepSeek-V4-Flash-0731",

            messages=[

                {
                    "role": "system",
                    "content":
                    "You are a defensive cybersecurity "
                    "vulnerability triage expert."
                },

                {
                    "role": "user",
                    "content": prompt
                }

            ]
        )


        ai_result = (
            response
            .choices[0]
            .message
            .content
        )


    except Exception as e:

        ai_result = (
            "AI explanation unavailable. "
            "Priority ranking was still calculated "
            "using the vulnerability attributes."
        )


    # ----------------------------------------------
    # Return result
    # ----------------------------------------------

    return {

        "total_vulnerabilities":
            len(vulnerabilities),

        "top5":
            top5,

        "ai_analysis":
            ai_result
    }