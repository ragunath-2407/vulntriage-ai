from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from dotenv import load_dotenv
import os
import json

load_dotenv()

app = FastAPI(title="VulnTriage AI")


# ==================================================
# CORS
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================
# FEATHERLESS AI
# ==================================================

client = OpenAI(
    base_url="https://api.featherless.ai/v1",
    api_key=os.getenv("FEATHERLESS_API_KEY")
)


# ==================================================
# HOME
# ==================================================

@app.get("/")
def home():

    return {
        "message": "VulnTriage AI is running!"
    }


# ==================================================
# PRIORITY SCORE
# ==================================================

def calculate_priority(vulnerability):

    cvss = float(
        vulnerability.get("cvss", 0)
    )

    epss = float(
        vulnerability.get("epss", 0)
    )

    kev = str(
        vulnerability.get("kev", "No")
    ).lower() == "yes"

    exposure = str(
        vulnerability.get(
            "exposure",
            "Internal"
        )
    ).lower()

    service_importance = float(
        vulnerability.get(
            "service_importance",
            1
        )
    )


    # CVSS
    cvss_score = cvss / 10


    # EPSS
    epss_score = epss


    # KEV
    kev_score = 1 if kev else 0


    # Exposure
    if exposure == "internet":

        exposure_score = 1.0

    elif exposure == "external":

        exposure_score = 0.8

    elif exposure == "internal":

        exposure_score = 0.4

    else:

        exposure_score = 0.2


    # Business importance
    importance_score = (
        service_importance / 5
    )


    # Final score
    priority_score = (

        cvss_score * 0.30

        + epss_score * 0.25

        + kev_score * 0.20

        + exposure_score * 0.15

        + importance_score * 0.10

    )


    return round(
        priority_score * 10,
        2
    )


# ==================================================
# SEVERITY
# ==================================================

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


# ==================================================
# PRIORITY LEVEL
# ==================================================

def get_priority_level(score):

    if score >= 8:

        return "P1 - Immediate"

    elif score >= 6:

        return "P2 - Urgent"

    elif score >= 4:

        return "P3 - Planned"

    else:

        return "P4 - Monitor"


# ==================================================
# STEP 1: RANK VULNERABILITIES
# ==================================================

@app.post("/api/rank")
def rank_vulnerabilities(data: dict):

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )


    if not vulnerabilities:

        return {
            "error":
            "No vulnerability records were provided."
        }


    ranked = []


    # Calculate every vulnerability
    for vulnerability in vulnerabilities:

        score = calculate_priority(
            vulnerability
        )


        vulnerability[
            "priority_score"
        ] = score


        vulnerability[
            "severity"
        ] = get_severity(
            vulnerability.get(
                "cvss",
                0
            )
        )


        vulnerability[
            "priority"
        ] = get_priority_level(
            score
        )


        ranked.append(
            vulnerability
        )


    # Sort highest score first
    ranked.sort(
        key=lambda x:
        x["priority_score"],
        reverse=True
    )


    # Select top 5
    top5 = ranked[:5]


    return {

        "total_vulnerabilities":
            len(vulnerabilities),

        "top5":
            top5

    }


# ==================================================
# STEP 2: FEATHERLESS AI EXPLANATION
# ==================================================

@app.post("/api/explain")
def explain_vulnerabilities(data: dict):

    organization = data.get(
        "organization",
        {}
    )

    top5 = data.get(
        "top5",
        []
    )


    if not top5:

        return {
            "error":
            "No top vulnerabilities were provided."
        }


    # Create AI prompt

    prompt = f"""

You are VulnTriage AI.

You are a defensive cybersecurity
vulnerability triage assistant.

The organization's profile is:

{json.dumps(
    organization,
    indent=2
)}


The five highest-priority vulnerabilities
calculated by our security scoring engine are:

{json.dumps(
    top5,
    indent=2
)}


For EACH vulnerability explain:

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
- Exposure
- Service importance
- CVSS
- KEV
- EPSS
- Calculated priority score


Priority levels:

P1 - Immediate
P2 - Urgent
P3 - Planned
P4 - Monitor


IMPORTANT:

Only provide defensive cybersecurity
recommendations.

Do NOT provide:

- exploit code
- attack payloads
- instructions for compromising systems
- unauthorized access instructions


Focus on safe remediation and risk reduction.

Keep the explanation concise and suitable
for a security team or management dashboard.

"""


    try:

        response = client.chat.completions.create(

            model=
            "deepseek-ai/DeepSeek-V4-Flash-0731",

            messages=[

                {
                    "role": "system",

                    "content":
                    "You are a defensive "
                    "cybersecurity vulnerability "
                    "triage expert."
                },

                {
                    "role": "user",

                    "content":
                    prompt
                }

            ]

        )


        ai_result = (
            response
            .choices[0]
            .message
            .content
        )


        return {

            "ai_analysis":
                ai_result

        }


    except Exception as e:

        return {

            "error":
                "Featherless AI explanation "
                "failed: "
                + str(e)

        }