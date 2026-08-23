# ============================================================
# VULNTRIAGE AI
# Personalized Vulnerability Triage Backend
# ============================================================

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from dotenv import load_dotenv

import os
import json
import threading


# ============================================================
# 1. LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

FEATHERLESS_API_KEY = os.getenv(
    "FEATHERLESS_API_KEY"
)


# ============================================================
# 2. CREATE FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="VulnTriage AI",
    description="Personalized Vulnerability Triage API",
    version="1.0.0"
)


# ============================================================
# 3. CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# 4. FEATHERLESS CLIENT
# ============================================================

client = None

if FEATHERLESS_API_KEY:

    client = OpenAI(
        base_url="https://api.featherless.ai/v1",
        api_key=FEATHERLESS_API_KEY,
        timeout=60.0,
        max_retries=0
    )


# ============================================================
# 5. AI LOCK
# ============================================================

ai_lock = threading.Lock()


# ============================================================
# 6. HOME
# ============================================================

@app.get("/")
def home():

    return {
        "status": "ok",
        "message": "VulnTriage AI is running!"
    }


# ============================================================
# 7. SAFE FLOAT
# ============================================================

def safe_float(value, default=0.0):

    try:

        if value is None or value == "":
            return default

        return float(value)

    except (TypeError, ValueError):

        return default


# ============================================================
# 8. SAFE INTEGER
# ============================================================

def safe_int(value, default=1):

    try:

        if value is None or value == "":
            return default

        return int(float(value))

    except (TypeError, ValueError):

        return default


# ============================================================
# 9. KEV CHECK
# ============================================================

def is_kev(value):

    if value is None:
        return False

    return str(value).strip().lower() in {
        "yes",
        "true",
        "1"
    }


# ============================================================
# 10. EXPOSURE SCORE
# ============================================================

def get_exposure_score(exposure):

    value = str(
        exposure or "Internal"
    ).strip().lower()


    if value == "internet":
        return 1.0


    if value == "external":
        return 0.8


    if value == "internal":
        return 0.4


    return 0.2


# ============================================================
# 11. SEVERITY
# ============================================================

def get_severity(cvss):

    cvss = safe_float(cvss)


    if cvss >= 9.0:
        return "Critical"


    if cvss >= 7.0:
        return "High"


    if cvss >= 4.0:
        return "Medium"


    return "Low"


# ============================================================
# 12. PRIORITY LEVEL
# ============================================================

def get_priority_level(score):

    score = safe_float(score)


    if score >= 8.0:
        return "P1 - Immediate"


    if score >= 6.0:
        return "P2 - Urgent"


    if score >= 4.0:
        return "P3 - Planned"


    return "P4 - Monitor"


# ============================================================
# 13. PRIORITY SCORING
# ============================================================

def calculate_priority(vulnerability):

    cvss = safe_float(
        vulnerability.get("cvss"),
        0.0
    )


    epss = safe_float(
        vulnerability.get("epss"),
        0.0
    )

    epss = max(
        0.0,
        min(epss, 1.0)
    )


    kev = is_kev(
        vulnerability.get("kev")
    )


    exposure = str(
        vulnerability.get(
            "exposure",
            "Internal"
        )
    ).strip()


    service_importance = safe_int(
        vulnerability.get(
            "service_importance"
        ),
        1
    )

    service_importance = max(
        1,
        min(service_importance, 5)
    )


    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    cvss_normalized = cvss / 10.0

    epss_normalized = epss

    kev_normalized = (
        1.0 if kev else 0.0
    )

    exposure_normalized = (
        get_exposure_score(exposure)
    )

    importance_normalized = (
        service_importance / 5.0
    )


    # --------------------------------------------------------
    # WEIGHTS
    #
    # CVSS                30%
    # EPSS                25%
    # KEV                 20%
    # Exposure            15%
    # Service Importance  10%
    # --------------------------------------------------------

    cvss_contribution = (
        cvss_normalized * 0.30
    )

    epss_contribution = (
        epss_normalized * 0.25
    )

    kev_contribution = (
        kev_normalized * 0.20
    )

    exposure_contribution = (
        exposure_normalized * 0.15
    )

    importance_contribution = (
        importance_normalized * 0.10
    )


    total = (
        cvss_contribution
        + epss_contribution
        + kev_contribution
        + exposure_contribution
        + importance_contribution
    )


    final_score = round(
        total * 10.0,
        2
    )


    # --------------------------------------------------------
    # SCORE REASONS
    # --------------------------------------------------------

    reasons = []


    if cvss >= 9.0:

        reasons.append(
            f"Very high CVSS ({cvss:.1f})"
        )

    elif cvss >= 7.0:

        reasons.append(
            f"High CVSS ({cvss:.1f})"
        )


    if epss >= 0.70:

        reasons.append(
            f"High EPSS ({epss:.2f})"
        )


    if kev:

        reasons.append(
            "Listed in CISA KEV"
        )


    if exposure.lower() == "internet":

        reasons.append(
            "Internet exposed"
        )

    elif exposure.lower() == "external":

        reasons.append(
            "Externally exposed"
        )


    if service_importance >= 4:

        reasons.append(
            f"High service importance "
            f"({service_importance}/5)"
        )


    if not reasons:

        reasons.append(
            "Moderate security risk signals"
        )


    return {

        "score": final_score,

        "severity":
            get_severity(cvss),

        "priority":
            get_priority_level(final_score),

        "breakdown": {

            "cvss":
                round(
                    cvss_contribution * 10,
                    2
                ),

            "epss":
                round(
                    epss_contribution * 10,
                    2
                ),

            "kev":
                round(
                    kev_contribution * 10,
                    2
                ),

            "exposure":
                round(
                    exposure_contribution * 10,
                    2
                ),

            "service_importance":
                round(
                    importance_contribution * 10,
                    2
                )
        },

        "reasons":
            reasons
    }


# ============================================================
# 14. WHY THIS VULNERABILITY RANKED HIGH
# ============================================================

def build_vulnerability_explanation(
    vulnerability
):

    cvss = safe_float(
        vulnerability.get("cvss"),
        0.0
    )


    epss = safe_float(
        vulnerability.get("epss"),
        0.0
    )


    kev = is_kev(
        vulnerability.get("kev")
    )


    exposure = str(
        vulnerability.get(
            "exposure",
            "Internal"
        )
    ).strip()


    asset = str(
        vulnerability.get(
            "asset",
            "the affected asset"
        )
    ).strip()


    technology = str(
        vulnerability.get(
            "technology",
            "the affected technology"
        )
    ).strip()


    version = str(
        vulnerability.get(
            "version",
            ""
        )
    ).strip()


    importance = safe_int(
        vulnerability.get(
            "service_importance"
        ),
        1
    )


    # --------------------------------------------------------
    # WHY RANKED HIGH
    # --------------------------------------------------------

    reasons = []


    if cvss >= 9.0:

        reasons.append(
            f"Very high CVSS ({cvss:.1f})"
        )

    elif cvss >= 7.0:

        reasons.append(
            f"High CVSS ({cvss:.1f})"
        )


    if epss >= 0.70:

        reasons.append(
            f"High EPSS ({epss:.2f})"
        )


    if kev:

        reasons.append(
            "Listed in CISA KEV"
        )


    if exposure.lower() == "internet":

        reasons.append(
            "Internet exposed"
        )

    elif exposure.lower() == "external":

        reasons.append(
            "Externally exposed"
        )


    if importance >= 4:

        reasons.append(
            f"High service importance "
            f"({importance}/5)"
        )


    if not reasons:

        reasons.append(
            "Several moderate security signals"
        )


    why_ranked = (
        "This vulnerability ranked highly because "
        + ", ".join(reasons)
        + "."
    )


    # --------------------------------------------------------
    # WHY IT MATTERS
    # --------------------------------------------------------

    if version:

        technology_text = (
            f"{technology} {version}"
        )

    else:

        technology_text = technology


    if exposure.lower() == "internet":

        exposure_text = (
            "the affected service is reachable "
            "from the internet"
        )

    elif exposure.lower() == "external":

        exposure_text = (
            "the affected service has external exposure"
        )

    else:

        exposure_text = (
            "the affected service is internally exposed"
        )


    if importance >= 4:

        importance_text = (
            f"and has high business importance "
            f"({importance}/5)"
        )

    else:

        importance_text = (
            f"with service importance "
            f"{importance}/5"
        )


    if kev:

        exploitation_text = (
            "It is also listed in CISA KEV."
        )

    elif epss >= 0.70:

        exploitation_text = (
            f"Its EPSS value of {epss:.2f} "
            "indicates a high exploitation signal."
        )

    else:

        exploitation_text = (
            "Its current exploitation signal is lower."
        )


    why_matters = (
        f"This vulnerability affects {asset} "
        f"running {technology_text}. "
        f"{exposure_text} "
        f"{importance_text}. "
        f"{exploitation_text}"
    )


    # --------------------------------------------------------
    # SAFE NEXT ACTION
    # --------------------------------------------------------

    safe_next_action = (
        "Verify the affected version, apply the "
        "vendor-supported security update or "
        "recommended mitigation, and confirm that "
        "the vulnerable version is no longer "
        "in production."
    )


    return {

        "why_ranked":
            why_ranked,

        "why_matters":
            why_matters,

        "safe_next_action":
            safe_next_action
    }


# ============================================================
# 15. RANK VULNERABILITIES
# ============================================================

@app.post("/api/rank")
def rank_vulnerabilities(data: dict):

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )


    if not isinstance(
        vulnerabilities,
        list
    ):

        return {
            "error":
            "Vulnerabilities must be a list."
        }


    if len(vulnerabilities) == 0:

        return {
            "error":
            "No vulnerability records were provided."
        }


    ranked = []


    # --------------------------------------------------------
    # PROCESS EACH VULNERABILITY
    # --------------------------------------------------------

    for original in vulnerabilities:

        if not isinstance(
            original,
            dict
        ):

            continue


        vulnerability = dict(
            original
        )


        # Score
        scoring = calculate_priority(
            vulnerability
        )


        vulnerability[
            "priority_score"
        ] = scoring["score"]


        vulnerability[
            "severity"
        ] = scoring["severity"]


        vulnerability[
            "priority"
        ] = scoring["priority"]


        vulnerability[
            "score_breakdown"
        ] = scoring["breakdown"]


        vulnerability[
            "priority_reasons"
        ] = scoring["reasons"]


        # Individual explanation
        explanation = (
            build_vulnerability_explanation(
                vulnerability
            )
        )


        vulnerability[
            "why_ranked"
        ] = explanation[
            "why_ranked"
        ]


        vulnerability[
            "why_matters"
        ] = explanation[
            "why_matters"
        ]


        vulnerability[
            "safe_next_action"
        ] = explanation[
            "safe_next_action"
        ]


        ranked.append(
            vulnerability
        )


    # --------------------------------------------------------
    # SORT
    # --------------------------------------------------------

    ranked.sort(
        key=lambda item:
            item.get(
                "priority_score",
                0
            ),
        reverse=True
    )


    # --------------------------------------------------------
    # TOP 5
    # --------------------------------------------------------

    top5 = ranked[:5]


    return {

        "total_vulnerabilities":
            len(vulnerabilities),

        "ranked_count":
            len(ranked),

        "top5":
            top5
    }


# ============================================================
# 16. AI PROMPT
# ============================================================

def create_ai_prompt(
    organization,
    top5
):

    return f"""
You are VulnTriage AI, a defensive cybersecurity
vulnerability triage assistant.

Organisation profile:

{json.dumps(
    organization,
    indent=2
)}

Top 5 vulnerabilities:

{json.dumps(
    top5,
    indent=2
)}

IMPORTANT:
Do NOT give one overall summary.

Give a separate explanation for EVERY vulnerability.

For EACH vulnerability use exactly this format:

PRIORITY: <rank number>
ID: <vulnerability id>
TITLE: <vulnerability title>

WHY IT MATTERS:
<2 or 3 concise sentences explaining why this
specific vulnerability matters to this organisation>

SOLUTION:
<2 or 3 concise sentences describing the safest
defensive remediation or next action>

RULES:
- Provide one section for each of the 5 priorities.
- Do not combine vulnerabilities.
- Do not give a general summary instead of individual sections.
- Use the organisation's technology, version, exposure,
  service importance, CVSS, KEV and EPSS where relevant.
- Only provide defensive remediation guidance.
- Do not provide exploit code, attack payloads,
  or unauthorized access instructions.

Keep each vulnerability section concise.
"""


# ============================================================
# 17. FEATHERLESS AI
# ============================================================

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

    if not isinstance(
        top5,
        list
    ) or len(top5) == 0:

        return {
            "error":
            "No Top 5 vulnerabilities were provided."
        }


    if client is None:

        return {
            "error":
            "Featherless AI is not configured."
        }


    acquired = ai_lock.acquire(
        blocking=False
    )


    if not acquired:

        return {
            "error":
            "Featherless AI is currently busy. "
            "Please try again shortly."
        }


    try:

        prompt = create_ai_prompt(
            organization,
            top5
        )


        response = (
            client
            .chat
            .completions
            .create(

                model="Qwen/Qwen3.5-9B",

                messages=[

                    {
                        "role": "system",
                        "content":
                        (
                            "You are a defensive "
                            "cybersecurity triage "
                            "assistant. "
                            "Return separate "
                            "explanations for each "
                            "priority."
                        )
                    },

                    {
                        "role": "user",
                        "content": prompt
                    }
                ],

                max_tokens=700,

                temperature=0.2,

                extra_body={
                    "chat_template_kwargs": {
                        "enable_thinking": False
                    }
                }
            )
        )


        content = (
            response
            .choices[0]
            .message
            .content
        )


        if not content:

            return {
                "error":
                "Featherless returned an empty response."
            }


        content = str(
            content
        ).strip()


        if not content:

            return {
                "error":
                "Featherless returned an empty response."
            }


        return {
            "ai_analysis": content
        }


    except Exception as exc:

        error_text = str(
            exc
        ).lower()


        if (
            "429" in error_text
            or "concurrency" in error_text
        ):

            return {
                "error":
                "Featherless AI is temporarily busy. "
                "Your Top 5 priorities are still available."
            }


        return {
            "error":
            "Featherless AI could not provide "
            "the individual explanations."
        }


    finally:

        ai_lock.release()


    # --------------------------------------------------------
    # API KEY CHECK
    # --------------------------------------------------------

    if client is None:

        return {

            "ai_analysis":
            (
                "Featherless AI is not configured. "
                "The individual Top 5 explanations "
                "above are still available."
            )
        }


    # --------------------------------------------------------
    # PREVENT SIMULTANEOUS REQUESTS
    # --------------------------------------------------------

    acquired = ai_lock.acquire(
        blocking=False
    )


    if not acquired:

        return {

            "ai_analysis":
            (
                "Featherless AI is currently busy. "
                "The individual Top 5 explanations "
                "above remain available."
            )
        }


    try:

        prompt = create_ai_prompt(
            organization,
            top5
        )


        response = (
            client
            .chat
            .completions
            .create(

                model="Qwen/Qwen3.5-9B",

                messages=[

                    {
                        "role": "system",

                        "content":
                        (
                            "You are a defensive "
                            "cybersecurity triage "
                            "assistant. Be concise."
                        )
                    },

                    {
                        "role": "user",

                        "content":
                            prompt
                    }
                ],

                max_tokens=400,

                temperature=0.2,

                # Send this as extra provider data
                # so OpenAI SDK does not reject it.
                extra_body={
                    "chat_template_kwargs": {
                        "enable_thinking": False
                    }
                }
            )
        )


        # ----------------------------------------------------
        # READ AI CONTENT
        # ----------------------------------------------------

        content = (
            response
            .choices[0]
            .message
            .content
        )


        # ----------------------------------------------------
        # EMPTY RESPONSE
        # ----------------------------------------------------

        if not content:

            return {

                "ai_analysis":
                (
                    "Featherless AI returned an "
                    "empty response. The individual "
                    "Top 5 explanations above remain "
                    "available."
                )
            }


        content = str(
            content
        ).strip()


        if not content:

            return {

                "ai_analysis":
                (
                    "Featherless AI returned an "
                    "empty response. The individual "
                    "Top 5 explanations above remain "
                    "available."
                )
            }


        return {

            "ai_analysis":
                content
        }


    except Exception as exc:

        error_text = str(
            exc
        ).lower()


        # ----------------------------------------------------
        # 429 / CONCURRENCY
        # ----------------------------------------------------

        if (
            "429" in error_text
            or "concurrency" in error_text
        ):

            return {

                "ai_analysis":
                (
                    "Featherless AI is temporarily "
                    "busy. The individual Top 5 "
                    "explanations and safe next "
                    "actions above remain available."
                )
            }


        # ----------------------------------------------------
        # OTHER AI ERROR
        # ----------------------------------------------------

        return {

            "ai_analysis":
            (
                "Featherless AI could not provide "
                "the optional summary. The individual "
                "Top 5 explanations above remain valid."
            )
        }


    finally:

        ai_lock.release()


# ============================================================
# END
# ============================================================
#
# Run:
#
# python -m uvicorn main:app --reload
#
# ============================================================