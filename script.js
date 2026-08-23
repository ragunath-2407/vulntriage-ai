// ============================================================
// VULNTRIAGE AI - FRONTEND
// ============================================================

// Local FastAPI backend
// For deployment, replace this with your Render URL.
const API_URL = "http://127.0.0.1:8000";


// ============================================================
// GLOBAL STATE
// ============================================================

let vulnerabilities = [];

let isAnalyzing = false;

let lastOrganization = null;

let lastTop5 = [];


// ============================================================
// CSV FILE UPLOAD
// ============================================================

const csvFileInput =
    document.getElementById("csvFile");

if (csvFileInput) {

    csvFileInput.addEventListener(
        "change",
        function (event) {

            const file =
                event.target.files[0];

            if (!file) {
                return;
            }

            const reader =
                new FileReader();

            reader.onload =
                function (e) {

                    try {

                        const csvText =
                            e.target.result;

                        const records =
                            parseCSV(csvText);

                        if (
                            !records ||
                            records.length === 0
                        ) {

                            vulnerabilities = [];

                            updateRecordCount(
                                "❌ No valid records found in CSV"
                            );

                            return;
                        }

                        vulnerabilities =
                            records;

                        updateRecordCount(
                            `${records.length} vulnerability records loaded`
                        );

                    } catch (error) {

                        console.error(
                            "CSV parsing error:",
                            error
                        );

                        vulnerabilities = [];

                        updateRecordCount(
                            "❌ Unable to read CSV file"
                        );
                    }
                };

            reader.readAsText(file);

        }
    );
}


// ============================================================
// CSV PARSER
// ============================================================

function parseCSV(text) {

    const lines =
        text
            .trim()
            .split(/\r?\n/);

    if (lines.length < 2) {

        throw new Error(
            "CSV file contains no records."
        );
    }


    const headers =
        lines[0]
            .split(",")
            .map(
                header =>
                    header.trim()
            );


    const records = [];


    for (
        let i = 1;
        i < lines.length;
        i++
    ) {

        const line =
            lines[i].trim();

        if (!line) {
            continue;
        }


        const values =
            line
                .split(",")
                .map(
                    value =>
                        value.trim()
                );


        const record = {};


        headers.forEach(
            (header, index) => {

                record[header] =
                    values[index] ?? "";

            }
        );


        // Convert numerical fields

        record.cvss =
            Number(record.cvss || 0);

        record.epss =
            Number(record.epss || 0);

        record.service_importance =
            Number(
                record.service_importance || 1
            );


        records.push(record);

    }


    return records;
}


// ============================================================
// DEMO DATA
// ============================================================

function loadDemoData() {

    vulnerabilities = [

        {
            id: "VULN-001",
            title: "Remote Code Execution",
            technology: "Apache",
            version: "2.4.49",
            asset: "Public Web Server",
            exposure: "Internet",
            service_importance: 5,
            cvss: 9.8,
            kev: "Yes",
            epss: 0.97
        },

        {
            id: "VULN-002",
            title: "Authentication Bypass",
            technology: "Apache",
            version: "2.4.50",
            asset: "Admin Portal",
            exposure: "Internet",
            service_importance: 5,
            cvss: 9.8,
            kev: "Yes",
            epss: 0.91
        },

        {
            id: "VULN-003",
            title: "SQL Injection",
            technology: "FastAPI",
            version: "0.95",
            asset: "Login API",
            exposure: "Internet",
            service_importance: 5,
            cvss: 9.1,
            kev: "No",
            epss: 0.82
        },

        {
            id: "VULN-004",
            title: "Privilege Escalation",
            technology: "Ubuntu",
            version: "22.04",
            asset: "Internal Server",
            exposure: "Internal",
            service_importance: 4,
            cvss: 7.8,
            kev: "No",
            epss: 0.45
        },

        {
            id: "VULN-005",
            title: "Cross Site Scripting",
            technology: "React",
            version: "18",
            asset: "Customer Portal",
            exposure: "Internet",
            service_importance: 3,
            cvss: 6.1,
            kev: "No",
            epss: 0.31
        },

        {
            id: "VULN-006",
            title: "Information Disclosure",
            technology: "Nginx",
            version: "1.18",
            asset: "Internal API",
            exposure: "Internal",
            service_importance: 2,
            cvss: 5.3,
            kev: "No",
            epss: 0.12
        }
    ];


    updateRecordCount(
        "6 demo vulnerability records loaded"
    );
}


// ============================================================
// UPDATE RECORD COUNT
// ============================================================

function updateRecordCount(text) {

    const recordCount =
        document.getElementById(
            "recordCount"
        );


    if (recordCount) {

        recordCount.textContent =
            text;
    }
}


// ============================================================
// MAIN TRIAGE FUNCTION
// ============================================================

async function runTriage() {

    // Prevent duplicate clicks

    if (isAnalyzing) {
        return;
    }


    // Make sure data exists

    if (
        !vulnerabilities ||
        vulnerabilities.length === 0
    ) {

        alert(
            "Please upload a CSV or click Load Demo Vulnerabilities."
        );

        return;
    }


    isAnalyzing = true;


    // --------------------------------------------------------
    // DOM
    // --------------------------------------------------------

    const analyzeButton =
        document.querySelector(
            ".analyze-button"
        );


    const loading =
        document.getElementById(
            "loading"
        );


    const prioritySection =
        document.getElementById(
            "prioritySection"
        );


    const aiSection =
        document.getElementById(
            "aiSection"
        );


    const aiAnalysis =
        document.getElementById(
            "aiAnalysis"
        );


    // --------------------------------------------------------
    // UI LOCK
    // --------------------------------------------------------

    if (analyzeButton) {

        analyzeButton.disabled =
            true;

        analyzeButton.textContent =
            "⏳ Analyzing...";
    }


    if (loading) {

        loading.classList.remove(
            "hidden"
        );
    }


    if (prioritySection) {

        prioritySection.classList.add(
            "hidden"
        );
    }


    if (aiSection) {

        aiSection.classList.add(
            "hidden"
        );
    }


    if (aiAnalysis) {

        aiAnalysis.innerHTML = "";
    }


    // --------------------------------------------------------
    // ORGANISATION DATA
    // --------------------------------------------------------

    const organization = {

        name:
            document
                .getElementById(
                    "organizationName"
                )
                ?.value
                ?.trim()
            || "Demo Organisation",


        technology:
            document
                .getElementById(
                    "organizationTechnology"
                )
                ?.value
                ?.trim()
            || "Unknown",


        version:
            document
                .getElementById(
                    "organizationVersion"
                )
                ?.value
                ?.trim()
            || "Unknown",


        exposure:
            document
                .getElementById(
                    "organizationExposure"
                )
                ?.value
            || "Internet"

    };


    lastOrganization =
        organization;


    try {

        // ====================================================
        // REQUEST 1: RANK
        // ====================================================

        const rankResponse =
            await fetch(
                `${API_URL}/api/rank`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        vulnerabilities:
                            vulnerabilities

                    })
                }
            );


        if (!rankResponse.ok) {

            throw new Error(
                `Ranking failed: HTTP ${rankResponse.status}`
            );
        }


        const rankData =
            await rankResponse.json();


        if (rankData.error) {

            throw new Error(
                rankData.error
            );
        }


        if (
            !rankData.top5 ||
            rankData.top5.length === 0
        ) {

            throw new Error(
                "The backend returned no Top 5 results."
            );
        }


        // Save Top 5

        lastTop5 =
            rankData.top5;


        // ====================================================
        // SHOW TOP 5
        // ====================================================

        displayTop5(
            rankData.top5
        );


        if (prioritySection) {

            prioritySection.classList.remove(
                "hidden"
            );
        }


        if (loading) {

            loading.classList.add(
                "hidden"
            );
        }


        // ====================================================
        // REQUEST 2: FEATHERLESS AI
        // ====================================================

        if (aiSection) {

            aiSection.classList.remove(
                "hidden"
            );
        }


        if (aiAnalysis) {

            aiAnalysis.innerHTML = `
                🤖 Featherless AI is preparing
                the security summary...
            `;
        }


        try {

            const explainResponse =
                await fetch(
                    `${API_URL}/api/explain`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({

                            organization:
                                organization,

                            top5:
                                rankData.top5

                        })
                    }
                );


            const explainData =
                await explainResponse.json();


            // ------------------------------------------------
            // API ERROR
            // ------------------------------------------------

            if (!explainResponse.ok) {

                showFallbackAIMessage(
                    "Featherless AI is temporarily unavailable."
                );

            }

            // ------------------------------------------------
            // BACKEND ERROR
            // ------------------------------------------------

            else if (
                explainData.error
            ) {

                showFallbackAIMessage(
                    explainData.error
                );

            }

            // ------------------------------------------------
            // EMPTY AI RESPONSE
            // ------------------------------------------------

            else if (
                !explainData.ai_analysis ||
                !String(
                    explainData.ai_analysis
                ).trim()
            ) {

                showFallbackAIMessage(
                    "Featherless returned an empty response."
                );

            }

            // ------------------------------------------------
            // SUCCESS
            // ------------------------------------------------

            else {

                displayAIAnalysis(
                    explainData.ai_analysis
                );
            }


        } catch (aiError) {

            console.error(
                "AI request error:",
                aiError
            );


            showFallbackAIMessage(
                "Featherless AI is temporarily unavailable. "
                + "The Top 5 results are still valid."
            );
        }


    } catch (error) {

        console.error(
            "Triage error:",
            error
        );


        if (loading) {

            loading.classList.add(
                "hidden"
            );
        }


        alert(
            `Unable to complete vulnerability ranking.\n\n${error.message}`
        );


    } finally {

        isAnalyzing =
            false;


        if (analyzeButton) {

            analyzeButton.disabled =
                false;

            analyzeButton.textContent =
                "🔍 Analyze & Find Top 5 Priorities";
        }


        if (loading) {

            loading.classList.add(
                "hidden"
            );
        }
    }
}


// ============================================================
// DISPLAY TOP 5
// ============================================================

function displayTop5(top5) {

    const container =
        document.getElementById(
            "priorityCards"
        );


    if (!container) {
        return;
    }


    container.innerHTML = "";


    top5.forEach(
        (vulnerability, index) => {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "vulnerability-card";


            // ------------------------------------------------
            // PRIORITY REASONS
            // ------------------------------------------------

            const reasons =
                vulnerability
                    .priority_reasons
                || [];


            const reasonHTML =
                reasons.length > 0

                    ? reasons
                        .map(
                            reason =>
                                `<li>✓ ${escapeHTML(reason)}</li>`
                        )
                        .join("")

                    : "<li>✓ Ranked using security signals</li>";


            // ------------------------------------------------
            // CARD HTML
            // ------------------------------------------------

            card.innerHTML = `

                <div class="rank">
                    #${index + 1}
                </div>


                <div class="vulnerability-info">

                    <h3>
                        ${escapeHTML(
                            vulnerability.title ||
                            "Unknown Vulnerability"
                        )}
                    </h3>


                    <p>
                        <strong>ID:</strong>
                        ${escapeHTML(
                            vulnerability.id ||
                            "N/A"
                        )}
                    </p>


                    <p>
                        <strong>Asset:</strong>
                        ${escapeHTML(
                            vulnerability.asset ||
                            "N/A"
                        )}
                    </p>


                    <p>
                        <strong>Technology:</strong>
                        ${escapeHTML(
                            vulnerability.technology ||
                            "N/A"
                        )}
                        ${escapeHTML(
                            vulnerability.version ||
                            ""
                        )}
                    </p>


                    <p>
                        <strong>Severity:</strong>
                        ${escapeHTML(
                            vulnerability.severity ||
                            "Unknown"
                        )}
                    </p>

                </div>


                <div class="score">

                    <span>
                        Priority Score
                    </span>

                    <strong>
                        ${vulnerability.priority_score ?? 0}
                    </strong>

                    <small>
                        ${escapeHTML(
                            vulnerability.priority ||
                            "P4 - Monitor"
                        )}
                    </small>

                </div>


                <div class="metrics">

                    <span>
                        CVSS:
                        ${vulnerability.cvss ?? 0}
                    </span>


                    <span>
                        EPSS:
                        ${vulnerability.epss ?? 0}
                    </span>


                    <span>
                        KEV:
                        ${escapeHTML(
                            vulnerability.kev ||
                            "No"
                        )}
                    </span>


                    <span>
                        Exposure:
                        ${escapeHTML(
                            vulnerability.exposure ||
                            "Unknown"
                        )}
                    </span>


                    <span>
                        Importance:
                        ${vulnerability.service_importance ?? 1}/5
                    </span>

                </div>


                <!-- WHY RANKED -->

                <div class="priority-reasons">

                    <strong>
                        Why ranked this high
                    </strong>

                    <ul>
                        ${reasonHTML}
                    </ul>

                </div>


                <!-- WHY IT MATTERS -->

                <div class="why-matters">

                    <strong>
                        💡 Why it matters
                    </strong>

                    <p>
                        ${escapeHTML(
                            vulnerability.why_matters ||
                            "This vulnerability was prioritized because of its security and organisational risk signals."
                        )}
                    </p>

                </div>


                <!-- SAFE NEXT ACTION -->

                <div class="safe-action">

                    <strong>
                        🛡️ Safe next action
                    </strong>

                    <p>
                        ${escapeHTML(
                            vulnerability.safe_next_action ||
                            "Verify the affected version and apply the vendor-supported remediation."
                        )}
                    </p>

                </div>

            `;


            container.appendChild(
                card
            );

        }
    );
}


// ============================================================
// DISPLAY AI ANALYSIS
// ============================================================

function displayAIAnalysis(text) {

    const container =
        document.getElementById(
            "aiAnalysis"
        );


    if (!container) {
        return;
    }


    const sections =
        String(text)
            .split(
                /(?=PRIORITY:\s*\d+)/gi
            )
            .filter(
                section =>
                    section.trim()
            );


    if (sections.length === 0) {

        container.innerHTML =
            `<div>${escapeHTML(text)}</div>`;

        return;
    }


    container.innerHTML =
        sections
            .map(
                (section, index) => {

                    const priorityMatch =
                        section.match(
                            /PRIORITY:\s*(\d+)/i
                        );


                    const idMatch =
                        section.match(
                            /ID:\s*(.*)/i
                        );


                    const titleMatch =
                        section.match(
                            /TITLE:\s*(.*)/i
                        );


                    const whyMatch =
                        section.match(
                            /WHY IT MATTERS:\s*([\s\S]*?)(?=SOLUTION:|$)/i
                        );


                    const solutionMatch =
                        section.match(
                            /SOLUTION:\s*([\s\S]*)/i
                        );


                    const priority =
                        priorityMatch
                            ? priorityMatch[1]
                            : index + 1;


                    const id =
                        idMatch
                            ? idMatch[1].trim()
                            : "";


                    const title =
                        titleMatch
                            ? titleMatch[1].trim()
                            : "Vulnerability";


                    const why =
                        whyMatch
                            ? whyMatch[1].trim()
                            : "No explanation returned.";


                    const solution =
                        solutionMatch
                            ? solutionMatch[1].trim()
                            : "No solution returned.";


                    return `

                        <div class="ai-priority-card">

                            <div class="ai-priority-header">

                                <div class="ai-priority-number">
                                    #${escapeHTML(priority)}
                                </div>

                                <div>

                                    <h3>
                                        ${escapeHTML(title)}
                                    </h3>

                                    <span>
                                        ${escapeHTML(id)}
                                    </span>

                                </div>

                            </div>


                            <div class="ai-why">

                                <strong>
                                    💡 Why it matters
                                </strong>

                                <p>
                                    ${escapeHTML(why)}
                                </p>

                            </div>


                            <div class="ai-solution">

                                <strong>
                                    🛡️ Recommended solution
                                </strong>

                                <p>
                                    ${escapeHTML(solution)}
                                </p>

                            </div>

                        </div>

                    `;
                }
            )
            .join("");
}


// ============================================================
// FALLBACK AI MESSAGE
// ============================================================

function showFallbackAIMessage(
    message
) {

    const container =
        document.getElementById(
            "aiAnalysis"
        );


    if (!container) {
        return;
    }


    container.innerHTML = `

        <div>

            <strong>
                ⚠️ AI Explanation
            </strong>


            <p style="margin-top:10px;">
                ${escapeHTML(message)}
            </p>


            <p style="margin-top:10px;">
                The Top 5 vulnerability ranking
                was calculated successfully using
                CVSS, EPSS, KEV, exposure and
                service importance.
            </p>

        </div>

    `;


    const retryButton =
        document.getElementById(
            "retryButton"
        );


    if (retryButton) {

        retryButton.classList.remove(
            "hidden"
        );
    }
}


// ============================================================
// RETRY AI ANALYSIS
// ============================================================

async function retryAIAnalysis() {

    if (
        !lastOrganization ||
        !lastTop5 ||
        lastTop5.length === 0
    ) {

        alert(
            "Please run the vulnerability analysis first."
        );

        return;
    }


    const retryButton =
        document.getElementById(
            "retryButton"
        );


    const aiAnalysis =
        document.getElementById(
            "aiAnalysis"
        );


    if (retryButton) {

        retryButton.disabled =
            true;

        retryButton.textContent =
            "⏳ Retrying...";
    }


    if (aiAnalysis) {

        aiAnalysis.innerHTML =
            "🤖 Retrying Featherless AI...";
    }


    try {

        const response =
            await fetch(
                `${API_URL}/api/explain`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        organization:
                            lastOrganization,

                        top5:
                            lastTop5

                    })
                }
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            data.error ||
            !data.ai_analysis ||
            !String(
                data.ai_analysis
            ).trim()
        ) {

            showFallbackAIMessage(
                data.error ||
                "Featherless returned an empty response."
            );

            return;
        }


        displayAIAnalysis(
            data.ai_analysis
        );


        if (retryButton) {

            retryButton.classList.add(
                "hidden"
            );
        }


    } catch (error) {

        console.error(
            "Retry error:",
            error
        );


        showFallbackAIMessage(
            "Featherless AI is still unavailable."
        );


    } finally {

        if (retryButton) {

            retryButton.disabled =
                false;

            retryButton.textContent =
                "🔄 Retry AI Analysis";
        }
    }
}


// ============================================================
// ESCAPE HTML
// ============================================================

function escapeHTML(value) {

    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}