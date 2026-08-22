let vulnerabilities = [];


// ==================================================
// CSV UPLOAD
// ==================================================

document
    .getElementById("csvFile")
    .addEventListener("change", function(event) {

        const file = event.target.files[0];

        if (!file) {
            return;
        }

        Papa.parse(file, {

            header: true,

            skipEmptyLines: true,

            complete: function(results) {

                vulnerabilities = results.data;

                document
                    .getElementById("recordCount")
                    .textContent =
                    `${vulnerabilities.length} vulnerability records loaded`;

            }

        });

    });


// ==================================================
// DEMO DATA
// ==================================================

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
            id: "VULN-003",
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
            id: "VULN-004",
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
            id: "VULN-005",
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


    document
        .getElementById("recordCount")
        .textContent =
        `${vulnerabilities.length} demo vulnerability records loaded`;
}


// ==================================================
// RUN TRIAGE
// ==================================================

async function runTriage() {

    if (vulnerabilities.length === 0) {

        alert(
            "Please upload a vulnerability CSV or load demo data."
        );

        return;
    }


    const organization = {

        name:
            document
                .getElementById("organizationName")
                .value,

        technology:
            document
                .getElementById("organizationTechnology")
                .value,

        version:
            document
                .getElementById("organizationVersion")
                .value,

        exposure:
            document
                .getElementById("organizationExposure")
                .value

    };


    // Show loading

    document
        .getElementById("loading")
        .style.display = "block";


    document
        .getElementById("prioritySection")
        .classList.add("hidden");


    document
        .getElementById("aiSection")
        .classList.add("hidden");


    try {

        // ==================================================
        // STEP 1: RANK VULNERABILITIES
        // ==================================================

        const rankResponse = await fetch(
            "http://127.0.0.1:8000/api/rank",
            {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({

                    vulnerabilities:
                        vulnerabilities

                })

            }
        );


        const rankData =
            await rankResponse.json();


        if (rankData.error) {

            alert(rankData.error);

            return;
        }


        // ==================================================
        // SHOW TOP 5 IMMEDIATELY
        // ==================================================

        displayTop5(
            rankData.top5
        );


        // Stop the first loading message

        document
            .getElementById("loading")
            .style.display = "none";


        // ==================================================
        // STEP 2: ASK FEATHERLESS AI
        // ==================================================

        const aiLoading =
            document.getElementById(
                "aiAnalysis"
            );


        document
            .getElementById("aiSection")
            .classList.remove("hidden");


        aiLoading.innerHTML =
            "🤖 Featherless AI is preparing explanations...";


        const explainResponse =
            await fetch(
                "http://127.0.0.1:8000/api/explain",
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


        if (explainData.error) {

            aiLoading.innerHTML =
                "⚠️ " + explainData.error;

            return;
        }


        // ==================================================
        // DISPLAY AI RESULT
        // ==================================================

        displayAIAnalysis(
            explainData.ai_analysis
        );

    }

    catch (error) {

        console.error(error);

        document
            .getElementById("loading")
            .style.display = "none";


        alert(
            "Unable to connect to FastAPI. " +
            "Make sure Uvicorn is running."
        );

    }

}


// ==================================================
// DISPLAY TOP 5
// ==================================================

function displayTop5(top5) {

    const container =
        document.getElementById(
            "priorityCards"
        );


    container.innerHTML = "";


    top5.forEach(
        (vulnerability, index) => {


            const card =
                document.createElement("div");


            card.className =
                "vulnerability-card";


            card.innerHTML = `

                <div class="rank">
                    #${index + 1}
                </div>


                <div class="vulnerability-info">

                    <h3>
                        ${vulnerability.title}
                    </h3>

                    <p>
                        <strong>ID:</strong>
                        ${vulnerability.id || "N/A"}
                    </p>

                    <p>
                        <strong>Asset:</strong>
                        ${vulnerability.asset || "N/A"}
                    </p>

                    <p>
                        <strong>Technology:</strong>
                        ${vulnerability.technology || "N/A"}
                        ${vulnerability.version || ""}
                    </p>

                    <p>
                        <strong>Severity:</strong>
                        ${vulnerability.severity}
                    </p>

                </div>


                <div class="score">

                    <span>
                        Priority Score
                    </span>

                    <strong>
                        ${vulnerability.priority_score}
                    </strong>

                    <small>
                        ${vulnerability.priority}
                    </small>

                </div>


                <div class="metrics">

                    <span>
                        CVSS:
                        ${vulnerability.cvss}
                    </span>

                    <span>
                        EPSS:
                        ${vulnerability.epss}
                    </span>

                    <span>
                        KEV:
                        ${vulnerability.kev}
                    </span>

                    <span>
                        Exposure:
                        ${vulnerability.exposure}
                    </span>

                    <span>
                        Importance:
                        ${vulnerability.service_importance}/5
                    </span>

                </div>

            `;


            container.appendChild(card);

        }
    );


    document
        .getElementById("prioritySection")
        .classList.remove("hidden");

}


// ==================================================
// DISPLAY AI ANALYSIS
// ==================================================

function displayAIAnalysis(text) {

    const container =
        document.getElementById(
            "aiAnalysis"
        );


    container.innerHTML =
        text
            .replace(
                /\*\*(.*?)\*\*/g,
                "<strong>$1</strong>"
            )
            .replace(
                /\n/g,
                "<br>"
            );

}