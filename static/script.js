/* ---------------------------------------------
   Elements
--------------------------------------------- */
const scanBtn = document.getElementById("scanBtn");
const results = document.getElementById("results");
const errorBox = document.getElementById("error");
const profileSelect = document.getElementById("profile");
const rangeRow = document.getElementById("rangeRow");

const progressContainer = document.getElementById("globalProgressContainer");
const progressBar = document.getElementById("globalProgressBar");
const progressStatus = document.getElementById("globalProgressStatus");

/* ---------------------------------------------
   Show / Hide TCP Range for Custom
--------------------------------------------- */
profileSelect.addEventListener("change", () => {
    if (profileSelect.value === "custom") {
        rangeRow.classList.remove("hidden");
    } else {
        rangeRow.classList.add("hidden");
    }
});

/* ---------------------------------------------
   Start Scan
--------------------------------------------- */
scanBtn.onclick = async () => {
    results.innerHTML = "";
    errorBox.classList.add("hidden");
    errorBox.textContent = "";

    const target = document.getElementById("target").value.trim();
    const profile = profileSelect.value;

    let tcpStart = document.getElementById("tcp_start")?.value?.trim();
    let tcpEnd = document.getElementById("tcp_end")?.value?.trim();

    if (!target) return showError("Please enter a target.");

    if (profile === "custom") {
        if (!tcpStart || !tcpEnd || isNaN(tcpStart) || isNaN(tcpEnd))
            return showError("Enter a valid TCP range.");

        tcpStart = parseInt(tcpStart, 10);
        tcpEnd = parseInt(tcpEnd, 10);

        if (tcpStart < 1 || tcpEnd > 65535 || tcpStart > tcpEnd)
            return showError("TCP range must be 1–65535.");
    } else {
        tcpStart = 1;
        tcpEnd = 1024;
    }

    // Disable button
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    // Start real-time progress
    startProgressStream(target, profile, tcpStart, tcpEnd);

    try {
        const res = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target,
                profile,
                tcp_start: tcpStart,
                tcp_end: tcpEnd,
            }),
        });

        const data = await res.json();

        if (!res.ok) throw new Error(data.error || "Scan failed.");

        renderResults(data);

    } catch (err) {
        showError(err.message);
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Start Scan";
    }
};

/* ---------------------------------------------
   SSE Real-Time Progress
--------------------------------------------- */
function startProgressStream(target, profile, tcpStart, tcpEnd) {
    progressBar.style.width = "0%";
    progressContainer.classList.remove("hidden");
    progressStatus.classList.remove("hidden");

    const safeTarget = encodeURIComponent(target);
    const url = `/progress?target=${safeTarget}&profile=${profile}&tcp_start=${tcpStart}&tcp_end=${tcpEnd}`;

    const stream = new EventSource(url);

    stream.onmessage = (event) => {
        let data;

        // Try JSON first
        try {
            data = JSON.parse(event.data);
        } catch {
            handleLegacyPhase(event.data);
            return;
        }

        // --------------------------
        // Percent handling
        // --------------------------
        if (data.phase === "tcp" || data.phase === "udp" || data.phase === "analysis") {
            progressBar.style.width = data.percent + "%";
            progressStatus.textContent =
                `${data.phase.toUpperCase()} ${data.percent}%`;
        }

        if (data.phase === "tcp_done") {
            progressStatus.textContent = "TCP scan complete";
            progressBar.style.width = "40%";
        }

        if (data.phase === "udp_done") {
            progressStatus.textContent = "UDP scan complete";
            progressBar.style.width = "70%";
        }

        if (data.phase === "complete") {
            progressStatus.textContent = "Scan complete!";
            progressBar.style.width = "100%";

            stream.close();
            setTimeout(() => {
                progressContainer.classList.add("hidden");
                progressStatus.classList.add("hidden");
            }, 900);
        }
    };

    stream.onerror = () => {
        console.warn("SSE closed unexpectedly.");
        stream.close();
    };
}

/* ---------------------------------------------
   Legacy non-JSON phase handler
--------------------------------------------- */
function handleLegacyPhase(msg) {
    switch (msg) {
        case "TCP_START":
            progressStatus.textContent = "Scanning TCP ports...";
            progressBar.style.width = "5%";
            break;

        case "TCP_DONE":
            progressStatus.textContent = "TCP scan complete";
            progressBar.style.width = "40%";
            break;

        case "UDP_START":
            progressStatus.textContent = "Scanning UDP ports...";
            break;

        case "UDP_DONE":
            progressStatus.textContent = "UDP scan complete";
            progressBar.style.width = "70%";
            break;

        case "ANALYSIS_START":
            progressStatus.textContent = "Analyzing services...";
            break;

        case "ANALYSIS_DONE":
            progressStatus.textContent = "Finalizing report...";
            progressBar.style.width = "90%";
            break;

        case "COMPLETE":
            progressStatus.textContent = "Scan complete!";
            progressBar.style.width = "100%";
            break;
    }
}

/* ---------------------------------------------
   Utility
--------------------------------------------- */
function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
}

/* ---------------------------------------------
   Render results box
--------------------------------------------- */
function renderResults(data) {
    const tcpList = data.open_tcp.length ? data.open_tcp.join(", ") : "None";
    const udpList = data.open_udp.length ? data.open_udp.join(", ") : "None";

    const issuesHtml = data.misconfigs.length
        ? data.misconfigs.map((x) => `<li>${escapeHtml(x)}</li>`).join("")
        : "<li>No misconfigurations detected.</li>";

    const extraHtml =
        data.extra_findings && data.extra_findings.length
            ? data.extra_findings.map((x) => `<li>${escapeHtml(x)}</li>`).join("")
            : "<li>No additional findings.</li>";

    const osGuess = data.os_guess || "Unknown";

    results.innerHTML = `
        <div class="result-box">
            <h2>Scan Results for ${escapeHtml(data.target)}</h2>
            <p><strong>Profile:</strong> ${escapeHtml(data.profile.toUpperCase())}</p>
            <p><strong>Elapsed:</strong> ${data.elapsed_sec} seconds</p>
            <p><strong>Guessed OS:</strong> ${escapeHtml(osGuess)}</p>

            <p><strong>Open TCP Ports:</strong> ${escapeHtml(tcpList)}</p>
            <p><strong>Open/Filtered UDP Ports:</strong> ${escapeHtml(udpList)}</p>

            <h3>Misconfigurations</h3>
            <ul>${issuesHtml}</ul>

            <h3>Additional Findings</h3>
            <ul>${extraHtml}</ul>

            <a href="${data.report_url}" target="_blank" class="report-btn">
                View Full HTML Report
            </a>
        </div>
    `;
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
