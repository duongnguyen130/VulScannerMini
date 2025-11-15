const scanBtn = document.getElementById("scanBtn");
const loader = document.getElementById("loader");
const results = document.getElementById("results");
const errorBox = document.getElementById("error");

scanBtn.onclick = async () => {
    results.innerHTML = "";
    errorBox.classList.add("hidden");
    errorBox.textContent = "";

    const target = document.getElementById("target").value.trim();
    const tcpStart = document.getElementById("tcp_start").value.trim();
    const tcpEnd = document.getElementById("tcp_end").value.trim();

    if (!target) {
        errorBox.textContent = "Please enter a target IP or domain.";
        errorBox.classList.remove("hidden");
        return;
    }

    loader.classList.remove("hidden");
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    try {
        const res = await fetch("/scan", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                target: target,
                tcp_start: tcpStart,
                tcp_end: tcpEnd
            })
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.error || "Scan failed");
        }

        const tcpList = data.open_tcp.length ? data.open_tcp.join(", ") : "None";
        const udpList = data.open_udp.length ? data.open_udp.join(", ") : "None";
        const issuesHtml = data.misconfigs.length
            ? data.misconfigs.map(x => `<li>${x}</li>`).join("")
            : "<li>No obvious misconfigurations detected.</li>";

        results.innerHTML = `
            <div class="result-box">
                <h2>Scan Results for ${data.target}</h2>
                <p><strong>Elapsed:</strong> ${data.elapsed_sec} s</p>
                <p><strong>Open TCP Ports:</strong> ${tcpList}</p>
                <p><strong>Open/Filtered UDP Ports:</strong> ${udpList}</p>
                <h3>Misconfigurations / Risks</h3>
                <ul>${issuesHtml}</ul>
                <a href="${data.report_url}" target="_blank" class="report-btn">
                    View Full HTML Report
                </a>
            </div>
        `;
    } catch (err) {
        errorBox.textContent = err.message;
        errorBox.classList.remove("hidden");
    } finally {
        loader.classList.add("hidden");
        scanBtn.disabled = false;
        scanBtn.textContent = "Start Scan";
    }
};
