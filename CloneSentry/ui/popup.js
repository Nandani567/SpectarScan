document.addEventListener('DOMContentLoaded', () => {

    const scanBtn = document.getElementById('scanBtn');
    const statusCard = document.getElementById('status-card');
    const verdictEl = document.getElementById('verdict');
    const riskEl = document.getElementById('risk-lvl');

    const aiScoreEl = document.getElementById('ai-score');
    const vtHitsEl = document.getElementById('vt-hits');
    const ageEl = document.getElementById('age');
    const sslEl = document.getElementById('ssl');

    const manualInput = document.getElementById("manualUrl");

    scanBtn.addEventListener('click', async () => {

        verdictEl.innerText = "Analyzing...";
        riskEl.innerText = "Processing...";
        statusCard.style.background = "#7f8c8d";
        scanBtn.disabled = true;

        try {
            let urlToScan = "";

            // 👉 Manual input
            if (manualInput && manualInput.value.trim() !== "") {
                let input = manualInput.value.trim();
                urlToScan = input.startsWith("http") ? input : "https://" + input;
            } 
            // 👉 Current tab fallback
            else {
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

                if (!tab.url || !tab.url.startsWith('http')) {
                    verdictEl.innerText = "Invalid Page";
                    riskEl.innerText = "Cannot scan this page.";
                    return;
                }

                urlToScan = tab.url;
            }

            const response = await fetch('https://spectarscan.onrender.com/predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlToScan })
            });

            if (!response.ok) throw new Error('Backend error');

            const data = await response.json();

            // ✅ Update UI
            verdictEl.innerText = data.verdict;
            riskEl.innerText = `Risk: ${data.risk_level}`;
            aiScoreEl.innerText = data.scores.ai_certainty;
            vtHitsEl.innerText = `${data.scores.virus_total_hits} Engines`;
            ageEl.innerText = data.security_report.domain_age;
            sslEl.innerText = data.security_report.ssl_active ? "Active" : "Missing";

            // ✅ Color logic
            if (data.is_phishing || data.risk_level === "High") {
                statusCard.style.background = "#c0392b";
            } else if (data.risk_level === "Medium") {
                statusCard.style.background = "#d35400";
            } else {
                statusCard.style.background = "#27ae60";
            }

        } catch (error) {
            console.error("SpecterScan Error:", error);
            verdictEl.innerText = "Connection Failed";
            riskEl.innerText = "Try again";
            statusCard.style.background = "#2c3e50";
        } finally {
            scanBtn.disabled = false;
        }
    });

});