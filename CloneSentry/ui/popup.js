document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const statusCard = document.getElementById('status-card');
    const verdictEl = document.getElementById('verdict');
    const riskEl = document.getElementById('risk-lvl');
    
   
    const aiScoreEl = document.getElementById('ai-score');
    const vtHitsEl = document.getElementById('vt-hits');
    const ageEl = document.getElementById('age');
    const sslEl = document.getElementById('ssl');

    scanBtn.addEventListener('click', async () => {
      
        verdictEl.innerText = "Analyzing Page...";
        riskEl.innerText = "Checking patterns & threat databases";
        statusCard.style.background = "#7f8c8d"; // Neutral Gray
        scanBtn.disabled = true;

        try {
            // 2. Get the active tab URL using Chrome API
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (!tab.url.startsWith('http')) {
                verdictEl.innerText = "Invalid Page";
                riskEl.innerText = "Cannot scan system pages.";
                scanBtn.disabled = false;
                return;
            }

            // 3. Secure Fetch to your Local Backend
            // We only send the URL. No personal data, no cookies.
        const response = await fetch('https://spectarscan.onrender.com/predict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: tab.url })
});

            if (!response.ok) throw new Error('Backend Unreachable');

            const data = await response.json();

            // 4. Update UI with the Response`
            verdictEl.innerText = data.verdict;
            riskEl.innerText = `Risk: ${data.risk_level}`;
            aiScoreEl.innerText = data.scores.ai_certainty;
            vtHitsEl.innerText = `${data.scores.virus_total_hits} Engines`;
            ageEl.innerText = data.security_report.domain_age;
            sslEl.innerText = data.security_report.ssl_active ? "Active" : "Missing";

            // 5. Dynamic Styling based on Risk
            if (data.is_phishing || data.risk_level === "High") {
                statusCard.style.background = "#c0392b"; // Danger Red
            } else if (data.risk_level === "Medium") {
                statusCard.style.background = "#d35400"; // Warning Orange
            } else {
                statusCard.style.background = "#27ae60"; // Safe Green
            }

        } catch (error) {
            console.error("SpecterScan Error:", error);
            verdictEl.innerText = "Connection Failed";
            riskEl.innerText = "Server unreachable. Try again.";
            statusCard.style.background = "#2c3e50";
        } finally {
            scanBtn.disabled = false;
        }
    });
});