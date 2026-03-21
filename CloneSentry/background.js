const API_URL = "https://spectarscan.onrender.com/predict";

console.log("SpecterScan service worker running");

// Prevent duplicate scans for same URL
let lastScannedUrl = "";

// Listen for tab updates
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

    // Only run when page fully loads
    if (changeInfo.status !== "complete") return;

    // Skip invalid URLs
    if (!tab.url || !tab.url.startsWith("http")) return;

    // Avoid scanning same URL repeatedly
    if (tab.url === lastScannedUrl) return;
    lastScannedUrl = tab.url;

    console.log("Scanning:", tab.url);

    try {
        const res = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: tab.url })
        });

        if (!res.ok) throw new Error("API failed");

        const data = await res.json();

        console.log("Result:", data);

        // Send result to content script
        chrome.tabs.sendMessage(tabId, {
            type: "SHOW_RESULT",
            verdict: data.verdict,
            risk: data.risk_level,
            is_phishing: data.is_phishing
        });

    } catch (error) {
        console.error("SpecterScan Error:", error);
    }

});