const scanCache = {};

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

    if (changeInfo.status !== "complete") return;
    if (!tab.url || !tab.url.startsWith("http")) return;

    const url = tab.url;

    // Check cache first
    if (scanCache[url]) {

        const cached = scanCache[url];

        if (cached.is_phishing) {
            chrome.tabs.sendMessage(tabId, {
                action: "phishing_warning",
                verdict: cached.verdict
            });
        }

        return;
    }

    try {

        const response = await fetch("https://spectarscan.onrender.com/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        // Save result in cache
        scanCache[url] = data;

        if (data.is_phishing) {
            chrome.tabs.sendMessage(tabId, {
                action: "phishing_warning",
                verdict: data.verdict
            });
        }

    } catch (err) {
        console.log("SpecterScan error:", err);
    }

});