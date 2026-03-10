chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

    if (changeInfo.status !== "complete") return;
    if (!tab.url || !tab.url.startsWith("http")) return;

    try {

        const response = await fetch("https://spectarscan.onrender.com/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: tab.url })
        });

        const data = await response.json();

        console.log("SpecterScan result:", data);

        if (data.is_phishing) {

            chrome.scripting.executeScript({
                target: { tabId: tabId },
                func: showWarning,
                args: [data.verdict]
            });

        }

    } catch (err) {
        console.error("SpecterScan error:", err);
    }

});


function showWarning(verdict) {

    const banner = document.createElement("div");

    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.background = "#c0392b";
    banner.style.color = "white";
    banner.style.padding = "15px";
    banner.style.fontSize = "16px";
    banner.style.fontWeight = "bold";
    banner.style.zIndex = "999999";

    banner.innerText = "⚠ SpecterScan Warning: " + verdict;

    document.body.prepend(banner);
}