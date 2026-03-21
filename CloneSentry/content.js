chrome.runtime.onMessage.addListener((message) => {

    if (message.type === "SHOW_RESULT") {

        // prevent duplicate
        if (document.getElementById("specter-banner")) return;

        const box = document.createElement("div");
        box.id = "specter-banner";

        box.innerText = `⚠ SpecterScan: ${message.verdict} (${message.risk})`;

        box.style.position = "fixed";
        box.style.bottom = "20px";
        box.style.right = "20px";
        box.style.padding = "12px";
        box.style.background =
            message.risk === "High" ? "#c0392b" :
            message.risk === "Medium" ? "#d35400" :
            "#27ae60";

        box.style.color = "white";
        box.style.zIndex = "999999";
        box.style.borderRadius = "8px";

        document.body.appendChild(box);

        setTimeout(() => box.remove(), 5000);
    }

});