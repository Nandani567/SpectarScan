chrome.runtime.onMessage.addListener((message) => {

    if (message.action === "phishing_warning") {

        const banner = document.createElement("div");

        banner.innerText = "⚠️ SpecterScan Warning: Possible Phishing Site";

        banner.style.position = "fixed";
        banner.style.top = "0";
        banner.style.left = "0";
        banner.style.right = "0";
        banner.style.padding = "15px";
        banner.style.background = "red";
        banner.style.color = "white";
        banner.style.fontSize = "18px";
        banner.style.textAlign = "center";
        banner.style.zIndex = "999999";

        document.body.prepend(banner);

    }

});