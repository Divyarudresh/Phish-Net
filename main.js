(function () {
    "use strict";

    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");
    const emailText = document.getElementById("email-text");
    const analyzeBtn = document.getElementById("analyze-btn");
    const resultCard = document.getElementById("result-card");
    const resultSection = document.getElementById("result-section");
    const errorToast = document.getElementById("error-toast");

    // URL checker elements
    const urlInput = document.getElementById("url-input");
    const urlAnalyzeBtn = document.getElementById("url-analyze-btn");
    const urlBadge = document.getElementById("url-badge");
    const urlLabel = document.getElementById("url-label");
    const urlRisk = document.getElementById("url-risk");
    const urlProbWrap = document.getElementById("url-prob-wrap");
    const urlProbBody = document.getElementById("url-prob-body");

    const tabs = document.querySelectorAll(".tab");
    const uploadPanel = document.getElementById("upload-panel");
    const pastePanel = document.getElementById("paste-panel");

    const safeIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
    const spamIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>`;

    let currentFile = null;

    // Tab switching
    tabs.forEach((tab) => {
        tab.addEventListener("click", () => {
            tabs.forEach((t) => t.classList.remove("active"));
            tab.classList.add("active");
            uploadPanel.classList.toggle("active", tab.dataset.tab === "upload");
            pastePanel.classList.toggle("active", tab.dataset.tab === "paste");
            if (tab.dataset.tab === "upload") {
                document.getElementById("dropzone-text").textContent = "Drag & drop your email here";
                document.getElementById("dropzone-hint").textContent = "or click to browse — .eml, .txt supported";
            } else {
                currentFile = null;
                fileInput.value = "";
            }
        });
    });

    // Dropzone
    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        const files = e.dataTransfer.files;
        if (files.length) handleFile(files[0]);
    });

    fileInput.addEventListener("change", (e) => {
        const files = e.target.files;
        if (files && files.length) handleFile(files[0]);
    });

    function handleFile(file) {
        const ext = (file.name || "").toLowerCase();
        if (!ext.endsWith(".eml") && !ext.endsWith(".txt")) {
            showError("Please upload a .eml or .txt file.");
            return;
        }
        currentFile = file;
        document.getElementById("dropzone-text").textContent = file.name;
        document.getElementById("dropzone-hint").textContent = "Click or drop another file to change";
    }

    function getEmailContent() {
        const activeTab = document.querySelector(".tab.active").dataset.tab;
        if (activeTab === "paste") {
            return emailText.value.trim();
        }
        return currentFile;
    }

    function showError(msg) {
        errorToast.textContent = msg;
        errorToast.classList.add("visible");
        setTimeout(() => errorToast.classList.remove("visible"), 4000);
    }

    function showResult(data) {
        const isSpam = data.is_spam;
        resultCard.className = "result-card visible " + (isSpam ? "spam" : "safe");
        resultCard.querySelector("#result-icon").innerHTML = isSpam ? spamIcon : safeIcon;
        resultCard.querySelector("#result-title").textContent = data.prediction;
        resultCard.querySelector("#result-subtitle").textContent = isSpam
            ? "This email appears to be spam or phishing. Be cautious."
            : "This email appears to be safe. No obvious spam indicators detected.";

        const safePct = data.safe_probability ?? 100 - data.spam_probability;
        const spamPct = data.spam_probability ?? 100 - data.safe_probability;

        resultCard.querySelector("#safe-bar").style.width = safePct + "%";
        resultCard.querySelector("#spam-bar").style.width = spamPct + "%";
        resultCard.querySelector("#safe-value").textContent = safePct + "%";
        resultCard.querySelector("#spam-value").textContent = spamPct + "%";

        resultSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    analyzeBtn.addEventListener("click", async () => {
        const content = getEmailContent();
        if (!content) {
            showError("Please upload an email file or paste email content.");
            return;
        }

        if (typeof content === "string" && !content.trim()) {
            showError("Please enter or paste some email content.");
            return;
        }

        analyzeBtn.classList.add("loading");
        analyzeBtn.disabled = true;

        try {
            let res;
            if (typeof content === "string") {
                res = await fetch("/predict", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ text: content }),
                });
            } else {
                const formData = new FormData();
                formData.append("file", content);
                res = await fetch("/predict", {
                    method: "POST",
                    body: formData,
                });
            }

            const data = await res.json();

            if (!res.ok) {
                showError(data.error || "Something went wrong.");
                return;
            }

            showResult(data);
        } catch (err) {
            showError("Network error. Please try again.");
        } finally {
            analyzeBtn.classList.remove("loading");
            analyzeBtn.disabled = false;
        }
    });

    // URL analyze
    if (urlAnalyzeBtn) {
        urlAnalyzeBtn.addEventListener("click", async () => {
            const url = (urlInput.value || "").trim();
            if (!url) {
                showError("Please enter a URL to analyze.");
                return;
            }

            urlAnalyzeBtn.classList.add("loading");
            urlAnalyzeBtn.disabled = true;

            try {
                const res = await fetch("/predict_url", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url }),
                });

                const data = await res.json();

                if (!res.ok || !data.success) {
                    showError(data.error || "URL analysis failed.");
                    return;
                }

                const label = (data.label || "").toString();
                urlLabel.textContent = label || "Unknown";
                urlRisk.textContent = data.risk || "";

                const isSafe = label.toLowerCase() === "benign";
                urlBadge.textContent = isSafe ? "Benign" : "Malicious";
                urlBadge.classList.remove("safe", "danger");
                urlBadge.classList.add(isSafe ? "safe" : "danger");

                // Probability breakdown table
                const probs = data.probabilities && typeof data.probabilities === "object" ? data.probabilities : {};
                if (Object.keys(probs).length > 0) {
                    urlProbWrap.classList.add("visible");
                    const sorted = Object.entries(probs).sort((a, b) => (b[1] || 0) - (a[1] || 0));
                    urlProbBody.innerHTML = sorted.map(([key, val]) => {
                        const labelCap = key.charAt(0).toUpperCase() + key.slice(1);
                        const pct = typeof val === "number" ? val.toFixed(1) : val;
                        return `<tr>
                            <th>${labelCap}</th>
                            <td class="prob-bar-cell">
                                <div class="prob-bar-track"><div class="prob-bar-fill ${key}" style="width:${pct}%"></div></div>
                            </td>
                            <td>${pct}%</td>
                        </tr>`;
                    }).join("");
                } else {
                    urlProbWrap.classList.remove("visible");
                }
            } catch (err) {
                showError("Network error while checking URL. Please try again.");
            } finally {
                urlAnalyzeBtn.classList.remove("loading");
                urlAnalyzeBtn.disabled = false;
            }
        });
    }
})();
