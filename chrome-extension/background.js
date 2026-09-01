/**
 * PhishLens PhishGuard - Background Service Worker
 * Manages badge telemetry, real-time threat notifications, and background scanning.
 */

console.log("🛡️ PhishLens Background Service Worker initialized.");

// Handle incoming messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "pageAnalysisComplete") {
    const analysis = message.analysis;
    const tabId = sender.tab ? sender.tab.id : null;

    if (tabId && analysis) {
      updateBadgeForTab(tabId, analysis);
    }
    sendResponse({ status: "received" });
  }
  return true;
});

function updateBadgeForTab(tabId, analysis) {
  const score = analysis.risk_score || 0;

  if (score >= 70) {
    chrome.action.setBadgeText({ text: "!", tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tabId });
  } else if (score >= 35) {
    chrome.action.setBadgeText({ text: "⚠️", tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#f59e0b", tabId: tabId });
  } else {
    chrome.action.setBadgeText({ text: "✓", tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId: tabId });
  }
}