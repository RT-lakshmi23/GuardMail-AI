// ============================================
// GUARDMAIL AI - EMAIL THREAT ANALYZER
// Advanced JavaScript Logic for Email Security
// ============================================

// ============================================
// STATISTICS TRACKING
// ============================================

const statistics = {
    totalEmails: 0,
    highRiskCount: 0,
    mediumRiskCount: 0,
    safeCount: 0
};

// Dashboard DOM Elements
const dashboardElements = {
    totalEmails: null,
    highRiskCount: null,
    mediumRiskCount: null,
    safeCount: null,
    highRiskPercent: null,
    mediumRiskPercent: null,
    safePercent: null
};

// Classification DOM Elements
const classificationElements = {
    classificationType: null,
    confidenceBar: null,
    confidenceValue: null,
    classificationExplanation: null
};

// ============================================
// CHARTS & ANALYTICS TRACKING
// ============================================

const chartData = {
    threatCounts: {
        phishing: 0,
        malware: 0,
        spoofing: 0,
        spam: 0,
        suspicious: 0
    },
    riskScores: [],
    timestamps: [],
    lastAnalysis: null
};

let threatDistributionChart = null;
let riskScoreTrendChart = null;

// ============================================
// THREAT CLASSIFICATION ENGINE
// ============================================

const threatClassifications = {
    credentialTheft: {
        name: 'Credential Theft',
        icon: '🔓',
        keywords: [
            /verify.*account|confirm.*password|update.*password|reset.*password/gi,
            /confirm.*identity|validate.*account|activate.*account|unlock.*account/gi,
            /urgent.*verify|immediately.*confirm|please.*provide.*password/gi,
            /re-enter.*password|verify.*email|confirm.*email|update.*email/gi,
            /security.*alert|suspicious.*activity|unusual.*activity.*detected/gi
        ],
        severity: 'high',
        explanation: 'This email is attempting to steal user credentials by requesting password or account verification. This is a classic phishing tactic.'
    },
    bankingScam: {
        name: 'Banking Scam',
        icon: '💳',
        keywords: [
            /update.*banking|confirm.*banking|verify.*bank|banking.*information/gi,
            /credit.*card|debit.*card|card.*verification|card.*security/gi,
            /account.*compromised|account.*frozen|account.*suspended|urgent.*action.*required/gi,
            /wire.*transfer|urgent.*transfer|transaction.*failed|verify.*payment/gi,
            /banking.*details|financial.*information|routing.*number|account.*number/gi
        ],
        severity: 'high',
        explanation: 'This email impersonates a financial institution and attempts to steal banking credentials or payment information. Extreme caution advised.'
    },
    rewardScam: {
        name: 'Reward Scam',
        icon: '🎁',
        keywords: [
            /congratulations.*won|claim.*prize|you.*won|lottery.*winner/gi,
            /claim.*reward|collect.*reward|free.*money|free.*cash/gi,
            /act.*now|limited.*time|expires.*today|hurry|act.*quickly/gi,
            /click.*claim|click.*here|verify.*prize|confirm.*win/gi,
            /reward.*waiting|prize.*waiting|bonus.*available|refund.*available/gi
        ],
        severity: 'medium',
        explanation: 'This is a reward or prize scam designed to trick users into clicking malicious links or providing personal information. Legitimate rewards don\'t require upfront verification.'
    },
    businessEmailCompromise: {
        name: 'Business Email Compromise',
        icon: '🏢',
        keywords: [
            /from.*ceo|from.*manager|from.*director|behalf.*of.*executive/gi,
            /urgent.*transfer|wire.*transfer.*urgent|immediate.*payment.*required/gi,
            /confidential.*request|sensitive.*matter|urgent.*action.*required/gi,
            /purchase.*order|invoice.*attached|payment.*details|banking.*transfer/gi,
            /act.*discreetly|keep.*this.*confidential|do.*not.*disclose|do.*not.*mention/gi
        ],
        severity: 'high',
        explanation: 'Business Email Compromise (BEC) attack impersonating a company executive to request financial transactions or sensitive information.'
    },
    socialEngineering: {
        name: 'Social Engineering',
        icon: '🎭',
        keywords: [
            /urgency|immediately|asap|right.*now|at.*once/gi,
            /click.*link|click.*button|download.*file|open.*attachment/gi,
            /rare.*opportunity|exclusive.*offer|limited.*availability/gi,
            /verify.*now|confirm.*now|update.*now|install.*now/gi,
            /fear.*based|act.*now|don't.*delay|don't.*miss.*out/gi
        ],
        severity: 'medium',
        explanation: 'This email uses psychological manipulation tactics to trick users into taking specific actions without careful consideration.'
    }
};

function classifyThreat(content) {
    let highestScore = 0;
    let classifiedThreat = 'Safe Email';
    let selectedClassification = null;
    const scores = {};

    // Score each threat classification
    for (const [key, threat] of Object.entries(threatClassifications)) {
        let score = 0;
        let matchCount = 0;

        // Check each keyword pattern
        for (const pattern of threat.keywords) {
            const matches = content.match(pattern);
            if (matches) {
                matchCount += matches.length;
            }
        }

        // Calculate confidence score (0-100)
        // Base score on number of keyword matches
        score = Math.min(matchCount * 15, 100);

        // Boost score if multiple keywords match
        if (matchCount > 1) {
            score += Math.min(matchCount * 5, 20);
        }

        scores[key] = Math.min(score, 100);

        // Track highest scoring threat
        if (score > highestScore) {
            highestScore = Math.min(score, 100);
            classifiedThreat = threat.name;
            selectedClassification = { key, ...threat, confidenceScore: highestScore };
        }
    }

    // If no threat detected above 15% confidence, mark as safe
    if (highestScore < 15) {
        classifiedThreat = 'Safe Email';
        selectedClassification = {
            key: 'safe',
            name: 'Safe Email',
            icon: '✓',
            severity: 'low',
            confidenceScore: 100,
            explanation: 'This email does not exhibit common phishing, scamming, or social engineering patterns. It appears to be legitimate.'
        };
    }

    return {
        classification: classifiedThreat,
        confidenceScore: selectedClassification.confidenceScore,
        severity: selectedClassification.severity,
        explanation: selectedClassification.explanation,
        allScores: scores,
        fullResult: selectedClassification
    };
}

// Threat Database
const threatPatterns = {
    phishing: [
        { pattern: /verify.*account|confirm.*password|update.*billing|urgent.*action/gi, score: 25, message: "Phishing attempt detected" },
        { pattern: /click.*link|click.*here|verify.*now|confirm.*identity/gi, score: 20, message: "Suspicious urgency to click links" },
        { pattern: /congratulations.*won|claim.*reward|prize|lottery/gi, score: 30, message: "Classic phishing scheme" },
        { pattern: /provide.*ssn|provide.*credit.*card|banking.*information/gi, score: 35, message: "Request for sensitive information" }
    ],
    malware: [
        { pattern: /download.*attachment|execute.*file|run.*macro|enable.*macro/gi, score: 30, message: "Suspicious file execution request" },
        { pattern: /\.exe|\.zip|\.rar|\.scr|\.bat/gi, score: 25, message: "Potentially dangerous attachment type detected" },
        { pattern: /malware|virus|trojan|ransomware|keylogger/gi, score: 15, message: "Security threat keywords detected" }
    ],
    spoofing: [
        { pattern: /from.*ceo|from.*manager|behalf.*of|acting.*on.*behalf/gi, score: 20, message: "Impersonation attempt detected" },
        { pattern: /urgent.*transfer|wire.*transfer|payment.*required|invoice.*attached/gi, score: 25, message: "Business email compromise pattern" }
    ],
    spam: [
        { pattern: /buy.*now|limited.*offer|free.*shipping|special.*deal|50%.*off/gi, score: 10, message: "Commercial/promotional content" },
        { pattern: /unsubscribe|click.*here.*offer|no.*spam/gi, score: 8, message: "Bulk marketing email indicators" }
    ],
    suspicious: [
        { pattern: /bit\.ly|tinyurl|shortened.*url|short\.link|goo\.gl/gi, score: 15, message: "URL shortener detected" },
        { pattern: /micrsoft|gogle|amazn|paypa|appel/gi, score: 25, message: "Domain misspelling detected" },
        { pattern: /@gmail\.|@yahoo\.|@hotmail\./gi, score: 10, message: "Corporate impersonation using free email" }
    ]
};

// Recommendations Database
const recommendationsBase = {
    low: [
        "✓ Email appears safe for interaction",
        "✓ Links and attachments can be opened cautiously",
        "✓ Verify sender information as a precaution",
        "✓ Keep your security software updated"
    ],
    medium: [
        "⚠ Do not click on suspicious links",
        "⚠ Do not download attachments from unknown senders",
        "⚠ Verify sender identity through alternative contact method",
        "⚠ Be cautious with any requests for personal information",
        "⚠ Forward to your IT security team for analysis"
    ],
    high: [
        "🚨 DO NOT click any links or download attachments",
        "🚨 DO NOT respond to requests for personal information",
        "🚨 Report this email to your IT security team immediately",
        "🚨 Mark as phishing/spam and delete",
        "🚨 Check if your account credentials have been compromised",
        "🚨 Enable two-factor authentication if available"
    ]
};

// DOM Elements - Initialize as null, will be set after DOM loads
let emailForm = null;
let emailContent = null;
let resultsContainer = null;
let riskCircle = null;
let riskPercentage = null;
let riskBadge = null;
let riskDetails = null;
let threatsList = null;
let recommendationsList = null;

// Initialize all DOM elements after page load
function initializeDOMElements() {
    dashboardElements.totalEmails = document.getElementById('totalEmails');
    dashboardElements.highRiskCount = document.getElementById('highRiskCount');
    dashboardElements.mediumRiskCount = document.getElementById('mediumRiskCount');
    dashboardElements.safeCount = document.getElementById('safeCount');
    dashboardElements.highRiskPercent = document.getElementById('highRiskPercent');
    dashboardElements.mediumRiskPercent = document.getElementById('mediumRiskPercent');
    dashboardElements.safePercent = document.getElementById('safePercent');

    classificationElements.classificationType = document.getElementById('classificationType');
    classificationElements.confidenceBar = document.getElementById('confidenceBar');
    classificationElements.confidenceValue = document.getElementById('confidenceValue');
    classificationElements.classificationExplanation = document.getElementById('classificationExplanation');

    emailForm = document.getElementById('emailForm');
    emailContent = document.getElementById('emailContent');
    resultsContainer = document.getElementById('resultsContainer');
    riskCircle = document.getElementById('riskCircle');
    riskPercentage = document.getElementById('riskPercentage');
    riskBadge = document.getElementById('riskBadge');
    riskDetails = document.getElementById('riskDetails');
    threatsList = document.getElementById('threatsList');
    recommendationsList = document.getElementById('recommendationsList');

    // Attach event listener for form submission
    if (emailForm) {
        emailForm.addEventListener('submit', (e) => {
            e.preventDefault();
            analyzeEmail();
        });
    }

    // Attach event listener for clear history button
    const clearHistoryBtn = document.getElementById('clearHistoryBtn');
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', clearScanHistory);
    }
}

// ============================================
// MAIN ANALYSIS FUNCTION
// ============================================

function analyzeEmail() {
    const content = emailContent.value.trim();

    // Validation
    if (!content) {
        showNotification('Please paste email content to analyze', 'error');
        return;
    }

    if (content.length < 20) {
        showNotification('Email content too short. Please paste the full email.', 'error');
        return;
    }

    // Disable button and show loading
    const button = emailForm.querySelector('.analyze-button');
    const originalText = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<span>Analyzing...</span><span class="button-icon">⏳</span>';

    // Simulate API delay
    setTimeout(() => {
        // Perform analysis
        const analysisResult = performThreatAnalysis(content);

        // Update UI with results
        displayResults(analysisResult);

        // Re-enable button
        button.disabled = false;
        button.innerHTML = originalText;

        // Scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 1500);
}

// ============================================
// THREAT ANALYSIS ENGINE
// ============================================

function performThreatAnalysis(content) {
    let totalScore = 0;
    const detectedThreats = [];
    const threatCategoryScores = {};

    // Scan against all threat patterns
    for (const [category, patterns] of Object.entries(threatPatterns)) {
        threatCategoryScores[category] = 0;

        for (const threat of patterns) {
            if (threat.pattern.test(content)) {
                threatCategoryScores[category] += threat.score;
                totalScore += threat.score;

                // Avoid duplicate threat messages
                if (!detectedThreats.find(t => t.message === threat.message)) {
                    detectedThreats.push({
                        message: threat.message,
                        category: category,
                        score: threat.score
                    });
                }
            }
        }
    }

    // Normalize score (0-100)
    totalScore = Math.min(totalScore, 100);

    // Determine risk level
    let riskLevel;
    if (totalScore < 20) {
        riskLevel = 'low';
    } else if (totalScore < 50) {
        riskLevel = 'medium';
    } else {
        riskLevel = 'high';
    }

    // Additional analysis
    const emailLength = content.length;
    const urlCount = (content.match(/https?:\/\/[^\s]+/gi) || []).length;
    const emailCount = (content.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).length;
    const urgencyKeywords = (content.match(/urgent|immediately|asap|act.*now|limited.*time/gi) || []).length;

    // Boost score for multiple risk indicators
    if (urgencyKeywords > 0) totalScore += Math.min(urgencyKeywords * 5, 15);
    if (urlCount > 5) totalScore += 10;
    if (emailCount > 5) totalScore += 5;

    // Final normalization
    totalScore = Math.min(totalScore, 100);

    // Classify threat using the new engine
    const classification = classifyThreat(content);

    return {
        score: totalScore,
        riskLevel: riskLevel,
        detectedThreats: detectedThreats,
        analysis: {
            urlCount,
            emailCount,
            urgencyLevel: urgencyKeywords > 0 ? 'High' : 'Normal',
            contentLength: emailLength
        },
        classification: classification
    };
}

// ============================================
// UI UPDATE FUNCTIONS
// ============================================

function displayResults(analysisResult) {
    const { score, riskLevel, detectedThreats, analysis, classification } = analysisResult;

    // Update Risk Score
    updateRiskScore(score, riskLevel);

    // Update Risk Badge
    const badgeTexts = {
        low: 'Safe',
        medium: 'Warning',
        high: 'Dangerous'
    };
    riskBadge.textContent = badgeTexts[riskLevel];
    riskBadge.className = `risk-badge ${riskLevel}`;

    // Update Risk Details
    const riskDescriptions = {
        low: 'Email appears to be safe. Standard security practices apply.',
        medium: 'Potential threats detected. Exercise caution and verify sender.',
        high: 'High risk detected. Do not interact with this email.'
    };
    riskDetails.innerHTML = `<p class="risk-description">${riskDescriptions[riskLevel]}</p>`;

    // Update Threats List
    updateThreatsList(detectedThreats, riskLevel);

    // Update Threat Classification
    updateThreatClassification(classification);

    // Update Recommendations
    updateRecommendations(riskLevel);

    // Update Dashboard Statistics
    updateDashboardStatistics(riskLevel);

    // Save scan to history
    saveScanToHistory(analysisResult);

    // Update charts with new analysis
    updateCharts(analysisResult);

    // Show results container
    resultsContainer.style.display = 'grid';

    // Animate cards
    animateResultCards();
}

function updateRiskScore(score, riskLevel) {
    const percentage = Math.round(score);

    // Animate number
    animateValue(0, percentage, 1000, (value) => {
        riskPercentage.textContent = value;
    });

    // Update circle color based on risk level
    riskCircle.className = `risk-circle ${riskLevel}`;

    // Update gradient based on score
    const angle = (percentage / 100) * 360;
    const colorMap = {
        low: 'var(--success-color)',
        medium: 'var(--warning-color)',
        high: 'var(--danger-color)'
    };

    riskCircle.style.background = `conic-gradient(${colorMap[riskLevel]} 0deg, ${colorMap[riskLevel]} ${angle}deg, var(--bg-tertiary) ${angle}deg)`;
}

function updateThreatsList(threats, riskLevel) {
    if (threats.length === 0) {
        threatsList.innerHTML = '<p class="no-threats">✓ No threats detected</p>';
        return;
    }

    // Sort threats by severity
    threats.sort((a, b) => b.score - a.score);

    const threatsHTML = threats
        .map(threat => {
            const threatClass = threat.score > 25 ? 'danger' : threat.score > 15 ? 'warning' : 'info';
            return `
                <div class="threat-item ${threatClass}">
                    <div class="threat-title">🔴 ${threat.message}</div>
                    <div class="threat-description">Confidence: ${threat.score}% | Category: ${formatCategoryName(threat.category)}</div>
                </div>
            `;
        })
        .join('');

    threatsList.innerHTML = threatsHTML;
}

function updateRecommendations(riskLevel) {
    const recommendations = recommendationsBase[riskLevel] || recommendationsBase.low;

    const recommendationsHTML = recommendations
        .map(rec => `<li>${rec}</li>`)
        .join('');

    recommendationsList.innerHTML = recommendationsHTML;
}

// ============================================
// THREAT CLASSIFICATION DISPLAY
// ============================================

function updateThreatClassification(classification) {
    const { classification: threatType, confidenceScore, severity, explanation } = classification;

    // Format threat type display
    const classNames = threatType.toLowerCase().replace(/\s+/g, '-');
    classificationElements.classificationType.textContent = threatType;
    classificationElements.classificationType.className = `classification-type ${classNames}`;

    // Animate confidence bar
    const barTarget = confidenceScore;
    animateProgressBar(classificationElements.confidenceBar, barTarget);

    // Update confidence value
    classificationElements.confidenceValue.textContent = Math.round(confidenceScore) + '%';

    // Update explanation
    classificationElements.classificationExplanation.textContent = explanation;

    // Add color coding based on severity
    const explanationBox = classificationElements.classificationExplanation;
    if (severity === 'high') {
        explanationBox.style.borderLeft = '3px solid var(--danger-color)';
    } else if (severity === 'medium') {
        explanationBox.style.borderLeft = '3px solid var(--warning-color)';
    } else {
        explanationBox.style.borderLeft = '3px solid var(--success-color)';
    }
}

function animateProgressBar(element, targetPercentage) {
    let currentWidth = 0;
    const targetWidth = targetPercentage;
    const increment = targetWidth / 30;

    const interval = setInterval(() => {
        currentWidth += increment;
        if (currentWidth >= targetWidth) {
            currentWidth = targetWidth;
            clearInterval(interval);
        }
        element.style.width = currentWidth + '%';
    }, 20);
}

// ============================================
// DASHBOARD UPDATE FUNCTION
// ============================================

function updateDashboardStatistics(riskLevel) {
    // Increment total emails
    statistics.totalEmails += 1;

    // Increment risk category count
    if (riskLevel === 'high') {
        statistics.highRiskCount += 1;
    } else if (riskLevel === 'medium') {
        statistics.mediumRiskCount += 1;
    } else if (riskLevel === 'low') {
        statistics.safeCount += 1;
    }

    // Save to localStorage
    saveStatisticsToStorage();

    // Calculate percentages
    const total = statistics.totalEmails;
    const highRiskPercent = total > 0 ? Math.round((statistics.highRiskCount / total) * 100) : 0;
    const mediumRiskPercent = total > 0 ? Math.round((statistics.mediumRiskCount / total) * 100) : 0;
    const safePercent = total > 0 ? Math.round((statistics.safeCount / total) * 100) : 0;

    // Animate dashboard updates
    animateDashboardNumber(dashboardElements.totalEmails, statistics.totalEmails);
    animateDashboardNumber(dashboardElements.highRiskCount, statistics.highRiskCount);
    animateDashboardNumber(dashboardElements.mediumRiskCount, statistics.mediumRiskCount);
    animateDashboardNumber(dashboardElements.safeCount, statistics.safeCount);

    // Update percentages
    dashboardElements.highRiskPercent.textContent = highRiskPercent + '%';
    dashboardElements.mediumRiskPercent.textContent = mediumRiskPercent + '%';
    dashboardElements.safePercent.textContent = safePercent + '%';

    // Update stat bar for total emails
    const totalEmailsCard = dashboardElements.totalEmails.closest('.dashboard-card');
    const statBar = totalEmailsCard.querySelector('.stat-bar');
    if (statBar) {
        const barWidth = Math.min((total / 100) * 100, 100);
        statBar.style.width = barWidth + '%';
    }

    // Add pulse animation to updated cards
    const cards = document.querySelectorAll('.dashboard-card');
    cards.forEach((card, index) => {
        card.style.animation = 'none';
        setTimeout(() => {
            card.style.animation = `cardPulse 0.6s ease-out`;
        }, 10);
    });
}

function animateDashboardNumber(element, targetValue) {
    const currentValue = parseInt(element.textContent) || 0;
    const increment = Math.ceil((targetValue - currentValue) / 10);
    let displayValue = currentValue;

    const counter = setInterval(() => {
        displayValue += increment;
        if (displayValue >= targetValue) {
            displayValue = targetValue;
            clearInterval(counter);
        }
        element.textContent = displayValue;
    }, 30);
}

function animateResultCards() {
    const cards = document.querySelectorAll('.result-card');
    cards.forEach((card, index) => {
        card.style.animation = 'none';
        setTimeout(() => {
            card.style.animation = `slideInUp 0.5s ease-out ${index * 0.1}s forwards`;
        }, 10);
    });
}

function animateValue(start, end, duration, callback) {
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;

    const timer = setInterval(() => {
        current += increment;
        if (current >= end) {
            current = end;
            clearInterval(timer);
        }
        callback(Math.round(current));
    }, 16);
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function formatCategoryName(category) {
    const names = {
        phishing: 'Phishing',
        malware: 'Malware',
        spoofing: 'Spoofing',
        spam: 'Spam',
        suspicious: 'Suspicious'
    };
    return names[category] || category;
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 100px;
        right: 20px;
        padding: 15px 20px;
        background: ${type === 'error' ? 'var(--danger-color)' : 'var(--success-color)'};
        color: white;
        border-radius: 8px;
        z-index: 2000;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        animation: slideInUp 0.3s ease-out;
        font-weight: 500;
    `;

    document.body.appendChild(notification);

    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutDown 0.3s ease-out forwards';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// ============================================
// EVENT LISTENERS
// ============================================

// Event listeners are attached in initializeDOMElements() after DOM is loaded

// Add keyboard shortcut
document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        if (document.activeElement === emailContent) {
            analyzeEmail();
        }
    }
});

// ============================================
// SMOOTH SCROLL BEHAVIOR
// ============================================

document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});

// ============================================
// INITIALIZATION & DEMO
// ============================================

// Scan History Storage
let scanHistory = [];

// Load scan history from localStorage
function loadScanHistory() {
    const stored = localStorage.getItem('guardmailScanHistory');
    if (stored) {
        try {
            scanHistory = JSON.parse(stored);
        } catch (e) {
            scanHistory = [];
        }
    }
    displayScanHistory();
}

// Save scan history to localStorage
function saveScanToHistory(analysisResult) {
    const timestamp = new Date().toLocaleString();
    const { score, riskLevel, classification } = analysisResult;

    const historyItem = {
        id: Date.now(),
        timestamp: timestamp,
        riskScore: Math.round(score),
        riskLevel: riskLevel,
        threatCategory: classification.classification,
        confidenceScore: Math.round(classification.confidenceScore)
    };

    // Add to beginning of array (most recent first)
    scanHistory.unshift(historyItem);

    // Limit history to 50 items
    if (scanHistory.length > 50) {
        scanHistory = scanHistory.slice(0, 50);
    }

    localStorage.setItem('guardmailScanHistory', JSON.stringify(scanHistory));
    displayScanHistory();
}

// Display scan history in sidebar
function displayScanHistory() {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;

    if (scanHistory.length === 0) {
        historyList.innerHTML = '<div class="history-empty">No scans yet</div>';
        return;
    }

    const historyHTML = scanHistory
        .map(item => {
            const riskIcon = {
                low: '✓',
                medium: '⚠️',
                high: '🚨'
            }[item.riskLevel] || '?';

            return `
                <div class="history-item" title="Risk Score: ${item.riskScore}%">
                    <div class="history-item-timestamp">${item.timestamp}</div>
                    <div class="history-item-risk ${item.riskLevel}">
                        <span>${riskIcon}</span>
                        <span>${item.riskScore}%</span>
                    </div>
                    <div class="history-item-category">${item.threatCategory}</div>
                </div>
            `;
        })
        .join('');

    historyList.innerHTML = historyHTML;
}

// Clear all scan history
function clearScanHistory() {
    if (confirm('Are you sure you want to clear all scan history? This cannot be undone.')) {
        scanHistory = [];
        localStorage.removeItem('guardmailScanHistory');
        displayScanHistory();
        showNotification('Scan history cleared', 'success');
    }
}

// Sample email for demonstration
const sampleEmails = {
    safe: `Dear Valued Customer,

Thank you for your recent purchase. Your order has been confirmed and will be shipped within 2-3 business days.

Order Details:
- Order ID: 12345678
- Total Amount: $99.99
- Delivery Address: 123 Main Street, City, State 12345

You will receive a tracking number via email once your package ships.

Best regards,
Customer Service Team
www.example.com`,

    suspicious: `URGENT: VERIFY YOUR ACCOUNT NOW!

Dear User,

We detected unusual activity on your account. Click here immediately to verify your identity and update your banking information.

CLICK HERE TO VERIFY: bit.ly/verifynow123

Congratulations! You've also won a $500 reward. Claim your prize now!

Act now - this offer expires in 24 hours!

Best regards,
Security Team`
};

// Load statistics from localStorage
function loadStatisticsFromStorage() {
    const stored = localStorage.getItem('guardmailStatistics');
    if (stored) {
        const data = JSON.parse(stored);
        statistics.totalEmails = data.totalEmails || 0;
        statistics.highRiskCount = data.highRiskCount || 0;
        statistics.mediumRiskCount = data.mediumRiskCount || 0;
        statistics.safeCount = data.safeCount || 0;
    }
}

// Save statistics to localStorage
function saveStatisticsToStorage() {
    localStorage.setItem('guardmailStatistics', JSON.stringify(statistics));
}

// Initialize dashboard display
function initializeDashboard() {
    loadStatisticsFromStorage();
    
    // Update dashboard elements
    if (dashboardElements.totalEmails) {
        dashboardElements.totalEmails.textContent = statistics.totalEmails;
    }
    if (dashboardElements.highRiskCount) {
        dashboardElements.highRiskCount.textContent = statistics.highRiskCount;
    }
    if (dashboardElements.mediumRiskCount) {
        dashboardElements.mediumRiskCount.textContent = statistics.mediumRiskCount;
    }
    if (dashboardElements.safeCount) {
        dashboardElements.safeCount.textContent = statistics.safeCount;
    }

    // Calculate and update percentages
    const total = statistics.totalEmails;
    if (total > 0) {
        const highRiskPercent = Math.round((statistics.highRiskCount / total) * 100);
        const mediumRiskPercent = Math.round((statistics.mediumRiskCount / total) * 100);
        const safePercent = Math.round((statistics.safeCount / total) * 100);

        if (dashboardElements.highRiskPercent) {
            dashboardElements.highRiskPercent.textContent = highRiskPercent + '%';
        }
        if (dashboardElements.mediumRiskPercent) {
            dashboardElements.mediumRiskPercent.textContent = mediumRiskPercent + '%';
        }
        if (dashboardElements.safePercent) {
            dashboardElements.safePercent.textContent = safePercent + '%';
        }

        // Update stat bar
        const totalEmailsCard = document.querySelector('#totalEmails').closest('.dashboard-card');
        const statBar = totalEmailsCard.querySelector('.stat-bar');
        if (statBar) {
            const barWidth = Math.min((total / 100) * 100, 100);
            statBar.style.width = barWidth + '%';
        }
    }
}

// Add demo functionality
window.loadSampleEmail = function(type) {
    emailContent.value = sampleEmails[type] || '';
    emailContent.focus();
    setTimeout(() => analyzeEmail(), 500);
};

// ============================================
// CHARTS & ANALYTICS FUNCTIONS
// ============================================

function initializeCharts() {
    // Initialize Threat Distribution Pie Chart
    const threatCtx = document.getElementById('threatDistributionChart');
    if (threatCtx && !threatDistributionChart) {
        threatDistributionChart = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['Phishing', 'Malware', 'Spoofing', 'Spam', 'Suspicious'],
                datasets: [{
                    data: [
                        chartData.threatCounts.phishing,
                        chartData.threatCounts.malware,
                        chartData.threatCounts.spoofing,
                        chartData.threatCounts.spam,
                        chartData.threatCounts.suspicious
                    ],
                    backgroundColor: [
                        '#ff6b6b',
                        '#ff006e',
                        '#ffa500',
                        '#4ecdc4',
                        '#95e1d3'
                    ],
                    borderColor: 'rgba(26, 31, 58, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                return label + ': ' + value + ' threats';
                            }
                        }
                    }
                }
            }
        });
    }

    // Initialize Risk Score Trend Chart
    const trendCtx = document.getElementById('riskScoreTrendChart');
    if (trendCtx && !riskScoreTrendChart) {
        riskScoreTrendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: chartData.timestamps.slice(-10),
                datasets: [{
                    label: 'Risk Score (%)',
                    data: chartData.riskScores.slice(-10),
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    borderWidth: 2,
                    pointBackgroundColor: '#00d4ff',
                    pointBorderColor: '#ffffff',
                    pointRadius: 5,
                    pointHoverRadius: 7,
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        labels: {
                            color: '#b0b8d4',
                            font: { size: 12, weight: '600' }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(10, 14, 39, 0.95)',
                        titleColor: '#00d4ff',
                        bodyColor: '#ffffff',
                        borderColor: '#00d4ff',
                        borderWidth: 1
                    }
                },
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        },
                        ticks: {
                            color: '#b0b8d4'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        },
                        ticks: {
                            color: '#b0b8d4'
                        }
                    }
                }
            }
        });
    }
}

function updateCharts(analysisResult) {
    const { score, riskLevel, detectedThreats } = analysisResult;

    // Update threat counts based on detected threats
    for (const threat of detectedThreats) {
        if (chartData.threatCounts.hasOwnProperty(threat.category)) {
            chartData.threatCounts[threat.category]++;
        }
    }

    // Add risk score to trend
    chartData.riskScores.push(Math.round(score));
    const now = new Date().toLocaleTimeString();
    chartData.timestamps.push(now);

    // Keep only last 10 scores for trend chart
    if (chartData.riskScores.length > 10) {
        chartData.riskScores.shift();
        chartData.timestamps.shift();
    }

    // Update charts
    if (threatDistributionChart) {
        threatDistributionChart.data.datasets[0].data = [
            chartData.threatCounts.phishing,
            chartData.threatCounts.malware,
            chartData.threatCounts.spoofing,
            chartData.threatCounts.spam,
            chartData.threatCounts.suspicious
        ];
        threatDistributionChart.update('active');
    }

    if (riskScoreTrendChart) {
        riskScoreTrendChart.data.labels = chartData.timestamps;
        riskScoreTrendChart.data.datasets[0].data = chartData.riskScores;
        riskScoreTrendChart.update('active');
    }
}

// ============================================
// PDF REPORT GENERATION
// ============================================

function generateSecurityReport(analysisResult) {
    const { jsPDF } = window.jspdf;
    if (!jsPDF) {
        showNotification('PDF library not loaded. Please refresh the page.', 'error');
        return;
    }

    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 15;
    let yPosition = 20;

    // Set colors
    const primaryColor = [0, 212, 255];
    const dangerColor = [255, 51, 102];
    const warningColor = [255, 170, 0];
    const darkBg = [26, 31, 58];

    // Header with background
    doc.setFillColor(darkBg[0], darkBg[1], darkBg[2]);
    doc.rect(0, 0, pageWidth, 40, 'F');

    // Title
    doc.setTextColor(0, 212, 255);
    doc.setFontSize(24);
    doc.setFont(undefined, 'bold');
    doc.text('🛡️ GUARDMAIL AI', margin, yPosition + 15);

    // Subtitle
    doc.setTextColor(176, 184, 212);
    doc.setFontSize(10);
    doc.setFont(undefined, 'normal');
    doc.text('Advanced Email Security Analysis Report', margin, yPosition + 25);

    yPosition += 45;

    // Report Info Section
    doc.setTextColor(0, 212, 255);
    doc.setFontSize(12);
    doc.setFont(undefined, 'bold');
    doc.text('REPORT INFORMATION', margin, yPosition);

    yPosition += 8;
    doc.setTextColor(176, 184, 212);
    doc.setFontSize(10);
    doc.setFont(undefined, 'normal');

    const reportDate = new Date().toLocaleString();
    doc.text(`Date & Time: ${reportDate}`, margin, yPosition);
    yPosition += 6;
    doc.text(`Analysis ID: ${Date.now()}`, margin, yPosition);

    yPosition += 12;

    // Risk Assessment Section
    doc.setTextColor(0, 212, 255);
    doc.setFontSize(12);
    doc.setFont(undefined, 'bold');
    doc.text('RISK ASSESSMENT', margin, yPosition);

    yPosition += 8;
    doc.setTextColor(176, 184, 212);
    doc.setFontSize(10);
    doc.setFont(undefined, 'normal');

    // Risk Score with color
    const { score, riskLevel, classification } = analysisResult;
    const riskLevelText = riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1);
    const riskColor = riskLevel === 'high' ? dangerColor : riskLevel === 'medium' ? warningColor : [0, 255, 136];

    doc.setTextColor(riskColor[0], riskColor[1], riskColor[2]);
    doc.setFont(undefined, 'bold');
    doc.text(`Risk Score: ${Math.round(score)}% (${riskLevelText})`, margin, yPosition);

    yPosition += 8;
    doc.setTextColor(176, 184, 212);
    doc.setFont(undefined, 'normal');
    doc.text(`Threat Category: ${classification.classification}`, margin, yPosition);
    yPosition += 6;
    doc.text(`Confidence Score: ${Math.round(classification.confidenceScore)}%`, margin, yPosition);

    yPosition += 12;

    // Threat Explanation Section
    doc.setTextColor(0, 212, 255);
    doc.setFontSize(12);
    doc.setFont(undefined, 'bold');
    doc.text('THREAT ANALYSIS', margin, yPosition);

    yPosition += 8;
    doc.setTextColor(176, 184, 212);
    doc.setFontSize(9);
    doc.setFont(undefined, 'normal');

    const explanationLines = doc.splitTextToSize(classification.explanation, pageWidth - 2 * margin);
    doc.text(explanationLines, margin, yPosition);
    yPosition += explanationLines.length * 5 + 4;

    yPosition += 4;

    // Security Recommendations Section
    doc.setTextColor(0, 212, 255);
    doc.setFontSize(12);
    doc.setFont(undefined, 'bold');
    doc.text('SECURITY RECOMMENDATIONS', margin, yPosition);

    yPosition += 8;
    doc.setTextColor(176, 184, 212);
    doc.setFontSize(9);
    doc.setFont(undefined, 'normal');

    const recommendations = recommendationsBase[riskLevel] || recommendationsBase.low;
    for (const rec of recommendations) {
        const recText = rec.replace(/^✓\s*/, '• ');
        const recLines = doc.splitTextToSize(recText, pageWidth - 2 * margin - 5);
        doc.text(recLines, margin + 5, yPosition);
        yPosition += recLines.length * 4;
    }

    yPosition += 8;

    // Footer
    doc.setTextColor(122, 130, 150);
    doc.setFontSize(8);
    doc.text('GuardMail AI - Enterprise Email Security Solution', pageWidth / 2, pageHeight - 10, { align: 'center' });
    doc.text(`Report generated: ${new Date().toISOString()}`, pageWidth / 2, pageHeight - 5, { align: 'center' });

    // Save PDF
    const filename = `GuardMail_Security_Report_${Date.now()}.pdf`;
    doc.save(filename);

    showNotification(`Security report downloaded: ${filename}`, 'success');
}

// ============================================
// EVENT INITIALIZATION
document.addEventListener('DOMContentLoaded', () => {
    console.log('GuardMail AI - Email Threat Analyzer initialized');
    console.log('Features: Advanced phishing detection, malware analysis, and security recommendations');
    initializeDOMElements();
    initializeDashboard();
    loadScanHistory();
});

// Add slideOutDown animation to stylesheet
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOutDown {
        to {
            opacity: 0;
            transform: translateY(20px);
        }
    }
`;
document.head.appendChild(style);
