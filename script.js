// ============================================
// GUARDMAIL AI - EMAIL THREAT ANALYZER
// Advanced JavaScript Logic for Email Security
// ============================================

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

// DOM Elements
const emailForm = document.getElementById('emailForm');
const emailContent = document.getElementById('emailContent');
const resultsContainer = document.getElementById('resultsContainer');
const riskCircle = document.getElementById('riskCircle');
const riskPercentage = document.getElementById('riskPercentage');
const riskBadge = document.getElementById('riskBadge');
const riskDetails = document.getElementById('riskDetails');
const threatsList = document.getElementById('threatsList');
const recommendationsList = document.getElementById('recommendationsList');

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

    return {
        score: totalScore,
        riskLevel: riskLevel,
        detectedThreats: detectedThreats,
        analysis: {
            urlCount,
            emailCount,
            urgencyLevel: urgencyKeywords > 0 ? 'High' : 'Normal',
            contentLength: emailLength
        }
    };
}

// ============================================
// UI UPDATE FUNCTIONS
// ============================================

function displayResults(analysisResult) {
    const { score, riskLevel, detectedThreats, analysis } = analysisResult;

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

    // Update Recommendations
    updateRecommendations(riskLevel);

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

emailForm.addEventListener('submit', (e) => {
    e.preventDefault();
    analyzeEmail();
});

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

// Add demo functionality
window.loadSampleEmail = function(type) {
    emailContent.value = sampleEmails[type] || '';
    emailContent.focus();
    setTimeout(() => analyzeEmail(), 500);
};

// Initialize with fade-in animation
document.addEventListener('DOMContentLoaded', () => {
    console.log('GuardMail AI - Email Threat Analyzer initialized');
    console.log('Features: Advanced phishing detection, malware analysis, and security recommendations');
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
