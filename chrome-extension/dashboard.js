// ShadowLens Dashboard JavaScript for Chrome Extension
let websiteData = [];
let filteredData = [];

// Initialize dashboard with comprehensive error handling
document.addEventListener('DOMContentLoaded', function() {
    try {
        console.log('🔒 ShadowLens Dashboard: Initializing...');
        loadDashboardData();
        setupEventListeners();
    } catch (error) {
        console.error('Critical error in dashboard initialization:', error);
        showNoDataMessage();
    }
});

function setupEventListeners() {
    try {
        // Search functionality
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                try {
                    filterWebsites();
                } catch (error) {
                    console.error('Error in search input handler:', error);
                }
            });
        }

        // Filter buttons
        const filterButtons = document.querySelectorAll('.filter-btn');
        filterButtons.forEach(button => {
            button.addEventListener('click', function() {
                try {
                    // Remove active class from all buttons
                    filterButtons.forEach(btn => {
                        try {
                            btn.classList.remove('active');
                        } catch (error) {
                            console.error('Error removing active class:', error);
                        }
                    });
                    // Add active class to clicked button
                    this.classList.add('active');
                    filterWebsites();
                } catch (error) {
                    console.error('Error in filter button handler:', error);
                }
            });
        });
    } catch (error) {
        console.error('Error setting up event listeners:', error);
    }
}

function loadDashboardData() {
    try {
        console.log('📊 Loading dashboard data from Chrome storage...');
        
        // Check if chrome.storage is available
        if (typeof chrome === 'undefined' || !chrome.storage) {
            console.error('Chrome storage not available');
            showNoDataMessage();
            return;
        }
        
        // Load from Chrome storage
        chrome.storage.local.get(['websiteHistory'], function(result) {
            try {
                if (chrome.runtime.lastError) {
                    console.error('Error loading from storage:', chrome.runtime.lastError);
                    showNoDataMessage();
                    return;
                }
                
                const history = result.websiteHistory || [];
                console.log('✅ Dashboard data loaded:', history.length, 'entries');
                
                if (history.length > 0) {
                    websiteData = history;
                    updateDashboard();
                } else {
                    console.warn('No website history found');
                    showNoDataMessage();
                }
            } catch (error) {
                console.error('Error processing dashboard data:', error);
                showNoDataMessage();
            }
        });
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showNoDataMessage();
    }
}

function updateDashboard() {
    try {
        console.log('🔄 Updating dashboard with', websiteData.length, 'websites');
        
        // Update statistics
        updateStatistics();
        
        // Update risk distribution chart
        updateRiskDistribution();
        
        // Display websites
        displayWebsites();
    } catch (error) {
        console.error('Error updating dashboard:', error);
        showNoDataMessage();
    }
}

function updateStatistics() {
    try {
        const totalWebsites = websiteData.length;
        const avgRisk = totalWebsites > 0 ? 
            (websiteData.reduce((sum, site) => sum + (site.riskScore || 0), 0) / totalWebsites).toFixed(1) : 0;
        const highRiskSites = websiteData.filter(site => (site.riskScore || 0) >= 6).length;
        const totalThreats = websiteData.reduce((sum, site) => sum + (site.privacyThreats ? site.privacyThreats.length : 0), 0);

        // Update stat cards
        updateElement('total-websites', totalWebsites);
        updateElement('avg-risk', avgRisk);
        updateElement('high-risk', highRiskSites);
        updateElement('total-threats', totalThreats);
    } catch (error) {
        console.error('Error updating statistics:', error);
    }
}

function updateRiskDistribution() {
    try {
        const safeCount = websiteData.filter(site => (site.riskScore || 0) <= 3).length;
        const moderateCount = websiteData.filter(site => (site.riskScore || 0) > 3 && (site.riskScore || 0) <= 5).length;
        const cautionCount = websiteData.filter(site => (site.riskScore || 0) > 5 && (site.riskScore || 0) <= 7).length;
        const dangerousCount = websiteData.filter(site => (site.riskScore || 0) > 7).length;

        updateElement('safe-count', safeCount);
        updateElement('moderate-count', moderateCount);
        updateElement('caution-count', cautionCount);
        updateElement('dangerous-count', dangerousCount);
    } catch (error) {
        console.error('Error updating risk distribution:', error);
    }
}

function displayWebsites() {
    try {
        const container = document.getElementById('websites-container');
        if (!container) {
            console.error('Websites container not found');
            return;
        }

        if (websiteData.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <p>No website analyses found</p>
                    <p>Start analyzing websites to see data here</p>
                </div>
            `;
            return;
        }

        // Apply current filters
        filterWebsites();
    } catch (error) {
        console.error('Error displaying websites:', error);
        showNoDataMessage();
    }
}

function filterWebsites() {
    try {
        const searchInput = document.getElementById('search-input');
        const activeFilterElement = document.querySelector('.filter-btn.active');
        
        const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        const activeFilter = activeFilterElement ? activeFilterElement.dataset.filter : 'all';

        console.log('🔍 Filtering websites:', { searchTerm, activeFilter });

        filteredData = websiteData.filter(site => {
            try {
                // Search filter
                const matchesSearch = !searchTerm || 
                    (site.url && site.url.toLowerCase().includes(searchTerm)) ||
                    (site.websiteType && site.websiteType.toLowerCase().includes(searchTerm));

                // Risk filter
                let matchesRisk = true;
                const riskScore = site.riskScore || 0;
                
                switch (activeFilter) {
                    case 'safe':
                        matchesRisk = riskScore <= 3;
                        break;
                    case 'moderate':
                        matchesRisk = riskScore > 3 && riskScore <= 5;
                        break;
                    case 'caution':
                        matchesRisk = riskScore > 5 && riskScore <= 7;
                        break;
                    case 'dangerous':
                        matchesRisk = riskScore > 7;
                        break;
                    default: // 'all'
                        matchesRisk = true;
                }

                return matchesSearch && matchesRisk;
            } catch (filterError) {
                console.error('Error filtering site:', filterError);
                return false;
            }
        });

        renderWebsites();
    } catch (error) {
        console.error('Error filtering websites:', error);
        showNoDataMessage();
    }
}

function renderWebsites() {
    try {
        const container = document.getElementById('websites-container');
        if (!container) {
            console.error('Websites container not found');
            return;
        }

        if (filteredData.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <p>No websites match the current filters</p>
                    <p>Try adjusting your search or filter criteria</p>
                </div>
            `;
            return;
        }

        const websitesHTML = filteredData.map(site => {
            try {
                return createWebsiteCard(site);
            } catch (cardError) {
                console.error('Error creating website card:', cardError);
                return '';
            }
        }).join('');
        
        container.innerHTML = `
            <div class="websites-grid">
                ${websitesHTML}
            </div>
        `;
    } catch (error) {
        console.error('Error rendering websites:', error);
        showNoDataMessage();
    }
}

function createWebsiteCard(site) {
    try {
        if (!site) {
            console.error('Invalid site data');
            return '';
        }

        const riskScore = site.riskScore || 0;
        const riskLevel = getRiskLevel(riskScore);
        const riskClass = `risk-${riskLevel.toLowerCase()}`;
        
        const timestamp = site.timestamp ? new Date(site.timestamp).toLocaleString() : 'Unknown';
        const threats = site.privacyThreats || [];
        const forms = site.forms || 0;
        const sensitiveFields = site.sensitiveFields || 0;
        const websiteType = site.websiteType || 'general';

        return `
            <div class="website-card">
                <div class="website-header">
                    <div class="website-url">${truncateUrl(site.url)}</div>
                    <div class="risk-badge ${riskClass}">${riskLevel}</div>
                </div>
                
                <div class="website-details">
                    <div class="detail-row">
                        <span class="detail-label">Risk Score:</span>
                        <span>${riskScore}/10</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Website Type:</span>
                        <span>${formatWebsiteType(websiteType)}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Forms:</span>
                        <span>${forms} (${sensitiveFields} sensitive)</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Threats:</span>
                        <span>${threats.length}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Analyzed:</span>
                        <span>${timestamp}</span>
                    </div>
                </div>
                
                ${threats.length > 0 ? `
                    <div class="threats-list">
                        <strong>Privacy Threats:</strong>
                        ${threats.slice(0, 3).map(threat => `
                            <div class="threat-item">${threat}</div>
                        `).join('')}
                        ${threats.length > 3 ? `<div class="threat-item">... and ${threats.length - 3} more</div>` : ''}
                    </div>
                ` : ''}
            </div>
        `;
    } catch (error) {
        console.error('Error creating website card:', error);
        return '';
    }
}

function getRiskLevel(riskScore) {
    try {
        const score = parseInt(riskScore) || 0;
        if (score <= 3) return 'Safe';
        if (score <= 5) return 'Moderate';
        if (score <= 7) return 'Caution';
        return 'Dangerous';
    } catch (error) {
        console.error('Error getting risk level:', error);
        return 'Unknown';
    }
}

function formatWebsiteType(type) {
    try {
        const types = {
            'educational': 'Educational',
            'social_media': 'Social Media',
            'financial': 'Financial',
            'ecommerce': 'E-commerce',
            'general': 'General'
        };
        return types[type] || type || 'General';
    } catch (error) {
        console.error('Error formatting website type:', error);
        return 'General';
    }
}

function truncateUrl(url) {
    try {
        if (!url) return 'Unknown URL';
        const urlString = String(url);
        if (urlString.length <= 50) return urlString;
        return urlString.substring(0, 47) + '...';
    } catch (error) {
        console.error('Error truncating URL:', error);
        return 'Unknown URL';
    }
}

function updateElement(id, value) {
    try {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    } catch (error) {
        console.error('Error updating element:', error);
    }
}

function showNoDataMessage() {
    try {
        const container = document.getElementById('websites-container');
        if (container) {
            container.innerHTML = `
                <div class="no-data">
                    <p>No analysis data available</p>
                    <p>Start analyzing websites to see data here</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error showing no data message:', error);
    }
}

function goBack() {
    try {
        // Close the dashboard tab and return to the extension popup
        window.close();
    } catch (error) {
        console.error('Error going back:', error);
        // Fallback: try to navigate back
        try {
            window.history.back();
        } catch (fallbackError) {
            console.error('Error in fallback navigation:', fallbackError);
        }
    }
}

// Auto-refresh data every 30 seconds with error handling
let refreshInterval;
try {
    refreshInterval = setInterval(() => {
        try {
            console.log('🔄 Auto-refreshing dashboard data...');
            loadDashboardData();
        } catch (error) {
            console.error('Error in auto-refresh:', error);
        }
    }, 30000);
} catch (error) {
    console.error('Error setting up auto-refresh:', error);
}

console.log('🔒 ShadowLens Dashboard: Ready!'); 