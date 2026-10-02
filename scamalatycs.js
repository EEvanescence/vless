const HTML_PAGE = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Scamalytics IP Checker - API & Fraud Risk Score Analysis</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        body {
            font-family: 'Inter', sans-serif;
            overflow-x: hidden;
            width: 100%;
        }
        
        .risk-low {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        }
        
        .risk-medium {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        }
        
        .risk-high {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        }
        
        .risk-very-high {
            background: linear-gradient(135deg, #991b1b 0%, #7f1d1d 100%);
        }
        
        .loading {
            border: 4px solid #f3f4f6;
            border-top: 4px solid #3b82f6;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen">
    <div class="w-full max-w-4xl mx-auto px-3 sm:px-4 py-6 sm:py-8 box-border">
        <div class="text-center mb-6 sm:mb-8">
            <h1 class="text-3xl sm:text-4xl font-bold text-gray-800 mb-2">Scamalytics IP Checker</h1>
            <p class="text-sm sm:text-base text-gray-600">Check IP Fraud Risk & Score Analysis</p>
        </div>

        <div class="mb-6">
            <div class="flex gap-2 bg-white rounded-xl shadow-lg p-1.5 sm:p-2">
                <button id="tabScamalyticsBtn" onclick="switchTab('scamalytics')" class="flex-1 py-2 px-2 sm:px-4 text-xs sm:text-sm md:text-base rounded-lg font-semibold transition-colors bg-blue-600 text-white">
                    Scamalytics IP Check
                </button>
                <button id="tabCheckhostBtn" onclick="switchTab('checkhost')" class="flex-1 py-2 px-2 sm:px-4 text-xs sm:text-sm md:text-base rounded-lg font-semibold transition-colors text-gray-600 hover:bg-gray-100">
                    Check-Host Network Test
                </button>
            </div>
        </div>

        <div id="scamalyticsPanel">

        <div class="bg-white rounded-2xl shadow-xl p-4 sm:p-6 mb-6 sm:mb-8">
            <div class="flex flex-col sm:flex-row gap-3 sm:gap-4">
                <input 
                    type="text" 
                    id="ipInput" 
                    placeholder="Enter IPv4, IPv6 or domain, e.g. 8.8.8.8, 2606:4700:4700::1111, example.com"
                    class="w-full flex-1 px-3 sm:px-4 py-2.5 sm:py-3 text-sm sm:text-base border-2 border-gray-300 rounded-lg focus:outline-none focus:border-blue-500 transition-colors"
                />
                <button 
                    onclick="checkIP()" 
                    id="checkBtn"
                    class="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6 sm:px-8 py-2.5 sm:py-3 rounded-lg transition-all text-sm sm:text-base transform active:scale-95">
                    Check
                </button>
            </div>
            <p class="text-xs sm:text-sm text-gray-500 mt-3">You can also use URL parameters: ?ip=8.8.8.8, ?ip=2606:4700:4700::1111 (IPv6, brackets like [::1] are also accepted) or ?domain=example.com</p>
            <p class="text-xs sm:text-sm text-blue-600 mt-2 break-words">API Endpoints: <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs">/8.8.8.8</code>, <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs">/api/domain/example.com</code> (full risk check)</p>
        </div>

        <div id="loading" class="hidden text-center py-12">
            <div class="loading mx-auto mb-4"></div>
            <p class="text-gray-600 text-sm sm:text-base">Fetching data...</p>
        </div>

        <div id="error" class="hidden bg-red-50 border-2 border-red-200 rounded-2xl p-4 sm:p-6 mb-6 sm:mb-8 fade-in">
            <div class="flex items-center gap-3">
                <span class="text-2xl sm:text-3xl">&#9888;&#65039;</span>
                <div class="break-words flex-1">
                    <h3 class="font-bold text-red-800 text-sm sm:text-base">Error Fetching Data</h3>
                    <p id="errorMessage" class="text-red-600 text-xs sm:text-sm mt-1"></p>
                </div>
            </div>
        </div>

        <div id="results" class="hidden fade-in">
            <div id="scoreCard" class="rounded-2xl shadow-xl p-6 sm:p-8 mb-6 text-white">
                <div class="text-center">
                    <h2 class="text-lg sm:text-xl font-semibold mb-2">Fraud Score</h2>
                    <div class="text-6xl sm:text-7xl font-bold mb-2" id="fraudScore">-</div>
                    <div class="text-xl sm:text-2xl font-semibold" id="riskLevel">-</div>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6 mb-6">
                <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                    <h3 class="font-bold text-base sm:text-lg mb-4 text-gray-800 flex items-center gap-2">
                        <span>&#127760;</span> IP Information
                    </h3>
                    <div class="space-y-3 text-sm sm:text-base">
                        <div class="flex justify-between border-b pb-2">
                            <span class="text-gray-600">IP Address:</span>
                            <span class="font-semibold break-all text-right" id="ipAddress">-</span>
                        </div>
                        <div class="flex justify-between border-b pb-2">
                            <span class="text-gray-600">Country:</span>
                            <span class="font-semibold text-right" id="country">-</span>
                        </div>
                        <div class="flex justify-between border-b pb-2">
                            <span class="text-gray-600">City:</span>
                            <span class="font-semibold text-right" id="city">-</span>
                        </div>
                        <div class="flex justify-between items-start gap-2">
                            <span class="text-gray-600 shrink-0">ISP:</span>
                            <span class="font-semibold text-xs sm:text-sm text-right break-words" id="isp">-</span>
                        </div>
                    </div>
                </div>

                <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                    <h3 class="font-bold text-base sm:text-lg mb-4 text-gray-800 flex items-center gap-2">
                        <span>&#9889;</span> Risk Factors
                    </h3>
                    <div class="space-y-3 text-sm sm:text-base" id="riskFactors">
                    </div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <h3 class="font-bold text-base sm:text-lg mb-4 text-gray-800 flex items-center gap-2">
                    <span>&#128202;</span> Additional Information
                </h3>
                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 sm:gap-4" id="additionalInfo">
                </div>
            </div>
        </div>

        <div id="domainResults" class="hidden fade-in">
            <div class="bg-white rounded-2xl shadow-xl p-4 sm:p-6 mb-4">
                <h2 class="text-lg sm:text-xl font-bold text-gray-800 mb-1">Domain: <span id="domainName" class="text-blue-600 break-all"></span></h2>
                <p class="text-xs sm:text-sm text-gray-500"><span id="domainIpCount">0</span> IP address(es) resolved. Each one is checked separately below.</p>
            </div>
            <div id="domainResultsList" class="space-y-4"></div>
        </div>

        </div>

        <div id="checkhostPanel" class="hidden">

            <div class="bg-white rounded-2xl shadow-xl p-4 sm:p-6 mb-6 sm:mb-8">
                <div class="flex flex-col sm:flex-row gap-3 sm:gap-4 mb-4">
                    <input
                        type="text"
                        id="chHostInput"
                        placeholder="Host, domain or IP (e.g. example.com)"
                        class="w-full flex-1 px-3 sm:px-4 py-2.5 sm:py-3 text-sm sm:text-base border-2 border-gray-300 rounded-lg focus:outline-none focus:border-purple-500 transition-colors"
                    />
                    <button
                        onclick="chRunCheck()"
                        id="chCheckBtn"
                        class="w-full sm:w-auto bg-purple-600 hover:bg-purple-700 text-white font-semibold px-6 sm:px-8 py-2.5 sm:py-3 rounded-lg transition-all text-sm sm:text-base transform active:scale-95">
                        Run Check
                    </button>
                </div>
                <p class="text-xs sm:text-sm text-purple-600 mb-2 break-words">API Endpoint: <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs">/checkhost/ping/us/example.com</code> (type is optional and defaults to "ping": <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs">/checkhost/us/example.com</code> still works)</p>

                <div class="pt-1 pb-3">
                    <h3 class="font-semibold text-sm sm:text-base text-gray-700 mb-2">Check Type</h3>
                    <div id="chTypeButtons" class="flex flex-wrap gap-2"></div>
                </div>

                <div class="pt-2">
                    <div class="flex justify-between items-center mb-2">
                        <h3 class="font-semibold text-sm sm:text-base text-gray-700">Countries</h3>
                        <button onclick="chResetNodeSelection()" class="text-xs px-2.5 py-1 bg-gray-100 hover:bg-gray-200 rounded-lg text-gray-600">Reset</button>
                    </div>
                    <p class="text-xs text-gray-400 mb-3">Pick one or more countries — each one is checked from every check-host.net node in that country.</p>

                    <div class="relative">
                        <button
                            type="button"
                            id="chCountryDropdownBtn"
                            onclick="chToggleCountryDropdown()"
                            class="w-full flex justify-between items-center px-3 sm:px-4 py-2.5 sm:py-3 text-sm sm:text-base border-2 border-gray-300 rounded-lg focus:outline-none focus:border-purple-500 transition-colors bg-white text-left">
                            <span id="chCountryDropdownLabel" class="text-gray-500 truncate mr-2">Select countries...</span>
                            <span class="text-gray-400 shrink-0">&#9662;</span>
                        </button>
                        <div id="chCountryDropdownPanel" class="hidden absolute left-0 right-0 mt-1 bg-white border-2 border-gray-300 rounded-lg shadow-xl z-30 max-w-full">
                            <input
                                type="text"
                                id="chCountrySearch"
                                placeholder="Search countries..."
                                oninput="chFilterCountryOptions()"
                                class="w-full px-3 py-2 border-b-2 border-gray-200 rounded-t-lg focus:outline-none text-xs sm:text-sm" />
                            <div id="chCountryOptionsList" class="max-h-48 sm:max-h-56 overflow-y-auto"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="chLoading" class="hidden text-center py-12">
                <div class="loading mx-auto mb-4"></div>
                <p class="text-gray-600 text-sm sm:text-base">Running check...</p>
            </div>

            <div id="chError" class="hidden bg-red-50 border-2 border-red-200 rounded-2xl p-4 sm:p-6 mb-6 sm:mb-8 fade-in">
                <div class="flex items-center gap-3">
                    <span class="text-2xl sm:text-3xl">&#9888;&#65039;</span>
                    <div class="break-words flex-1">
                        <h3 class="font-bold text-red-800 text-sm sm:text-base">Error Running Check</h3>
                        <p id="chErrorMessage" class="text-red-600 text-xs sm:text-sm mt-1"></p>
                    </div>
                </div>
            </div>

            <div id="chResults" class="hidden fade-in bg-white rounded-2xl shadow-xl p-4 sm:p-6">
                <h3 class="font-bold text-base sm:text-lg mb-4 text-gray-800">Results</h3>
                <div class="w-full overflow-hidden">
                    <div id="chResultsList" class="space-y-4"></div>
                </div>
            </div>

        </div>

    </div>

    <script>
        window.addEventListener('DOMContentLoaded', () => {
            const urlParams = new URLSearchParams(window.location.search);
            const paramIP = urlParams.get('ip');
            const paramDomain = urlParams.get('domain');

            if (paramIP) {
                document.getElementById('ipInput').value = stripIPBrackets(paramIP);
                checkIP();
            } else if (paramDomain) {
                document.getElementById('ipInput').value = paramDomain;
                checkIP();
            }
        });

        document.getElementById('ipInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                checkIP();
            }
        });

async function checkIP() {
            const typedInput = document.getElementById('ipInput').value.trim();

            if (!typedInput) {
                showError('Please enter an IP address or domain');
                return;
            }

            // Accepts pasted "[2606:4700:4700::1111]" / "[::1]:443" forms
            // too, not just bare addresses.
            const cleanedInput = stripIPBrackets(typedInput);
            const inputIsIP = isValidIP(cleanedInput);
            const inputIsDomain = !inputIsIP && isValidDomain(cleanedInput);

            if (!inputIsIP && !inputIsDomain) {
                showError('Invalid IP address or domain format');
                return;
            }

            // Canonical form for IPv6 so the URL, the API call, and the
            // cache key all agree regardless of how the address was typed.
            const rawInput = inputIsIP ? normalizeIP(cleanedInput) : cleanedInput;

            const url = new URL(window.location);
            if (inputIsIP) {
                url.searchParams.delete('domain');
                url.searchParams.set('ip', rawInput);
            } else {
                url.searchParams.delete('ip');
                url.searchParams.set('domain', rawInput);
            }
            window.history.pushState({}, '', url);

            showLoading();

            try {
                if (inputIsIP) {
                    const response = await fetch('/api/' + encodeURIComponent(rawInput));
                    const data = await response.json();

                    if (!response.ok || data.error) {
                        throw new Error(data.message || 'Failed to fetch data');
                    }

                    displayResults({
                        ip: data.info.ip,
                        fraudScore: data.info.fraud_score,
                        riskLevel: translateRiskFromEnglish(data.info.risk),
                        details: {
                            'Country Name': (data.details.country || '-') + ' ' + (data.details.flag || ''),
                            'Country Code': data.details.country_code || '-',
                            'City': data.details.city || '-',
                            'ISP': data.details.isp || '-',
                            'ISP Name': data.details.isp || '-',
                            'Organization Name': data.details.organization || '-',
                            'Hostname': data.details.hostname || '-',
                            'ASN': data.details.asn || '-',
                            'State / Province': data.details.state || '-',
                            'Postal Code': data.details.postal_code || '-',
                            'Datacenter': data.details.datacenter || '-',
                            'Anonymizing VPN': data.details.vpn || '-',
                            'Tor Exit Node': data.details.tor || '-',
                            'Public Proxy': data.details.proxy || '-',
                            'Server': data.details.server || '-',
                            'Web Proxy': data.details.web_proxy || '-'
                        }
                    });
                } else {
                    const resolveRes = await fetch('/api/' + encodeURIComponent(rawInput));
                    const resolveData = await resolveRes.json();

                    if (!resolveData.success || !resolveData.groups || resolveData.groups.length === 0) {
                        throw new Error(resolveData.message || 'No IP addresses found for this domain');
                    }

                    document.getElementById('loading').classList.add('hidden');
                    document.getElementById('error').classList.add('hidden');
                    document.getElementById('results').classList.add('hidden');
                    document.getElementById('domainResults').classList.remove('hidden');
                    document.getElementById('domainName').textContent = rawInput;
                    document.getElementById('domainIpCount').textContent = '0 / ' + resolveData.total_ips;
                    document.getElementById('domainResultsList').innerHTML = '';

                    let totalLoaded = 0;

                    for (let g = 0; g < resolveData.groups.length; g++) {
                        const groupIps = resolveData.groups[g];

                        const batchRes = await fetch('/api/check-ips', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ ips: groupIps })
                        });

                        const batchData = await batchRes.json();
                        if (batchData.success && batchData.results) {
                            appendDomainResults(batchData.results);
                            totalLoaded += batchData.results.length;
                            document.getElementById('domainIpCount').textContent = totalLoaded + ' / ' + resolveData.total_ips;
                        }
                    }
                }

            } catch (error) {
                console.error('Error:', error);
                showError(error.message || 'Error fetching data. Please try again.');
            }
        }

        function appendDomainResults(results) {
            const listDiv = document.getElementById('domainResultsList');

            results.forEach(item => {
                if (item.error) {
                    listDiv.innerHTML += \`
                        <div class="bg-red-50 border-2 border-red-200 rounded-xl p-3 sm:p-4">
                            <p class="font-semibold text-red-700 text-sm break-all">\${item.ip || 'Unknown IP'}</p>
                            <p class="text-xs text-red-500 mt-1">\${item.message || 'Failed to fetch data for this IP'}</p>
                        </div>
                    \`;
                    return;
                }

                const score = item.fraud_score || 0;
                let riskClass = 'risk-low';
                if (score > 75) riskClass = 'risk-very-high';
                else if (score > 50) riskClass = 'risk-high';
                else if (score > 25) riskClass = 'risk-medium';

                const details = item.details || {};
                const country = ((details.country || '-') + ' ' + (details.flag || '')).trim();
                const isp = details.isp || details.organization || '-';

                listDiv.innerHTML += \`
                    <div class="bg-white rounded-xl shadow-lg overflow-hidden border border-gray-100 mb-3">
                        <div class="flex flex-col sm:flex-row">
                            <div class="\${riskClass} text-white p-3 sm:p-4 sm:w-36 flex flex-col items-center justify-center text-center">
                                <div class="text-2xl sm:text-3xl font-bold">\${score}</div>
                                <div class="text-xs opacity-90">\${translateRiskFromEnglish(item.risk)}</div>
                            </div>
                            <div class="p-3 sm:p-4 flex-1 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-xs sm:text-sm">
                                <div class="break-all"><span class="text-gray-500">IP:</span> <span class="font-semibold">\${item.ip}\${ipVersionBadge(item.ip)}</span></div>
                                <div class="truncate"><span class="text-gray-500">Country:</span> <span class="font-semibold">\${country}</span></div>
                                <div class="truncate"><span class="text-gray-500">ISP:</span> <span class="font-semibold">\${isp}</span></div>
                                <div><span class="text-gray-500">VPN:</span> <span class="font-semibold">\${details.vpn || '-'}</span></div>
                                <div><span class="text-gray-500">Tor:</span> <span class="font-semibold">\${details.tor || '-'}</span></div>
                                <div><span class="text-gray-500">Datacenter:</span> <span class="font-semibold">\${details.datacenter || '-'}</span></div>
                            </div>
                        </div>
                    </div>
                \`;
            });
        }

        function translateRiskFromEnglish(englishRisk) {
            const translations = {
                'very_low': 'Very Low Risk',
                'low': 'Low Risk',
                'medium': 'Medium Risk',
                'high': 'High Risk',
                'very_high': 'Very High Risk',
                'unknown': 'Unknown'
            };
            return translations[englishRisk] || englishRisk;
        }

        // Small "IPv4"/"IPv6" chip shown next to an address so mixed
        // results (e.g. a domain with both A and AAAA records) are easy
        // to tell apart at a glance.
        function ipVersionBadge(ip) {
            const version = getIPVersion(ip);
            if (!version) return '';
            const color = version === 6 ? 'bg-indigo-100 text-indigo-700' : 'bg-sky-100 text-sky-700';
            return \`<span class="inline-block \${color} text-[10px] font-bold px-1.5 py-0.5 rounded ml-1.5 align-middle">IPv\${version}</span>\`;
        }

        function displayResults(data) {
            document.getElementById('loading').classList.add('hidden');
            document.getElementById('error').classList.add('hidden');
            document.getElementById('domainResults').classList.add('hidden');
            
            const resultsDiv = document.getElementById('results');
            resultsDiv.classList.remove('hidden');

            const scoreCard = document.getElementById('scoreCard');
            if (data.fraudScore <= 25) {
                scoreCard.className = 'rounded-2xl shadow-xl p-6 sm:p-8 mb-6 text-white risk-low';
            } else if (data.fraudScore <= 50) {
                scoreCard.className = 'rounded-2xl shadow-xl p-6 sm:p-8 mb-6 text-white risk-medium';
            } else if (data.fraudScore <= 75) {
                scoreCard.className = 'rounded-2xl shadow-xl p-6 sm:p-8 mb-6 text-white risk-high';
            } else {
                scoreCard.className = 'rounded-2xl shadow-xl p-6 sm:p-8 mb-6 text-white risk-very-high';
            }

            document.getElementById('fraudScore').textContent = data.fraudScore;
            document.getElementById('riskLevel').textContent = data.riskLevel;

            document.getElementById('ipAddress').innerHTML = data.ip + ipVersionBadge(data.ip);
            document.getElementById('country').textContent = data.details['Country Name'] || '-';
            document.getElementById('city').textContent = data.details['City'] || '-';
            document.getElementById('isp').textContent = data.details['ISP Name'] || data.details['ISP'] || data.details['Organization Name'] || '-';

            const riskFactorsDiv = document.getElementById('riskFactors');
            riskFactorsDiv.innerHTML = '';
            
            const factorsToShow = [
                { key: 'Anonymizing VPN', icon: '&#128274;' },
                { key: 'Tor Exit Node', icon: '&#129437;' },
                { key: 'Server', icon: '&#128421;&#65039;' },
                { key: 'Public Proxy', icon: '&#127760;' },
                { key: 'Web Proxy', icon: '&#128257;' },
                { key: 'Datacenter', icon: '&#127970;' }
            ];

            factorsToShow.forEach(factor => {
                const value = data.details[factor.key] || 'No';
                const isYes = value.toLowerCase() === 'yes';
                const isUnknown = value.toLowerCase() === 'unknown';
                riskFactorsDiv.innerHTML += \`
                    <div class="flex justify-between items-center border-b pb-2">
                        <span class="text-gray-600 text-xs sm:text-sm">\${factor.icon} \${factor.key}:</span>
                        <span class="font-semibold text-xs sm:text-sm \${isYes ? 'text-red-600' : isUnknown ? 'text-orange-600' : 'text-green-600'}">
                            \${value}
                        </span>
                    </div>
                \`;
            });

            const additionalInfoDiv = document.getElementById('additionalInfo');
            additionalInfoDiv.innerHTML = '';
            
            const additionalFields = [
                'Country Code', 
                'State / Province', 
                'Postal Code', 
                'Hostname', 
                'ASN', 
                'Organization Name'
            ];
            
            additionalFields.forEach(field => {
                if (data.details[field] && data.details[field] !== '-') {
                    additionalInfoDiv.innerHTML += \`
                        <div class="bg-gray-50 rounded-lg p-2.5 sm:p-3">
                            <div class="text-xs text-gray-500 mb-1">\${field}</div>
                            <div class="font-semibold text-gray-800 text-xs sm:text-sm break-words">\${data.details[field]}</div>
                        </div>
                    \`;
                }
            });
        }

        function displayDomainResults(domain, results) {
            document.getElementById('loading').classList.add('hidden');
            document.getElementById('error').classList.add('hidden');
            document.getElementById('results').classList.add('hidden');

            document.getElementById('domainResults').classList.remove('hidden');
            document.getElementById('domainName').textContent = domain;
            document.getElementById('domainIpCount').textContent = results.length;

            const listDiv = document.getElementById('domainResultsList');
            listDiv.innerHTML = '';

            results.forEach(item => {
                if (item.error) {
                    listDiv.innerHTML += \`
                        <div class="bg-red-50 border-2 border-red-200 rounded-xl p-3 sm:p-4">
                            <p class="font-semibold text-red-700 text-sm break-all">\${item.ip || 'Unknown IP'}</p>
                            <p class="text-xs text-red-500 mt-1">\${item.message || 'Failed to fetch data for this IP'}</p>
                        </div>
                    \`;
                    return;
                }

                const score = item.fraud_score || 0;
                let riskClass = 'risk-low';
                if (score > 75) riskClass = 'risk-very-high';
                else if (score > 50) riskClass = 'risk-high';
                else if (score > 25) riskClass = 'risk-medium';

                const details = item.details || {};
                const country = ((details.country || '-') + ' ' + (details.flag || '')).trim();
                const isp = details.isp || details.organization || '-';

                listDiv.innerHTML += \`
                    <div class="bg-white rounded-xl shadow-lg overflow-hidden border border-gray-100">
                        <div class="flex flex-col sm:flex-row">
                            <div class="\${riskClass} text-white p-3 sm:p-4 sm:w-36 flex flex-col items-center justify-center text-center">
                                <div class="text-2xl sm:text-3xl font-bold">\${score}</div>
                                <div class="text-xs opacity-90">\${translateRiskFromEnglish(item.risk)}</div>
                            </div>
                            <div class="p-3 sm:p-4 flex-1 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-xs sm:text-sm">
                                <div class="break-all"><span class="text-gray-500">IP:</span> <span class="font-semibold">\${item.ip}\${ipVersionBadge(item.ip)}</span></div>
                                <div class="truncate"><span class="text-gray-500">Country:</span> <span class="font-semibold">\${country}</span></div>
                                <div class="truncate"><span class="text-gray-500">ISP:</span> <span class="font-semibold">\${isp}</span></div>
                                <div><span class="text-gray-500">VPN:</span> <span class="font-semibold">\${details.vpn || '-'}</span></div>
                                <div><span class="text-gray-500">Tor:</span> <span class="font-semibold">\${details.tor || '-'}</span></div>
                                <div><span class="text-gray-500">Datacenter:</span> <span class="font-semibold">\${details.datacenter || '-'}</span></div>
                            </div>
                        </div>
                    </div>
                \`;
            });
        }

        function showLoading() {
            document.getElementById('results').classList.add('hidden');
            document.getElementById('domainResults').classList.add('hidden');
            document.getElementById('error').classList.add('hidden');
            document.getElementById('loading').classList.remove('hidden');
        }

        function showError(message) {
            document.getElementById('loading').classList.add('hidden');
            document.getElementById('results').classList.add('hidden');
            document.getElementById('domainResults').classList.add('hidden');
            document.getElementById('error').classList.remove('hidden');
            document.getElementById('errorMessage').textContent = message;
        }

        function isValidIP(ip) {
            return isValidIPv4(ip) || isValidIPv6(ip);
        }

        // Strips a "[addr]" / "[addr]:port" wrapper and a trailing
        // "%zoneId" so pasted URLs/link-local addresses still validate.
        function stripIPBrackets(input) {
            let s = (input || '').trim();
            if (s.startsWith('[')) {
                const end = s.indexOf(']');
                if (end !== -1) {
                    const host = s.slice(1, end);
                    const rest = s.slice(end + 1);
                    if (!rest || rest.startsWith(':')) {
                        s = host;
                    }
                }
            }
            if (s.includes(':')) {
                const zoneIdx = s.indexOf('%');
                if (zoneIdx !== -1) s = s.slice(0, zoneIdx);
            }
            return s;
        }

        function expandIPv6(ip) {
            let addr = ip;
            const ipv4TailMatch = addr.match(/(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})$/);
            if (ipv4TailMatch) {
                const embeddedIPv4 = ipv4TailMatch[1];
                const parts = embeddedIPv4.split('.').map(Number);
                const hi = ((parts[0] << 8) | parts[1]).toString(16);
                const lo = ((parts[2] << 8) | parts[3]).toString(16);
                addr = addr.slice(0, addr.length - embeddedIPv4.length) + hi + ':' + lo;
            }

            let head = addr, tail = '', hasDoubleColon = false;
            if (addr.includes('::')) {
                hasDoubleColon = true;
                const idx = addr.indexOf('::');
                head = addr.slice(0, idx);
                tail = addr.slice(idx + 2);
            }

            const headParts = head.length ? head.split(':') : [];
            const tailParts = tail.length ? tail.split(':') : [];

            let groups;
            if (hasDoubleColon) {
                const missing = 8 - (headParts.length + tailParts.length);
                groups = [...headParts, ...Array(Math.max(missing, 0)).fill('0'), ...tailParts];
            } else {
                groups = addr.split(':');
            }
            return groups.map(g => parseInt(g, 16));
        }

        // RFC 5952 canonical text form - same algorithm as the Worker
        // backend, so the address shown/sent from the browser always
        // matches the one the API normalizes to (and therefore the
        // same cache entry).
        function canonicalizeIPv6(ip) {
            if (!isValidIPv6(ip)) return null;
            const groups = expandIPv6(ip.toLowerCase());

            const isV4Mapped = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 &&
                groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
            if (isV4Mapped) {
                const ipv4 = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join('.');
                return '::ffff:' + ipv4;
            }

            const hextets = groups.map(g => g.toString(16));
            let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
            for (let i = 0; i < 8; i++) {
                if (groups[i] === 0) {
                    if (curStart === -1) curStart = i;
                    curLen++;
                    if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
                } else {
                    curStart = -1; curLen = 0;
                }
            }
            if (bestLen < 2) bestStart = -1;
            if (bestStart === -1) return hextets.join(':');

            const before = hextets.slice(0, bestStart);
            const after = hextets.slice(bestStart + bestLen);
            return before.join(':') + '::' + after.join(':');
        }

        function normalizeIP(input) {
            const stripped = stripIPBrackets(input);
            if (isValidIPv6(stripped)) {
                return canonicalizeIPv6(stripped) || stripped;
            }
            return stripped;
        }

        function getIPVersion(ip) {
            if (isValidIPv6(ip)) return 6;
            if (isValidIPv4(ip)) return 4;
            return null;
        }

        function isValidIPv4(ip) {
            const ipv4Regex = /^(\\d{1,3}\\.){3}\\d{1,3}$/;
            if (!ipv4Regex.test(ip)) return false;
            return ip.split('.').every(part => parseInt(part, 10) >= 0 && parseInt(part, 10) <= 255);
        }

        function isValidIPv6(ip) {
            const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
            return ipv6Regex.test(ip);
        }

        function isValidDomain(domain) {
            if (!domain || domain.length > 253) return false;
            const domainRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.[A-Za-z0-9-]{1,63})*\\.[A-Za-z]{2,}$/;
            return domainRegex.test(domain);
        }

        const CH_COUNTRIES = [
            ['at', 'Austria'], ['br', 'Brazil'], ['bg', 'Bulgaria'], ['ca', 'Canada'],
            ['cy', 'Cyprus'], ['fi', 'Finland'], ['fr', 'France'], ['de', 'Germany'],
            ['hk', 'Hong Kong'], ['hu', 'Hungary'], ['in', 'India'], ['id', 'Indonesia'],
            ['ir', 'Iran'], ['il', 'Israel'], ['it', 'Italy'], ['jp', 'Japan'],
            ['kz', 'Kazakhstan'], ['md', 'Moldova'], ['nl', 'Netherlands'], ['pl', 'Poland'],
            ['pt', 'Portugal'], ['ro', 'Romania'], ['ru', 'Russia'], ['rs', 'Serbia'],
            ['sg', 'Singapore'], ['si', 'Slovenia'], ['es', 'Spain'], ['se', 'Sweden'],
            ['ch', 'Switzerland'], ['tr', 'Turkey'], ['gb', 'UK'], ['us', 'USA'],
            ['ua', 'Ukraine'], ['vn', 'Vietnam']
        ];

        const CH_CHECK_TYPES = [
            ['ping', 'Ping'], ['http', 'HTTP'], ['tcp', 'TCP'], ['udp', 'UDP'], ['dns', 'DNS']
        ];
        let chSelectedType = 'ping';

        function chRenderTypeButtons() {
            const container = document.getElementById('chTypeButtons');
            container.innerHTML = CH_CHECK_TYPES.map(([code, label]) => \`
                <button type="button" onclick="chSelectType('\${code}')" data-type="\${code}"
                    class="ch-type-btn px-3 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm rounded-lg font-semibold border-2 transition-colors \${code === chSelectedType ? 'bg-purple-600 border-purple-600 text-white' : 'bg-white border-gray-300 text-gray-600 hover:bg-gray-50'}">
                    \${label}
                </button>
            \`).join('');
        }

        function chSelectType(code) {
            chSelectedType = code;
            document.querySelectorAll('.ch-type-btn').forEach(btn => {
                const active = btn.getAttribute('data-type') === code;
                btn.className = 'ch-type-btn px-3 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm rounded-lg font-semibold border-2 transition-colors ' +
                    (active ? 'bg-purple-600 border-purple-600 text-white' : 'bg-white border-gray-300 text-gray-600 hover:bg-gray-50');
            });
        }

        function switchTab(tab) {
            const scamBtn = document.getElementById('tabScamalyticsBtn');
            const chBtn = document.getElementById('tabCheckhostBtn');
            const scamPanel = document.getElementById('scamalyticsPanel');
            const chPanel = document.getElementById('checkhostPanel');

            const activeClass = 'flex-1 py-2 px-2 sm:px-4 text-xs sm:text-sm md:text-base rounded-lg font-semibold transition-colors bg-blue-600 text-white';
            const activeClassPurple = 'flex-1 py-2 px-2 sm:px-4 text-xs sm:text-sm md:text-base rounded-lg font-semibold transition-colors bg-purple-600 text-white';
            const inactiveClass = 'flex-1 py-2 px-2 sm:px-4 text-xs sm:text-sm md:text-base rounded-lg font-semibold transition-colors text-gray-600 hover:bg-gray-100';

            if (tab === 'scamalytics') {
                scamPanel.classList.remove('hidden');
                chPanel.classList.add('hidden');
                scamBtn.className = activeClass;
                chBtn.className = inactiveClass;
            } else {
                chPanel.classList.remove('hidden');
                scamPanel.classList.add('hidden');
                chBtn.className = activeClassPurple;
                scamBtn.className = inactiveClass;
                if (document.getElementById('chCountryOptionsList').children.length === 0) {
                    chRenderCountryOptions();
                }
                if (document.getElementById('chTypeButtons').children.length === 0) {
                    chRenderTypeButtons();
                }
            }
        }

        function chRenderCountryOptions() {
            const list = document.getElementById('chCountryOptionsList');
            list.innerHTML = CH_COUNTRIES.map(([code, name]) => \`
                <label class="ch-country-option flex items-center gap-2 px-3 py-2 text-sm cursor-pointer hover:bg-gray-50" data-country-name="\${name.toLowerCase()}">
                    <input type="checkbox" class="ch-country-checkbox" value="\${code}" onchange="chOnCountryToggle()">
                    <span>\${name} <span class="text-gray-400 text-xs">(\${code})</span></span>
                </label>
            \`).join('');
        }

        function chFilterCountryOptions() {
            const query = document.getElementById('chCountrySearch').value.trim().toLowerCase();
            document.querySelectorAll('.ch-country-option').forEach(row => {
                const name = row.getAttribute('data-country-name') || '';
                row.classList.toggle('hidden', query !== '' && !name.includes(query));
            });
        }

        function chToggleCountryDropdown() {
            const panel = document.getElementById('chCountryDropdownPanel');
            const isHidden = panel.classList.contains('hidden');
            if (isHidden) {
                panel.classList.remove('hidden');
                document.getElementById('chCountrySearch').value = '';
                chFilterCountryOptions();
                setTimeout(() => document.getElementById('chCountrySearch').focus(), 0);
            } else {
                panel.classList.add('hidden');
            }
        }

        document.addEventListener('click', (e) => {
            const panel = document.getElementById('chCountryDropdownPanel');
            const btn = document.getElementById('chCountryDropdownBtn');
            if (!panel || panel.classList.contains('hidden')) return;
            if (!panel.contains(e.target) && !btn.contains(e.target)) {
                panel.classList.add('hidden');
            }
        });

        function chGetSelectedCountries() {
            return Array.from(document.querySelectorAll('.ch-country-checkbox:checked')).map(cb => cb.value);
        }

        function chOnCountryToggle() {
            chUpdateCountryDropdownLabel();
        }

        function chUpdateCountryDropdownLabel() {
            const label = document.getElementById('chCountryDropdownLabel');
            const selected = chGetSelectedCountries();
            if (selected.length === 0) {
                label.textContent = 'Select countries...';
                label.className = 'text-gray-500 truncate mr-2';
            } else if (selected.length <= 2) {
                label.textContent = selected.map(c => c.toUpperCase()).join(', ');
                label.className = 'text-gray-800 truncate mr-2';
            } else {
                label.textContent = selected.length + ' countries selected';
                label.className = 'text-gray-800 truncate mr-2';
            }
        }

        function chResetNodeSelection() {
            document.querySelectorAll('.ch-country-checkbox').forEach(cb => { cb.checked = false; });
            chUpdateCountryDropdownLabel();
        }

        async function chRunCheck() {
            const host = document.getElementById('chHostInput').value.trim();
            const selectedCountries = chGetSelectedCountries();

            if (!host) {
                chShowError('Please enter a host, domain or IP address');
                return;
            }
            if (selectedCountries.length === 0) {
                chShowError('Select at least one country');
                return;
            }

            chShowLoading();

            try {
                const params = new URLSearchParams();
                params.set('host', host);
                params.set('type', chSelectedType);
                selectedCountries.forEach(c => params.append('country', c));

                const res = await fetch('/checkhost/check?' + params.toString());
                const data = await res.json();

                if (!res.ok || !data.ok) {
                    throw new Error(data.message || 'Failed to run check');
                }

                chDisplayResults(data.host, data.results);

            } catch (error) {
                console.error('Check-Host error:', error);
                chShowError(error.message || 'Error running the check. Please try again.');
            }
        }

        function chShowLoading() {
            document.getElementById('chResults').classList.add('hidden');
            document.getElementById('chError').classList.add('hidden');
            document.getElementById('chLoading').classList.remove('hidden');
        }

        function chShowError(message) {
            document.getElementById('chLoading').classList.add('hidden');
            document.getElementById('chResults').classList.add('hidden');
            document.getElementById('chError').classList.remove('hidden');
            document.getElementById('chErrorMessage').textContent = message;
        }

        function chColumnsForType(t) {
            if (t === 'http') return ['Node', 'Status', 'Code', 'Time'];
            if (t === 'tcp' || t === 'udp') return ['Node', 'Status', 'Time'];
            if (t === 'dns') return ['Node', 'Status', 'IPs'];
            return ['Node', 'Status', 'Ping'];
        }

        const CH_STATUS_LABELS = {
            ping: { OK: 'Reachable', FAIL: 'Unreachable', TIMEOUT: 'Timeout', UNKNOWN: 'Unknown' },
            http: { OK: 'Reachable', FAIL: 'Failed', TIMEOUT: 'Timeout', UNKNOWN: 'Unknown' },
            tcp: { OK: 'Open', FAIL: 'Closed', FILTERED: 'Open or filtered', TIMEOUT: 'Timeout', UNKNOWN: 'Unknown' },
            udp: { OK: 'Open', FAIL: 'Closed', FILTERED: 'Open or filtered', TIMEOUT: 'Timeout', UNKNOWN: 'Unknown' },
            dns: { OK: 'Resolved', FAIL: 'No records', TIMEOUT: 'Timeout', UNKNOWN: 'Unknown' },
        };

        function chStatusLabel(t, status) {
            return (CH_STATUS_LABELS[t] && CH_STATUS_LABELS[t][status]) || status || '-';
        }

        function chStatusColorClass(status) {
            if (status === 'OK') return 'text-green-600';
            if (status === 'FILTERED') return 'text-yellow-600';
            return 'text-red-600';
        }

        const CH_DNS_MAX_IPS_SHOWN = 5;

        function chExtraCells(t, n, host) {
            if (t === 'http') {
                const time = n.response_time_s != null ? Math.round(n.response_time_s * 1000) + ' ms' : '-';
                const code = n.code_display || (n.http_code != null ? String(n.http_code) : '-');
                return \`
                    <td class="py-1.5 px-2 text-xs sm:text-sm text-gray-700">\${code}</td>
                    <td class="py-1.5 px-2 text-xs sm:text-sm text-gray-700">\${time}</td>
                \`;
            }
            if (t === 'tcp' || t === 'udp') {
                const time = n.time_s != null ? Math.round(n.time_s * 1000) + ' ms' : '-';
                return \`<td class="py-1.5 px-2 text-xs sm:text-sm text-gray-700">\${time}</td>\`;
            }
            if (t === 'dns') {
                const ips = Array.isArray(n.ips) ? n.ips : [];
                if (ips.length === 0) {
                    return '<td class="py-1.5 px-2 text-xs sm:text-sm text-gray-400 align-top">-</td>';
                }
                const shown = ips.slice(0, CH_DNS_MAX_IPS_SHOWN);
                const truncated = ips.length > CH_DNS_MAX_IPS_SHOWN;
                const resolveLink = \`/api/\${encodeURIComponent(host)}\`;
                return \`
                    <td class="py-1.5 px-2 text-xs sm:text-sm text-gray-700 align-top">
                        <div class="leading-relaxed">\${shown.join('<br>')}</div>
                        \${truncated ? \`
                            <div class="text-gray-400">...</div>
                            <a href="\${resolveLink}" target="_blank" rel="noopener noreferrer" class="text-purple-600 hover:underline">See all \${ips.length} IPs &rarr;</a>
                        \` : ''}
                    </td>
                \`;
            }
            return \`<td class="py-1.5 px-2 text-xs sm:text-sm text-gray-700">\${n.ping_ms != null ? n.ping_ms + ' ms' : '-'}</td>\`;
        }

        function chDisplayResults(host, results) {
            document.getElementById('chLoading').classList.add('hidden');
            document.getElementById('chError').classList.add('hidden');
            document.getElementById('chResults').classList.remove('hidden');

            const listDiv = document.getElementById('chResultsList');
            listDiv.innerHTML = '';

            results.forEach(entry => {
                if (!entry.ok) {
                    listDiv.innerHTML += \`
                        <div class="bg-red-50 border-2 border-red-200 rounded-xl p-4">
                            <p class="font-semibold text-red-700">\${entry.country.toUpperCase()}</p>
                            <p class="text-sm text-red-500">\${entry.message || 'Request failed'}</p>
                        </div>
                    \`;
                    return;
                }

                const d = entry.data;
                const checkType = d.check_type || chSelectedType;
                const accessible = !!d.is_accessible;
                const badgeClass = accessible ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700';
                const badgeText = accessible ? 'Accessible' : 'Not accessible';
                const columns = chColumnsForType(checkType);

                let nodeRows = '';
                Object.keys(d.details || {}).forEach(nodeId => {
                    const n = d.details[nodeId] || {};
                    const statusColor = chStatusColorClass(n.status);
                    const statusLabel = chStatusLabel(checkType, n.status);
                    nodeRows += \`
                        <tr class="border-b last:border-b-0">
                            <td class="py-1.5 px-2 text-xs sm:text-sm text-gray-600 align-top">\${nodeId}</td>
                            <td class="py-1.5 px-2 text-xs sm:text-sm font-semibold \${statusColor} align-top">\${statusLabel}</td>
                            \${chExtraCells(checkType, n, d.host || host)}
                        </tr>
                    \`;
                });

                listDiv.innerHTML += \`
                    <div class="border-2 border-gray-100 rounded-xl p-4">
                        <div class="flex items-center justify-between mb-1">
                            <h4 class="font-bold text-gray-800">\${(d.country || entry.country).toUpperCase()} <span class="text-xs font-normal text-gray-400">(\${checkType.toUpperCase()})</span></h4>
                            <span class="px-3 py-1 rounded-full text-xs font-semibold \${badgeClass}">\${badgeText}</span>
                        </div>
                        <p class="text-xs sm:text-sm text-gray-500 mb-3">\${d.nodes_checked || 0} node(s) checked for \${d.host || host}</p>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left">
                                <thead>
                                    <tr class="border-b text-gray-500 text-xs">
                                        \${columns.map(c => \`<td class="py-1 px-2">\${c}</td>\`).join('')}
                                    </tr>
                                </thead>
                                <tbody>\${nodeRows}</tbody>
                            </table>
                        </div>
                        \${d.report_url ? \`<a href="\${d.report_url}" target="_blank" rel="noopener noreferrer" class="inline-block mt-3 text-xs sm:text-sm text-purple-600 hover:underline">View full report on check-host.net &rarr;</a>\` : ''}
                    </div>
                \`;
            });
        }
    </script>
</body>
</html>`;

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request);
  },
};

function safeDecodeURIComponent(s) {
  try {
    return decodeURIComponent(s);
  } catch (e) {
    return s;
  }
}

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  const cleanPath = safeDecodeURIComponent(path.replace(/^\/+|\/+$/g, ""));

  if (request.method === "POST" && (cleanPath === "api/check-ips" || cleanPath === "check-ips")) {
    return handleBatchIpsRequest(request);
  }

  if (cleanPath === "checkhost" || cleanPath.startsWith("checkhost/")) {
    const chSubPath = cleanPath === "checkhost" ? "" : cleanPath.substring("checkhost/".length);
    return chHandleRequest(request, chSubPath);
  }

  if (cleanPath.startsWith("api/domain/")) {
    const domainTarget = stripIPBrackets(cleanPath.substring("api/domain/".length));
    if (domainTarget && isValidDomain(domainTarget)) {
      return handleFullDomainCheck(domainTarget, request);
    }
    return jsonResponse(
      { error: true, message: "Invalid domain format", domain: domainTarget },
      400,
    );
  }

  const domainParam = url.searchParams.get("domain");
  if (domainParam) {
    if (isValidDomain(domainParam)) {
      return handleFullDomainCheck(domainParam, request);
    }
    return jsonResponse(
      { error: true, message: "Invalid domain format", domain: domainParam },
      400,
    );
  }

  let target = null;

  if (cleanPath) {
    if (cleanPath.startsWith("api/")) {
      target = stripIPBrackets(cleanPath.substring(4));
    } else {
      target = stripIPBrackets(cleanPath);
    }

    if (target && isValidIP(target)) {
      return handleAPIRequest(normalizeIP(target), request);
    }
    if (target && isValidDomain(target)) {
      return handleDomainRequest(target, request);
    }
  }

  const apiParam = url.searchParams.get("api")
    ? stripIPBrackets(url.searchParams.get("api"))
    : null;
  if (apiParam) {
    if (isValidIP(apiParam)) {
      return handleAPIRequest(normalizeIP(apiParam), request);
    }
    if (isValidDomain(apiParam)) {
      return handleDomainRequest(apiParam, request);
    }
  }

  return new Response(HTML_PAGE, {
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "public, max-age=3600",
    },
  });
}

async function handleAPIRequest(ip, request) {
  if (!isValidIP(ip)) {
    return jsonResponse(
      {
        error: true,
        message: "Invalid IP address format",
        ip: ip,
      },
      400,
    );
  }

  ip = normalizeIP(ip);

  const cacheUrl = new URL(request.url);
  cacheUrl.pathname = `/api-cache/${encodeURIComponent(ip)}`;
  cacheUrl.search = "";
  const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
  const cache = caches.default;

  let cachedResponse = await cache.match(cacheKey);
  if (cachedResponse) {
    const responseHeaders = new Headers(cachedResponse.headers);
    responseHeaders.set("X-Cache", "HIT");
    return new Response(cachedResponse.body, {
      status: cachedResponse.status,
      headers: responseHeaders,
    });
  }

  try {
    const data = await getScamalyticsDataCached(ip);
    const apiResponse = {
      info: {
        success: true,
        ip: data.ip,
        fraud_score: data.fraudScore,
        risk: data.risk,
        risk_source: data.source || "unknown",
        risk_diagnostics: data.diagnostics || {},
      },
      details: buildIpDetails(data),
    };

    const finalResponse = jsonResponse(apiResponse);
    finalResponse.headers.set("X-Cache", "MISS");
    finalResponse.headers.set("Cache-Control", "public, max-age=3600");

    await cache.put(cacheKey, finalResponse.clone());

    return finalResponse;
  } catch (error) {
    return jsonResponse(
      {
        error: true,
        message: error.message || "Failed to fetch IP data",
        ip: ip,
        risk_diagnostics: error.failures || {},
      },
      500,
    );
  }
}

function buildIpDetails(data) {
  const countryCode = data.details["Country Code"] || null;
  const flagEmoji = getFlagEmoji(countryCode);

  return {
    ip_version: getIPVersion(data.ip),
    country: data.details["Country Name"] || null,
    country_code: countryCode,
    flag: flagEmoji,
    state: data.details["State / Province"] || null,
    city: data.details["City"] || null,
    postal_code: data.details["Postal Code"] || null,
    isp: data.details["ISP Name"] || data.details["ISP"] || null,
    organization: data.details["Organization Name"] || null,
    hostname: data.details["Hostname"] || null,
    asn: data.details["ASN"] || null,
    datacenter: data.details["Datacenter"] || null,
    vpn: data.details["Anonymizing VPN"] || null,
    tor: data.details["Tor Exit Node"] || null,
    proxy: data.details["Public Proxy"] || null,
    server: data.details["Server"] || null,
    web_proxy: data.details["Web Proxy"] || null,
  };
}

const RENDER_RESOLVER_API = "https://domain-resolve.onrender.com";

async function resolveDomain(domain) {
  try {
    const targetUrl = `${RENDER_RESOLVER_API}/resolve?domain=${encodeURIComponent(domain)}`;
    const response = await fetch(targetUrl, {
      headers: { Accept: "application/json" },
    });

    if (!response.ok) {
      return { success: false, total_ips: 0, total_groups: 0, groups: [] };
    }

    const data = await response.json();
    return data;
  } catch (e) {
    return { success: false, total_ips: 0, total_groups: 0, groups: [] };
  }
}

async function handleDomainRequest(domain, request) {
  try {
    const resolveData = await resolveDomain(domain);

    if (!resolveData.success || !resolveData.groups || resolveData.groups.length === 0) {
      return jsonResponse(
        {
          error: true,
          message: "Could not resolve this domain to any IPv4/IPv6 address",
          domain: domain,
        },
        404,
      );
    }

    return jsonResponse(resolveData);
  } catch (error) {
    return jsonResponse(
      {
        error: true,
        message: error.message || "Failed to resolve domain",
        domain: domain,
      },
      500,
    );
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getScamalyticsDataCached(ip, mode = "single") {
  const cacheUrl = new URL("https://cache.internal/scamalytics-raw");
  cacheUrl.searchParams.set("ip", ip);
  const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
  const cache = caches.default;

  const cached = await cache.match(cacheKey);
  if (cached) {
    return await cached.json();
  }

  const data =
    mode === "group" ? await fetchScamalyticsDataForGroup(ip) : await fetchScamalyticsData(ip);

  const cacheResponse = new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=3600" },
  });
  await cache.put(cacheKey, cacheResponse);

  return data;
}

function sanitizeIpList(rawIps) {
  const valid = [];
  const invalid = [];
  const seen = new Set();

  for (const raw of rawIps) {
    if (typeof raw !== "string") {
      invalid.push(raw);
      continue;
    }
    const cleaned = stripIPBrackets(raw.trim());
    if (!isValidIP(cleaned)) {
      invalid.push(raw);
      continue;
    }
    const normalized = normalizeIP(cleaned);
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    valid.push(normalized);
  }

  return { valid, invalid };
}

const SELF_FETCH_LEAF_SIZE = 8;

const SELF_FETCH_MAX_FANOUT = 40;

async function scoreIpListInProcess(ips) {
  const results = [];
  const chunkSize = 3;

  for (let i = 0; i < ips.length; i += chunkSize) {
    const chunk = ips.slice(i, i + chunkSize);

    const chunkResults = await Promise.all(
      chunk.map(async (ip, idx) => {
        await sleep(idx * 250);
        try {
          const data = await getScamalyticsDataCached(ip, "group");
          return {
            ip: data.ip,
            fraud_score: data.fraudScore,
            risk: data.risk,
            details: buildIpDetails(data),
          };
        } catch (err) {
          return { ip, error: true, message: "Failed to fetch data for this IP" };
        }
      }),
    );

    results.push(...chunkResults);
    if (i + chunkSize < ips.length) {
      await sleep(400);
    }
  }

  return results;
}

async function selfCheckGroup(origin, ips) {
  try {
    const res = await fetch(`${origin}/api/check-ips`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ ips }),
    });
    const json = await res.json();
    if (json && json.success && Array.isArray(json.results)) {
      return json.results;
    }
    throw new Error((json && json.message) || `group self-check HTTP ${res.status}`);
  } catch (e) {
    return scoreIpListInProcess(ips);
  }
}

async function scoreIpList(ips, origin) {
  if (!origin || ips.length <= SELF_FETCH_LEAF_SIZE) {
    return scoreIpListInProcess(ips);
  }

  const groupSize = Math.max(SELF_FETCH_LEAF_SIZE, Math.ceil(ips.length / SELF_FETCH_MAX_FANOUT));
  const groups = [];
  for (let i = 0; i < ips.length; i += groupSize) {
    groups.push(ips.slice(i, i + groupSize));
  }

  const results = [];
  const dispatchConcurrency = 5;
  for (let i = 0; i < groups.length; i += dispatchConcurrency) {
    const batch = groups.slice(i, i + dispatchConcurrency);
    const batchResults = await Promise.all(batch.map((group) => selfCheckGroup(origin, group)));
    for (const groupResult of batchResults) {
      results.push(...groupResult);
    }
    if (i + dispatchConcurrency < groups.length) {
      await sleep(300);
    }
  }

  return results;
}

async function handleFullDomainCheck(domain, request) {
  const cacheUrl = new URL("https://cache.internal/domain-check");
  cacheUrl.searchParams.set("domain", domain);
  const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
  const cache = caches.default;

  const cached = await cache.match(cacheKey);
  if (cached) {
    const responseHeaders = new Headers(cached.headers);
    responseHeaders.set("X-Cache", "HIT");
    return new Response(cached.body, { status: cached.status, headers: responseHeaders });
  }

  try {
    const resolveData = await resolveDomain(domain);

    if (!resolveData.success || !resolveData.groups || resolveData.groups.length === 0) {
      return jsonResponse(
        {
          error: true,
          message: "Could not resolve this domain to any IPv4/IPv6 address",
          domain: domain,
        },
        404,
      );
    }

    const { valid: allIps } = sanitizeIpList(resolveData.groups.flat());
    const origin = request ? new URL(request.url).origin : null;
    const results = await scoreIpList(allIps, origin);

    const finalResponse = jsonResponse({
      success: true,
      domain: domain,
      total_ips: resolveData.total_ips,
      count: results.length,
      results: results,
    });
    finalResponse.headers.set("X-Cache", "MISS");
    finalResponse.headers.set("Cache-Control", "public, max-age=3600");
    await cache.put(cacheKey, finalResponse.clone());

    return finalResponse;
  } catch (error) {
    return jsonResponse(
      {
        error: true,
        message: error.message || "Failed to check domain",
        domain: domain,
      },
      500,
    );
  }
}

async function handleBatchIpsRequest(request) {
  try {
    const body = await request.json();
    const ips = body.ips;

    if (!Array.isArray(ips) || ips.length === 0) {
      return jsonResponse({ error: true, message: "Invalid or empty ips array" }, 400);
    }

    const { valid, invalid } = sanitizeIpList(ips);

    if (valid.length === 0) {
      return jsonResponse(
        { error: true, message: "No valid IPv4/IPv6 addresses in ips array", invalid },
        400,
      );
    }

    const origin = new URL(request.url).origin;
    const results = await scoreIpList(valid, origin);

    for (const bad of invalid) {
      results.push({ ip: bad, error: true, message: "Invalid IP address format" });
    }

    return jsonResponse({
      success: true,
      count: results.length,
      results: results,
    });
  } catch (err) {
    return jsonResponse({ error: true, message: "Failed to process batch" }, 500);
  }
}

async function safeCacheMatch(cache, key) {
  try {
    return await cache.match(key);
  } catch (e) {
    return undefined;
  }
}

async function safeCachePut(cache, key, response) {
  try {
    await cache.put(key, response);
  } catch (e) {}
}

async function fetchScamalyticsData(ip) {
  const targetUrl = `https://scamalytics.com/ip/${ip}`;
  const startedAt = Date.now();

  const cache = caches.default;
  const negCacheKey = new Request(
    `https://cache.internal/scamalytics-fail?ip=${encodeURIComponent(ip)}`,
  );

  const negCached = await safeCacheMatch(cache, negCacheKey);

  if (negCached) {
    const error = new Error(
      "All connection paths and mirror proxies failed recently. Please try again.",
    );
    error.failures = {
      Cache: "NEGATIVE_CACHE",
    };
    throw error;
  }

  const groupA = [
    {
      name: "Direct",
      url: targetUrl,
      direct: true,
      timeout: currentDirectTimeoutMs(),
    },
    {
      name: "CorsProxyIO",
      url: `https://corsproxy.io/?url=${encodeURIComponent(targetUrl)}`,
      timeout: 5000,
    },
    {
      name: "Codetabs",
      url: `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(targetUrl)}`,
      timeout: 5000,
    },
    {
      name: "AllOrigins",
      url: `https://api.allorigins.win/raw?url=${encodeURIComponent(targetUrl)}`,
      timeout: 5000,
    },
  ];

  let diagnostics = {};

  try {
    const result = await raceProxies(groupA, 5000, ip);

    return {
      ...result.parsed,
      source: result.source,
      diagnostics: {
        ...result.failures,
        [result.source]: "SUCCESS",
      },
    };
  } catch (eA) {
    diagnostics = {
      ...diagnostics,
      ...(eA.failures || {}),
    };

    const groupB = [
      {
        name: "ThingProxy",
        url: `https://thingproxy.freeboard.io/fetch/${targetUrl}`,
        timeout: 5000,
      },
      {
        name: "JSONP",
        url: `https://jsonp.afeld.me/?url=${encodeURIComponent(targetUrl)}`,
        timeout: 5000,
      },
    ];

    try {
      const result = await raceProxies(groupB, 5000, ip);

      return {
        ...result.parsed,
        source: result.source,
        diagnostics: {
          ...diagnostics,
          ...result.failures,
          [result.source]: "SUCCESS",
        },
      };
    } catch (eB) {
      diagnostics = {
        ...diagnostics,
        ...(eB.failures || {}),
      };

      const failResponse = new Response("1", {
        headers: {
          "Cache-Control": `public, max-age=${NEGATIVE_CACHE_TTL_SECONDS}`,
        },
      });

      await safeCachePut(cache, negCacheKey, failResponse);

      const error = new Error("All connection paths and mirror proxies failed.");

      error.failures = diagnostics;
      throw error;
    }
  }
}

const DIRECT_TIMEOUT_CEILING_MS = 3000;
const DIRECT_TIMEOUT_FLOOR_MS = 800;
const DIRECT_TIMEOUT_MULTIPLIER = 2.5;
const DIRECT_LATENCY_WINDOW = 20;
const DIRECT_LATENCY_MIN_SAMPLES = 5;
const directLatencies = [];

function recordDirectLatency(ms) {
  directLatencies.push(ms);
  if (directLatencies.length > DIRECT_LATENCY_WINDOW) directLatencies.shift();
}

function currentDirectTimeoutMs() {
  if (directLatencies.length < DIRECT_LATENCY_MIN_SAMPLES) return DIRECT_TIMEOUT_CEILING_MS;
  const avg = directLatencies.reduce((a, b) => a + b, 0) / directLatencies.length;
  return Math.round(
    Math.min(
      DIRECT_TIMEOUT_CEILING_MS,
      Math.max(DIRECT_TIMEOUT_FLOOR_MS, avg * DIRECT_TIMEOUT_MULTIPLIER),
    ),
  );
}

async function fetchScamalyticsDataForGroup(ip) {
  return fetchScamalyticsData(ip);
}

const NEGATIVE_CACHE_TTL_SECONDS = 45;

async function raceProxies(proxyList, timeoutMs, ip) {
  const failures = {};

  for (const proxy of proxyList) {
    const attemptTimeoutMs = proxy.timeout || (proxy.direct ? currentDirectTimeoutMs() : timeoutMs);
    const attemptStartedAt = Date.now();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), attemptTimeoutMs);

    try {
      const headers = proxy.direct
        ? {
            "User-Agent": getRandomUserAgent(),
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
          }
        : {
            "User-Agent": getRandomUserAgent(),
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          };

      const response = await fetch(proxy.url, {
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        failures[proxy.name] = `HTTP ${response.status}`;
        continue;
      }

      const html = await response.text();

      if (!html || html.length < 1000) {
        failures[proxy.name] = "INVALID Response too short";
        continue;
      }

      let parsed;

      try {
        parsed = parseScamalyticsHTML(html, ip);
      } catch (err) {
        failures[proxy.name] = `INVALID ${err.message}`;
        continue;
      }

      if (proxy.direct) {
        recordDirectLatency(Date.now() - attemptStartedAt);
      }

      return {
        html,
        source: proxy.name,
        parsed,
        failures,
      };
    } catch (err) {
      clearTimeout(timeoutId);

      if (proxy.direct && err && err.name === "AbortError") {
        recordDirectLatency(attemptTimeoutMs);
        failures[proxy.name] = "TIMEOUT";
      } else {
        failures[proxy.name] =
          err && err.name === "AbortError" ? "TIMEOUT" : `ERROR ${err?.message || "Unknown error"}`;
      }
    }
  }

  const error = new Error("All proxy attempts failed");
  error.failures = failures;
  throw error;
}

function parseScamalyticsHTML(html, ip) {
  if (!html || typeof html !== "string") {
    throw new Error("Empty Scamalytics response");
  }

  const details = {};

  const jsonScoreMatch = html.match(/["']score["']\s*:\s*["']?(\d{1,3})["']?/i);

  const textScoreMatch = html.match(/Fraud Score:\s*(\d{1,3})/i);

  const scoreMatch = jsonScoreMatch || textScoreMatch;

  if (!scoreMatch) {
    throw new Error("Fraud score not found");
  }

  const fraudScore = Number.parseInt(scoreMatch[1], 10);

  if (!Number.isInteger(fraudScore) || fraudScore < 0 || fraudScore > 100) {
    throw new Error("Invalid fraud score");
  }

  const jsonRiskMatch = html.match(/["']risk["']\s*:\s*["']([^"']+)["']/i);

  let riskLevel = "unknown";

  if (jsonRiskMatch) {
    const normalizedRisk = jsonRiskMatch[1].trim().toLowerCase().replace(/\s+/g, "_");

    if (
      normalizedRisk === "very_low" ||
      normalizedRisk === "low" ||
      normalizedRisk === "medium" ||
      normalizedRisk === "high" ||
      normalizedRisk === "very_high"
    ) {
      riskLevel = normalizedRisk;
    }
  }

  if (riskLevel === "unknown") {
    const riskMatch = html.match(/<div class="panel_title[^"]*"[^>]*>(.*?)<\/div>/i);

    if (riskMatch) {
      const riskText = riskMatch[1]
        .replace(/<[^>]+>/g, " ")
        .trim()
        .toLowerCase();

      if (riskText.includes("very low risk")) {
        riskLevel = "very_low";
      } else if (riskText.includes("very high risk")) {
        riskLevel = "very_high";
      } else if (riskText.includes("low risk")) {
        riskLevel = "low";
      } else if (riskText.includes("medium risk")) {
        riskLevel = "medium";
      } else if (riskText.includes("high risk")) {
        riskLevel = "high";
      }
    }
  }

  if (riskLevel === "unknown") {
    if (fraudScore === 0) {
      riskLevel = "very_low";
    } else if (fraudScore <= 25) {
      riskLevel = "low";
    } else if (fraudScore <= 50) {
      riskLevel = "medium";
    } else if (fraudScore <= 75) {
      riskLevel = "high";
    } else {
      riskLevel = "very_high";
    }
  }

  const tableRowRegex =
    /<tr>\s*<th>([^<]+)<\/th>\s*<td>(?:<div class="risk[^"]*">)?([^<]+)(?:<\/div>)?<\/td>\s*<\/tr>/gi;

  let match;

  while ((match = tableRowRegex.exec(html)) !== null) {
    const key = match[1].trim();
    const value = match[2].trim();

    if (key && value && value.toLowerCase() !== "n/a") {
      details[key] = value;
    }
  }

  const ispMatch = html.match(/<a href="[^"]*\/ip\/isp\/[^"]*">([^<]+)<\/a>/i);

  if (ispMatch) {
    details["ISP Name"] = ispMatch[1].trim();
    details["ISP"] = ispMatch[1].trim();
  }

  return {
    ip,
    fraudScore,
    risk: riskLevel,
    details,
  };
}

function isValidIP(ip) {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

function isValidIPv4(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  return ip.split(".").every((part) => parseInt(part, 10) >= 0 && parseInt(part, 10) <= 255);
}

function isValidIPv6(ip) {
  const ipv6Regex =
    /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
  return ipv6Regex.test(ip);
}

function stripIPBrackets(input) {
  let s = (input || "").trim();
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end !== -1) {
      const host = s.slice(1, end);
      const rest = s.slice(end + 1);
      if (!rest || rest.startsWith(":")) {
        s = host;
      }
    }
  }
  if (s.includes(":")) {
    const zoneIdx = s.indexOf("%");
    if (zoneIdx !== -1) s = s.slice(0, zoneIdx);
  }
  return s;
}

function expandIPv6(ip) {
  let addr = ip;

  const ipv4TailMatch = addr.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (ipv4TailMatch) {
    const embeddedIPv4 = ipv4TailMatch[1];
    const parts = embeddedIPv4.split(".").map(Number);
    const hi = ((parts[0] << 8) | parts[1]).toString(16);
    const lo = ((parts[2] << 8) | parts[3]).toString(16);
    addr = addr.slice(0, addr.length - embeddedIPv4.length) + hi + ":" + lo;
  }

  let head = addr;
  let tail = "";
  let hasDoubleColon = false;

  if (addr.includes("::")) {
    hasDoubleColon = true;
    const idx = addr.indexOf("::");
    head = addr.slice(0, idx);
    tail = addr.slice(idx + 2);
  }

  const headParts = head.length ? head.split(":") : [];
  const tailParts = tail.length ? tail.split(":") : [];

  let groups;
  if (hasDoubleColon) {
    const missing = 8 - (headParts.length + tailParts.length);
    groups = [...headParts, ...Array(Math.max(missing, 0)).fill("0"), ...tailParts];
  } else {
    groups = addr.split(":");
  }

  return groups.map((g) => parseInt(g, 16));
}

function canonicalizeIPv6(ip) {
  if (!isValidIPv6(ip)) return null;
  const groups = expandIPv6(ip.toLowerCase());

  const isV4Mapped =
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff;

  if (isV4Mapped) {
    const ipv4 = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join(".");
    return "::ffff:" + ipv4;
  }

  const hextets = groups.map((g) => g.toString(16));

  let bestStart = -1,
    bestLen = 0,
    curStart = -1,
    curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) bestStart = -1;

  if (bestStart === -1) {
    return hextets.join(":");
  }

  const before = hextets.slice(0, bestStart);
  const after = hextets.slice(bestStart + bestLen);
  return before.join(":") + "::" + after.join(":");
}

function normalizeIP(input) {
  const stripped = stripIPBrackets(input);
  if (isValidIPv6(stripped)) {
    return canonicalizeIPv6(stripped) || stripped;
  }
  return stripped;
}

function getIPVersion(ip) {
  if (isValidIPv6(ip)) return 6;
  if (isValidIPv4(ip)) return 4;
  return null;
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253) return false;
  const domainRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$/;
  return domainRegex.test(domain);
}

function getFlagEmoji(countryCode) {
  if (!countryCode || countryCode.length !== 2) return "";
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  try {
    return String.fromCodePoint(...codePoints);
  } catch (e) {
    return "";
  }
}

function getRandomUserAgent() {
  const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
  ];
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

const CH_RENDER_API_BASE = "https://check-host.onrender.com";
const CH_VALID_TYPES = ["ping", "http", "tcp", "udp", "dns"];

async function chHandleRequest(request, chSubPath) {
  if (chSubPath === "check") {
    return chHandleCheckRequest(request);
  }

  const parts = chSubPath.split("/").filter(Boolean);

  if (parts.length >= 3 && CH_VALID_TYPES.includes(parts[0].toLowerCase())) {
    const type = parts[0].toLowerCase();
    const country = parts[1];
    const host = parts.slice(2).join("/");
    return chHandleDirectRequest(type, country, host);
  }

  if (parts.length >= 2) {
    const country = parts[0];
    const host = parts.slice(1).join("/");
    return chHandleDirectRequest("ping", country, host);
  }

  return chJsonResponse({ ok: false, message: "Unknown Check-Host endpoint" }, 404);
}

async function chHandleDirectRequest(type, country, host) {
  if (!CH_VALID_TYPES.includes(type)) {
    return chJsonResponse(
      { ok: false, message: `Invalid check type (expected one of: ${CH_VALID_TYPES.join(", ")})` },
      400,
    );
  }
  if (!country || !/^[a-zA-Z]{2,3}$/.test(country)) {
    return chJsonResponse(
      { ok: false, message: 'Invalid country code format (expected e.g. "us", "de", "ir")' },
      400,
    );
  }
  if (!host) {
    return chJsonResponse({ ok: false, message: "Missing host" }, 400);
  }

  host = normalizeIP(stripIPBrackets(host));

  const result = await chCheckSingleCountry(host, country.toLowerCase(), type);

  if (!result.ok) {
    return chJsonResponse(
      { ok: false, message: result.message, country: country.toLowerCase(), host },
      502,
    );
  }

  return chJsonResponse({ ok: true, ...result.data });
}

async function chHandleCheckRequest(request) {
  const url = new URL(request.url);
  let host = url.searchParams.get("host");
  const countries = url.searchParams.getAll("country");
  const rawType = (url.searchParams.get("type") || "ping").toLowerCase();

  if (!host) {
    return chJsonResponse({ ok: false, message: 'Missing "host" parameter' }, 400);
  }
  if (!CH_VALID_TYPES.includes(rawType)) {
    return chJsonResponse(
      {
        ok: false,
        message: `Invalid "type" parameter (expected one of: ${CH_VALID_TYPES.join(", ")})`,
      },
      400,
    );
  }

  host = normalizeIP(stripIPBrackets(host));
  if (countries.length === 0) {
    return chJsonResponse({ ok: false, message: "Select at least one country" }, 400);
  }

  const limitedCountries = countries.slice(0, 10);

  const results = await Promise.all(
    limitedCountries.map((country) => chCheckSingleCountry(host, country.toLowerCase(), rawType)),
  );

  return chJsonResponse({ ok: true, host, type: rawType, results });
}

async function chCheckSingleCountry(host, country, type = "ping") {
  const cacheUrl = new URL("https://cache.internal/checkhost-render");
  cacheUrl.searchParams.set("country", country);
  cacheUrl.searchParams.set("host", host);
  cacheUrl.searchParams.set("type", type);
  const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
  const cache = caches.default;

  const cached = await cache.match(cacheKey);
  if (cached) {
    const data = await cached.json();
    return { country, ok: true, data };
  }

  const target = `${CH_RENDER_API_BASE}/api/${encodeURIComponent(type)}/${encodeURIComponent(country)}/${encodeURIComponent(host)}`;

  try {
    const res = await fetch(target, {
      headers: { Accept: "application/json" },
    });

    const contentType = res.headers.get("content-type") || "";
    const bodyText = await res.text();

    if (!contentType.toLowerCase().includes("json")) {
      const snippet = bodyText.slice(0, 150).replace(/\s+/g, " ").trim();
      throw new Error(`Non-JSON response (HTTP ${res.status}): "${snippet}"`);
    }

    let data;
    try {
      data = JSON.parse(bodyText);
    } catch (e) {
      throw new Error(`Invalid JSON response (HTTP ${res.status})`);
    }

    if (!res.ok) {
      throw new Error((data && data.message) || `HTTP ${res.status}`);
    }

    const cacheResponse = new Response(JSON.stringify(data), {
      headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=60" },
    });
    await cache.put(cacheKey, cacheResponse);

    return { country, ok: true, data };
  } catch (e) {
    return { country, ok: false, message: e.message || "Request failed" };
  }
}

function chJsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
