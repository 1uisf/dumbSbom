// SVG for GitHub icon
const githubIconSVG = `<svg aria-hidden="true" height="15" viewBox="0 0 16 16" width="15" style="vertical-align:middle;margin-left:4px;fill:#333;display:inline-block;"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path></svg>`;

// Results page JavaScript for SBOM Analyzer

document.addEventListener('DOMContentLoaded', function() {
    console.log('=== SBOM Results Page Debug ===');
    console.log('DOM loaded, fetching scan data from backend...');
    
    // Initialize dependency sections to ensure they start collapsed
    initializeDependencySections();

    // Fetch scan data from backend
    fetch('/api/scan_data')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
        showError('No analysis results found. Please upload a file for analysis.');
        return;
    }
            console.log('Scan data received from backend:', data);
            // Always set vulnerability data globally for graph and popups
            window.vulnerabilityDataFromServer = data.vulnerabilities && typeof data.vulnerabilities === 'object' ? data.vulnerabilities : {};
            // Defensive: ensure sbom_data is an object
            const sbomData = (data.sbom_data && typeof data.sbom_data === 'object') ? data.sbom_data : {};
            // Defensive: ensure dependencies and dependency_tree are arrays
            sbomData.dependencies = Array.isArray(sbomData.dependencies) ? sbomData.dependencies : [];
            sbomData.dependency_tree = Array.isArray(sbomData.dependency_tree) ? sbomData.dependency_tree : [];
            // Defensive: ensure project_type and filename are strings
            sbomData.project_type = typeof data.project_type === 'string' ? data.project_type : 'Unknown';
            sbomData.filename = typeof data.filename === 'string' ? data.filename : '-';
            
            // Store sbom data globally for filter access
            window.sbomDataFromServer = sbomData;
            
            // Initialize the results page with robust data
            initializeResults(sbomData);
            
            // Load package health data
            loadPackageHealthData();
        })
        .catch(err => {
            console.error('Failed to fetch scan data:', err);
            showError('No analysis results found. Please upload a file for analysis.');
        });

    // Add export graph functionality
    const exportBtn = document.getElementById('export-graph-btn');
    if (exportBtn) {
        exportBtn.onclick = function() {
            try {
                // Try to find the vis-network canvas
                let graphDiv = document.getElementById('dependency-graph');
                let canvas = graphDiv.querySelector('canvas');
                if (!canvas) throw new Error('Graph canvas not found. Please ensure the graph is loaded.');
                let image = canvas.toDataURL('image/png');
                let a = document.createElement('a');
                a.href = image;
                a.download = 'graph.png';
                a.click();
            } catch (err) {
                alert('Export failed: ' + err.message);
            }
        };
    }
});

// Helper: compare two version strings (semver, loose)
function compareVersions(v1, v2) {
    // Split by dot, compare each part numerically
    const a = v1.split('.').map(Number);
    const b = v2.split('.').map(Number);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        const n1 = a[i] || 0;
        const n2 = b[i] || 0;
        if (n1 > n2) return 1;
        if (n1 < n2) return -1;
    }
    return 0;
}

// Deduplicate dependencies by name, keeping highest version
function deduplicateDependencies(tree) {
    const nodeMap = new Map(); // name.toLowerCase() -> {node, version, originalName}
    const edges = [];

    // First pass: flatten all nodes and keep highest version
    function flatten(tree, parentKey = 'root') {
        if (!Array.isArray(tree)) return;
        for (const dep of tree) {
            if (!dep.name || !dep.version) continue;
            const name = dep.name;
            const key = name.toLowerCase();
            if (!nodeMap.has(key) || compareVersions(dep.version, nodeMap.get(key).version) > 0) {
                nodeMap.set(key, { ...dep, originalName: dep.name });
            }
            // Record edge from parent to this node
            edges.push({ from: parentKey, to: key });
            // Recurse into subdependencies
            if (Array.isArray(dep.subdependencies)) {
                flatten(dep.subdependencies, key);
            }
        }
    }
    flatten(tree);

    // Second pass: build deduped nodes and edges
    // All edges point to the deduped node for each name
    return {
        nodes: Array.from(nodeMap.values()),
        edges
    };
}

// Clean package name for display (remove platform-specific markers)
function cleanPackageNameForDisplay(pkgName) {
    if (!pkgName) return pkgName;
    
    // Remove platform-specific markers and long conditional expressions
    let cleaned = pkgName;
    
    // Remove quoted platform markers like "aarch64", "x86_64", etc.
    // Pattern: package-"platform" -> package
    cleaned = cleaned.replace(/-\s*["']([^"']+)["']/g, '');
    
    // Remove long conditional expressions in parentheses
    // Pattern: package-(long_condition) -> package
    cleaned = cleaned.replace(/-\s*\([^)]{20,}\)/g, '');
    
    // Remove common platform identifiers
    const platformPatterns = [
        /-aarch64/i, /-x86_64/i, /-amd64/i, /-ppc64le/i, /-win32/i,
        /-linux/i, /-macos/i, /-windows/i, /-darwin/i,
        /-cp\d+/i, /-py\d+/i, /-abi\d+/i  // Python version markers
    ];
    
    platformPatterns.forEach(pattern => {
        cleaned = cleaned.replace(pattern, '');
    });
    
    // Clean up any double dashes or trailing dashes
    cleaned = cleaned.replace(/-+/g, '-');  // Replace multiple dashes with single
    cleaned = cleaned.replace(/-+$/, '');   // Remove trailing dash
    
    return cleaned.trim();
}

// Build graph data using deduplication
function buildGraphDataDeduped(tree) {
    const { nodes, edges } = deduplicateDependencies(tree);
    // Add root node
    const graphNodes = [
        {
            id: 'root',
            label: 'Project Root\n(Your Project)',
            level: 0,
            shape: 'ellipse',
            color: { background: '#2c3e50', border: '#34495e' },
            font: { color: '#fff', size: 16, bold: true },
            size: 35
        },
        ...nodes.map(node => {
            // Try both original and lowercased keys for vulnerability data
            let vulnData = null;
            if (window.vulnerabilityDataFromServer) {
                vulnData = window.vulnerabilityDataFromServer[node.originalName] || window.vulnerabilityDataFromServer[node.originalName.toLowerCase()] || null;
            }
            
            // Check for health issues
            const healthIssue = getPackageHealthIssue(node.originalName);
            
            function isFlexibleOrInvalidVersion(version) {
                if (!version) return true;
                if (typeof version !== 'string') version = String(version);
                // Mark as N/A if it does not contain any digit OR contains a '*'
                return !(/[0-9]/.test(version)) || version.includes('*');
            }
            // If no vulnData, always treat as N/A 
            let riskLevel = 'na';
            let riskScore = 0;
            let vulnCount = 0;
            if (vulnData) {
                riskLevel = vulnData.risk_level;
                riskScore = vulnData.risk_score;
                vulnCount = vulnData.vulnerability_count;
            }
            if (isFlexibleOrInvalidVersion(node.version)) {
                riskLevel = 'na';
                riskScore = 0;
                vulnCount = 0;
            }
            
            // Override risk level if health issue exists, but keep vulnerability info
            if (healthIssue) {
                // Map health severity to risk level, but don't override if vulnerability is higher
                const healthRiskLevel = healthIssue.severity;
                const healthRiskScore = healthIssue.severity === 'critical' ? 95.0 :
                                       healthIssue.severity === 'high' ? 80.0 :
                                       healthIssue.severity === 'medium' ? 60.0 : 30.0;
                
                // Only override if health issue is more severe than vulnerability
                if (healthRiskScore > riskScore) {
                    riskLevel = healthRiskLevel;
                    riskScore = healthRiskScore;
                }
                // If vulnerability is more severe, keep the vulnerability risk level
            }
            
            // Color coding based on risk level only (not riskScore)
            let nodeColors;
            if (riskLevel === 'na') {
                // N/A - Gray (neutral)
                nodeColors = {
                    background: '#95a5a6',
                    border: '#7f8c8d',
                    highlight: {
                        background: '#bdc3c7',
                        border: '#95a5a6'
                    }
                };
            } else if (riskLevel === 'critical') {
                // Critical - Dark red
                nodeColors = {
                    background: '#dc3545',
                    border: '#c82333',
                    highlight: {
                        background: '#e74c3c',
                        border: '#dc3545'
                    }
                };
            } else if (riskLevel === 'high') {
                // High - Red
                nodeColors = {
                    background: '#dc3545',
                    border: '#c82333',
                    highlight: {
                        background: '#e74c3c',
                        border: '#dc3545'
                    }
                };
            } else if (riskLevel === 'medium') {
                // Medium - Yellow
                nodeColors = {
                    background: '#f1c40f',
                    border: '#f39c12',
                    highlight: {
                        background: '#f7dc6f',
                        border: '#f1c40f'
                    }
                };
            } else if (riskLevel === 'low') {
                // Low - Green
                nodeColors = {
                    background: '#2ecc71',
                    border: '#27ae60',
                    highlight: {
                        background: '#58d68d',
                        border: '#2ecc71'
                    }
                };
            } else {
                // Safe - Green
                nodeColors = {
                    background: '#2ecc71',
                    border: '#27ae60',
                    highlight: {
                        background: '#58d68d',
                        border: '#2ecc71'
                    }
                };
            }
            
            // Check if this is a direct dependency and has GitHub data
            const isDirectDependency = window.sbomDataFromServer && 
                window.sbomDataFromServer.dependencies && 
                window.sbomDataFromServer.dependencies.some(dep => 
                    dep.name && dep.name.toLowerCase() === node.originalName.toLowerCase()
                );
            const hasGithub = node.github && typeof node.github === 'object' && Object.keys(node.github).length > 0;
            
            // Use cleaned name for display, but keep original for lookups
            const displayName = cleanPackageNameForDisplay(node.originalName);
            let label = `${displayName}`;
            
            // Show vulnerability count if there are vulnerabilities, regardless of health issues
            if (vulnCount > 0) {
                // Add a visual indicator for vulnerability count
                const indicator = vulnCount > 9 ? '9+' : vulnCount.toString();
                const vulnLabel = vulnCount === 1 ? 'vuln' : 'vulns';
                label += `\n⚠ ${indicator} ${vulnLabel}`;
            } else if (healthIssue) {
                // Only show health severity if no vulnerabilities
                label += `\n${healthIssue.severity}`;
            } else if (riskLevel === 'na') {
                label += `\nN/A`;
            }
            
            // --- FIX: Define 'title' for each node ---
            let title = `${displayName}`;
            if (node.version) title += ` v${node.version}`;
            if (riskLevel === 'na') {
                title += `\nRisk: N/A`;
            } else {
                title += `\nRisk: ${riskLevel.toUpperCase()}`;
            }
            if (vulnCount > 0) {
                title += `\nVulnerabilities: ${vulnCount}`;
            }
            if (healthIssue) {
                title += `\nHealth: ${healthIssue.severity}`;
            }
            
            return {
                id: node.originalName.toLowerCase(),
                label: label,
                level: 1,
                version: node.version,
                type: node.type,
                risk_level: riskLevel,
                risk_score: riskScore,
                package_name: node.originalName,
                color: nodeColors,
                font: { 
                    color: '#fff', 
                    size: 14, 
                    bold: true, 
                    multi: true 
                },
                size: 20,
                title: title,
                vuln_count: vulnCount,
                health_issue: healthIssue
            };
        })
    ];
    // Edges: allow multiple parents to point to the same node
    const graphEdges = edges.map(edge => ({
        from: edge.from === 'root' ? 'root' : edge.from.toLowerCase(),
        to: edge.to.toLowerCase(),
            arrows: 'to',
            smooth: { type: 'curvedCW', roundness: 0.2 },
            width: 2
    }));
    return { nodes: graphNodes, edges: graphEdges };
}

// Use deduplicated graph for rendering, with node click events
function renderDependencyGraph(dependencyTree) {
    console.log('Rendering deduplicated dependency graph...');
    const { nodes, edges } = buildGraphDataDeduped(dependencyTree);
    const container = document.getElementById('dependency-graph');
    if (!container) {
        console.log('Dependency graph container not found');
        return;
    }
    if (!nodes.length) {
        container.innerHTML = '<p>No dependencies to display.</p>';
        return;
    }
    if (typeof vis === 'undefined' || typeof vis.Network === 'undefined') {
        console.error('vis.js library not loaded. Cannot render graph.');
        container.innerHTML = '<p>Error: Graph library not loaded. Please refresh the page.</p>';
        return;
    }
    const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
    
    // Store references for filtering
    currentGraphData = data;
    
    const options = {
        layout: {
            improvedLayout: true,
            hierarchical: false,
            randomSeed: 42
        },
        nodes: {
            shape: 'box',
            font: { size: 14, face: 'Arial' }, 
            borderWidth: 2, 
            shadow: true
        },
        edges: {
            arrows: 'to',
            smooth: { type: 'curvedCW', roundness: 0.2 }, 
            width: 2,
            length: 200 
        },
        interaction: {
            hover: false,  // Disable hover tooltips
            zoomView: false,  // Disable zoom on mouse wheel
            dragView: false,  // Disable dragging
            selectConnectedEdges: false,
            keyboard: {
                enabled: false
            }
        },
        physics: {
            enabled: true,  // Enable temporarily to apply spacing
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -50,
                centralGravity: 0.01,
                springLength: 200,
                springConstant: 0.08,
                avoidOverlap: 1
            },
            barnesHut: {
                gravitationalConstant: -20000,
                centralGravity: 0.3,
                springLength: 200,
                springConstant: 0.04,
                avoidOverlap: 1
            },
            stabilization: {
                enabled: true,
                iterations: 250,
                updateInterval: 25
            },
            minVelocity: 0.75
        }
    };
    const network = new vis.Network(container, data, options);
    
    // Store network reference globally for toggle function
    window.currentNetwork = network;
    currentNetwork = network;
    
    // Initialize graph filters with a delay to ensure data is available
    setTimeout(() => {
        initializeGraphFilters();
    }, 500);
    
    // Disable physics after stabilization to keep nodes static
    network.on('stabilizationIterationsDone', function() {
        console.log('Graph stabilized, disabling physics');
        network.setOptions({
            physics: {
                enabled: false
            }
        });
        // Fit the graph to show all nodes with some padding
        setTimeout(() => {
            network.fit({
                animation: {
                    duration: 1000,
                    easingFunction: 'easeInOutQuad'
                }
            });
        }, 100);
    });
    
    // Add click event for node details
    network.on('click', function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = data.nodes.get(nodeId);
            showNodeDetails(node, dependencyTree);
        }
    });

    console.log('Dependency graph rendered with', nodes.length, 'nodes and', edges.length, 'edges');
    console.log('Click the graph controls box to toggle zoom and drag interactions');
    
    // Set initial graph controls styling since interactions are disabled by default
    setTimeout(() => {
        const toggleButton = document.getElementById('graph-toggle-button');
        const toggleIcon = document.getElementById('graph-toggle-icon');
        const toggleText = document.getElementById('graph-toggle-text');
        
        if (toggleButton && toggleIcon && toggleText) {
            toggleButton.style.backgroundColor = 'rgba(255,255,255,0.97)';
            toggleButton.style.borderColor = '#e1e8ed';
            toggleIcon.classList.remove('fa-hand-pointer');
            toggleIcon.classList.add('fa-mouse-pointer');
            toggleText.textContent = 'Zoom & Drag';
        }
    }, 100);
}



function showNodeDetails(node, dependencyTree) {
    console.log('=== showNodeDetails Debug ===');
    console.log('Node clicked:', node);
    console.log('Node id:', node.id, 'label:', node.label);
    console.log('Dependency tree:', dependencyTree);
    console.log('Available vulnerability data:', window.vulnerabilityDataFromServer);
    
    // Handle root node specially
    if (node.id === 'root') {
        const popupContent = `
            <div class="node-details-popup">
                <h3>Project Root</h3>
                <div class="detail-row">
                    <strong>Type:</strong> Your Project
                </div>
                <div class="detail-row">
                    <strong>Direct Dependencies:</strong> ${dependencyTree.length}
                </div>
                <div class="detail-row">
                    <strong>Total Dependencies:</strong> ${countTotalDependencies(dependencyTree)}
                </div>
            </div>
        `;
        showModal(popupContent);
        return;
    }

    // Extract package name from node (handle both old and new formats)
    let packageName = node.package_name || node.label.split('\n')[0];
    const [name, role] = node.label.split('\n');
    console.log('Extracted name:', name, 'role:', role, 'packageName:', packageName);
    const vulnKey = packageName.toLowerCase();
    console.log('Vulnerability lookup key:', vulnKey);
    
    // Find the dependency data for this node (case-insensitive)
    const dependency = findDependencyByName(packageName, dependencyTree);
    console.log('Found dependency:', dependency);
    
    if (!dependency) {
        console.warn('No dependency found for name:', packageName, '(case-insensitive)');
        return;
    }

    // Try both original and lowercased keys for vulnerability data
    let vulnData = null;
    if (window.vulnerabilityDataFromServer) {
        vulnData = window.vulnerabilityDataFromServer[packageName] || window.vulnerabilityDataFromServer[vulnKey] || null;
    }
    // Enforce N/A for flexible/invalid versions
    function isFlexibleOrInvalidVersion(version) {
        if (!version) return true;
        if (typeof version !== 'string') version = String(version);
        return !(/[0-9]/.test(version)) || version.includes('*');
    }
    let isNA = false;
    if (node.risk_level === 'na' || isFlexibleOrInvalidVersion(node.version)) {
        isNA = true;
    }
    if (isNA) {
        // Show N/A details modal
        showNAPackageDetails(dependency, role, vulnData || { risk_level: 'na', recommendation: 'Cannot scan vulnerabilities - no vulnerability data available for this package.' });
    } else if (vulnData) {
        showVulnerabilityDetails(dependency, role, vulnData);
    } else {
        showBasicNodeDetails(dependency, role);
    }
}

function showBasicNodeDetails(dependency, role) {
    // Add GitHub information if available
    let githubSection = '';
    if (dependency.github) {
        const github = dependency.github;
        
        // Health assessment display
        let healthSection = '';
        if (github.health) {
            const health = github.health;
            const statusClass = `health-${health.overall_status}`;
            const statusIcon = health.overall_status === 'excellent' ? 'fas fa-check-circle' :
                              health.overall_status === 'good' ? 'fas fa-thumbs-up' :
                              health.overall_status === 'moderate' ? 'fas fa-exclamation-triangle' :
                              health.overall_status === 'poor' ? 'fas fa-times-circle' :
                              'fas fa-radiation';
            
            healthSection = `
                <div class="health-assessment">
                    <h4><i class="fas fa-heartbeat"></i> Repository Health</h4>
                    <div class="health-summary ${statusClass}">
                        <div class="health-status">
                            <i class="${statusIcon}"></i>
                            <span class="health-label">${health.overall_status.toUpperCase()}</span>
                            <span class="health-score">${health.overall_score}/${health.max_score}</span>
                        </div>

                    </div>
                    <div class="health-metrics">
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">POPULARITY:</span>
                            <span class="metric-value ${health.metrics.popularity.status}">${health.metrics.popularity.status.replace(/_/g, ' ')} (${health.metrics.popularity.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">MAINTENANCE:</span>
                            <span class="metric-value ${health.metrics.maintenance.status}">${health.metrics.maintenance.status.replace(/_/g, ' ')} (${health.metrics.maintenance.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">ACTIVITY:</span>
                            <span class="metric-value ${health.metrics.activity.status}">${health.metrics.activity.status.replace(/_/g, ' ')} (${health.metrics.activity.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">COMMUNITY:</span>
                            <span class="metric-value ${health.metrics.community.status}">${health.metrics.community.status.replace(/_/g, ' ')} (${health.metrics.community.score}/4)</span>
                        </div>
                    </div>
                </div>
            `;
        }
        
        githubSection = `
            <div class="github-section">
                <h4><i class="fab fa-github"></i> GitHub Repository</h4>
                <div class="github-info">
                    <div class="detail-row">
                        <strong>Repository:</strong> 
                        <a href="${github.html_url}" target="_blank" rel="noopener noreferrer">${github.full_name}</a>
                    </div>
                    ${github.description ? `
                        <div class="detail-row">
                            <strong>Description:</strong> ${github.description}
                        </div>
                    ` : ''}
                    <div class="github-stats">
                        <div class="github-stat">
                            <i class="fas fa-star"></i> ${github.stargazers_count || 0} stars
                        </div>
                        <div class="github-stat">
                            <i class="fas fa-code-branch"></i> ${github.forks_count || 0} forks
                        </div>
                        <div class="github-stat">
                            <i class="fas fa-exclamation-circle"></i> ${github.open_issues_count || 0} open issues
                        </div>
                        ${github.language ? `
                            <div class="github-stat">
                                <i class="fas fa-code"></i> ${github.language}
                            </div>
                        ` : ''}
                        ${github.pushed_at ? `
                            <div class="github-stat">
                                <i class="fas fa-clock"></i> Last Updated: ${new Date(github.pushed_at).toLocaleDateString()}
                            </div>
                        ` : ''}
                    </div>
                    ${healthSection}
                </div>
            </div>
        `;
    }

    const popupContent = `
        <div class="node-details-popup">
            <h3>${dependency.name}</h3>
            <div class="detail-row">
                <strong>Role:</strong> ${role.replace(/[()]/g, '')}
            </div>
            <div class="detail-row">
                <strong>Version:</strong> ${dependency.version || 'Not specified'}
            </div>
            <div class="detail-row">
                <strong>Type:</strong> ${dependency.type || 'python'}
            </div>
            <div class="detail-row">
                <strong>Sub-dependencies:</strong> ${dependency.subdependencies ? dependency.subdependencies.length : 0}
            </div>
            ${dependency.subdependencies && dependency.subdependencies.length > 0 ? `
                <div class="subdeps-list">
                    <strong>Sub-dependencies:</strong>
                    <ul>
                        ${dependency.subdependencies.map(sub => `<li>${sub.name} (Sub-dependency)</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            ${githubSection}
        </div>
    `;
    showModal(popupContent);
}

function showVulnerabilityDetails(dependency, role, vulnData) {
    console.log('=== showVulnerabilityDetails Debug ===');
    console.log('Dependency:', dependency);
    console.log('Vulnerability data:', vulnData);
    console.log('Vulnerabilities array:', vulnData.vulnerabilities);
    
    const riskClass = `risk-${vulnData.risk_level}`;
    const riskScore = vulnData.risk_score || 0;
    const vulnCount = vulnData.vulnerability_count || 0;
    
    // Separate current and future vulnerabilities
    let currentVulns = [];
    let futureVulns = [];
    if (vulnData.vulnerabilities && vulnData.vulnerabilities.length > 0) {
        vulnData.vulnerabilities.forEach(vuln => {
            // If the vuln has an 'affected_versions' or 'fixed_versions' field, use it to determine if it's a future vuln
            // For now, use a custom field 'future_vuln' if present, else treat all as current
            if (vuln.future_vuln) {
                futureVulns.push(vuln);
            } else {
                currentVulns.push(vuln);
            }
        });
    }
    
    // Sort vulnerabilities by severity (critical to none)
    function vulnSort(a, b) {
        const sevOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'none': 4 };
        const aSev = sevOrder[a.severity] ?? 5;
        const bSev = sevOrder[b.severity] ?? 5;
        
        // If same severity, sort by CVSS score (higher first)
        if (aSev === bSev) {
            const aScore = parseFloat(a.cvss_score) || 0;
            const bScore = parseFloat(b.cvss_score) || 0;
            return bScore - aScore;
        }
        
        return aSev - bSev;
    }
    currentVulns.sort(vulnSort);
    futureVulns.sort(vulnSort);

    let vulnList = '';
    if (currentVulns.length > 0) {
        vulnList = `
            <div class="vulnerabilities-section">
                <h4>Vulnerabilities Found (${currentVulns.length})</h4>
                <div class="vuln-list">
                    ${currentVulns.map(vuln => {
                        const severityClass = vuln.severity || 'none';
                        const cvssDisplay = vuln.cvss_score ? `CVSS: ${vuln.cvss_score}` : '';
                        const vulnId = vuln.cve_id || vuln.id || 'Unknown';
                        const vulnTitle = vuln.title || vuln.description || 'No title available';
                        const vulnDesc = vuln.description || vuln.title || 'No description available';
                        
                        return `
                            <div class="vuln-item risk-${severityClass}">
                            <div class="vuln-header">
                                    <div class="vuln-id-section">
                                        <strong>${vulnId}</strong>
                                        ${cvssDisplay ? `<span class="cvss-badge">${cvssDisplay}</span>` : ''}
                            </div>
                                    <span class="severity-badge ${severityClass}">${severityClass.toUpperCase()}</span>
                                </div>
                                <div class="vuln-title">${vulnTitle}</div>
                                <div class="vuln-description">${vulnDesc}</div>
                                ${vuln.recommendation ? `
                            <div class="vuln-recommendation">
                                <strong>Recommendation:</strong> ${vuln.recommendation}
                            </div>
                                ` : ''}
                            ${vuln.references && vuln.references.length > 0 ? `
                                <div class="vuln-references">
                                    <strong>References:</strong>
                                    <ul>
                                            ${vuln.references.map(ref => `<li><a href="${ref}" target="_blank" rel="noopener noreferrer">${ref}</a></li>`).join('')}
                                    </ul>
                                </div>
                            ` : ''}
                        </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
    }
    
    let futureVulnList = '';
    if (futureVulns.length > 0) {
        futureVulnList = `
            <div class="future-vulnerabilities-section">
                <h4>Future Vulnerabilities (${futureVulns.length})</h4>
                <div class="future-vuln-explanation">
                    <em>These vulnerabilities affect newer versions than the one you are currently using. Be cautious when upgrading.</em>
                </div>
                <div class="vuln-list">
                    ${futureVulns.map(vuln => {
                        const severityClass = vuln.severity || 'none';
                        const cvssDisplay = vuln.cvss_score ? `CVSS: ${vuln.cvss_score}` : '';
                        const vulnId = vuln.cve_id || vuln.id || 'Unknown';
                        const vulnTitle = vuln.title || vuln.description || 'No title available';
                        const vulnDesc = vuln.description || vuln.title || 'No description available';
                        
                        return `
                            <div class="vuln-item risk-${severityClass}">
                                <div class="vuln-header">
                                    <div class="vuln-id-section">
                                        <strong>${vulnId}</strong>
                                        ${cvssDisplay ? `<span class="cvss-badge">${cvssDisplay}</span>` : ''}
                                    </div>
                                    <span class="severity-badge ${severityClass}">${severityClass.toUpperCase()}</span>
                                </div>
                                <div class="vuln-title">${vulnTitle}</div>
                                <div class="vuln-description">${vulnDesc}</div>
                                ${vuln.recommendation ? `
                            <div class="vuln-recommendation">
                                <strong>Recommendation:</strong> ${vuln.recommendation}
                            </div>
                                ` : ''}
                            ${vuln.references && vuln.references.length > 0 ? `
                                <div class="vuln-references">
                                    <strong>References:</strong>
                                    <ul>
                                            ${vuln.references.map(ref => `<li><a href="${ref}" target="_blank" rel="noopener noreferrer">${ref}</a></li>`).join('')}
                                    </ul>
                                </div>
                            ` : ''}
                        </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
    }
    
    // Add GitHub information if available
    let githubSection = '';
    if (dependency.github) {
        const github = dependency.github;
        
        // Health assessment display
        let healthSection = '';
        if (github.health) {
            const health = github.health;
            const statusClass = `health-${health.overall_status}`;
            const statusIcon = health.overall_status === 'excellent' ? 'fas fa-check-circle' :
                              health.overall_status === 'good' ? 'fas fa-thumbs-up' :
                              health.overall_status === 'moderate' ? 'fas fa-exclamation-triangle' :
                              health.overall_status === 'poor' ? 'fas fa-times-circle' :
                              'fas fa-radiation';
            
            healthSection = `
                <div class="health-assessment">
                    <h4><i class="fas fa-heartbeat"></i> Repository Health</h4>
                    <div class="health-summary ${statusClass}">
                        <div class="health-status">
                            <i class="${statusIcon}"></i>
                            <span class="health-label">${health.overall_status.toUpperCase()}</span>
                            <span class="health-score">${health.overall_score}/${health.max_score}</span>
                        </div>
                    </div>
                    <div class="health-metrics">
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">POPULARITY:</span>
                            <span class="metric-value ${health.metrics.popularity.status}">${health.metrics.popularity.status.replace(/_/g, ' ')} (${health.metrics.popularity.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">MAINTENANCE:</span>
                            <span class="metric-value ${health.metrics.maintenance.status}">${health.metrics.maintenance.status.replace(/_/g, ' ')} (${health.metrics.maintenance.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">ACTIVITY:</span>
                            <span class="metric-value ${health.metrics.activity.status}">${health.metrics.activity.status.replace(/_/g, ' ')} (${health.metrics.activity.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">COMMUNITY:</span>
                            <span class="metric-value ${health.metrics.community.status}">${health.metrics.community.status.replace(/_/g, ' ')} (${health.metrics.community.score}/4)</span>
                        </div>
                    </div>
                </div>
            `;
        }
        
        githubSection = `
            <div class="github-section">
                <h4><i class="fab fa-github"></i> GitHub Repository</h4>
                <div class="github-info">
            <div class="detail-row">
                        <strong>Repository:</strong> 
                        <a href="${github.html_url}" target="_blank" rel="noopener noreferrer">${github.full_name}</a>
            </div>
                    ${github.description ? `
                        <div class="detail-row">
                            <strong>Description:</strong> ${github.description}
                        </div>
                    ` : ''}
                    <div class="github-stats">
                        <div class="github-stat">
                            <i class="fas fa-star"></i> ${github.stargazers_count || 0} stars
                        </div>
                        <div class="github-stat">
                            <i class="fas fa-code-branch"></i> ${github.forks_count || 0} forks
                        </div>
                        <div class="github-stat">
                            <i class="fas fa-exclamation-circle"></i> ${github.open_issues_count || 0} open issues
                        </div>
                        ${github.language ? `
                            <div class="github-stat">
                                <i class="fas fa-code"></i> ${github.language}
                            </div>
                        ` : ''}
                        ${github.pushed_at ? `
                            <div class="github-stat">
                                <i class="fas fa-clock"></i> Last Updated: ${new Date(github.pushed_at).toLocaleDateString()}
                            </div>
                        ` : ''}
                    </div>
                    ${healthSection}
                </div>
            </div>
        `;
    }

    const popupContent = `
        <div class="node-details-popup wide-node-modal">
            <div class="node-modal-columns">
                <div class="node-modal-left">
                    <h3>${dependency.name}</h3>
            <div class="detail-row">
                <strong>Version:</strong> ${dependency.version || 'Not specified'}
            </div>
            <div class="detail-row">
                <strong>Type:</strong> ${dependency.type || 'python'}
            </div>
            <div class="detail-row">
                <strong>Sub-dependencies:</strong> ${dependency.subdependencies ? dependency.subdependencies.length : 0}
            </div>
                    ${githubSection}
                </div>
                <div class="node-modal-right">
                    <div class="security-section spaced-security-section">
                <h4>Security Assessment</h4>
                <div class="risk-summary">
                    <div class="risk-level ${riskClass}">
                                <strong>Risk Level:</strong> ${vulnData.risk_level.toUpperCase()} (${riskScore.toFixed(1)})
                    </div>
                    <div class="risk-score">
                                <strong>Vulnerability Count:</strong> ${vulnCount}
                    </div>
                <div class="recommendation">
                    <strong>Recommendation:</strong> ${vulnData.recommendation}
                    </div>
                </div>
                    </div>
                    <div class="vulnerability-list-container">
            ${vulnList}
                        ${futureVulnList}
                    </div>
                </div>
            </div>
        </div>
    `;
    showModal(popupContent);
}

function showNAPackageDetails(dependency, role, vulnData) {
    console.log('=== showNAPackageDetails Debug ===');
    console.log('Dependency:', dependency);
    console.log('Vulnerability data:', vulnData);

    // Add GitHub information if available
    let githubSection = '';
    if (dependency.github) {
        const github = dependency.github;
        
        // Health assessment display
        let healthSection = '';
        if (github.health) {
            const health = github.health;
            const statusClass = `health-${health.overall_status}`;
            const statusIcon = health.overall_status === 'excellent' ? 'fas fa-check-circle' :
                              health.overall_status === 'good' ? 'fas fa-thumbs-up' :
                              health.overall_status === 'moderate' ? 'fas fa-exclamation-triangle' :
                              health.overall_status === 'poor' ? 'fas fa-times-circle' :
                              'fas fa-radiation';
            
            healthSection = `
                <div class="health-assessment">
                    <h4><i class="fas fa-heartbeat"></i> Repository Health</h4>
                    <div class="health-summary ${statusClass}">
                        <div class="health-status">
                            <i class="${statusIcon}"></i>
                            <span class="health-label">${health.overall_status.toUpperCase()}</span>
                            <span class="health-score">${health.overall_score}/${health.max_score}</span>
                </div>
            </div>
                    <div class="health-metrics">
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">POPULARITY:</span>
                            <span class="metric-value ${health.metrics.popularity.status}">${health.metrics.popularity.status.replace(/_/g, ' ')} (${health.metrics.popularity.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">MAINTENANCE:</span>
                            <span class="metric-value ${health.metrics.maintenance.status}">${health.metrics.maintenance.status.replace(/_/g, ' ')} (${health.metrics.maintenance.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">ACTIVITY:</span>
                            <span class="metric-value ${health.metrics.activity.status}">${health.metrics.activity.status.replace(/_/g, ' ')} (${health.metrics.activity.score}/4)</span>
                        </div>
                        <div class="health-metric">
                            <span class="metric-label" style="font-weight:bold;text-transform:uppercase;">COMMUNITY:</span>
                            <span class="metric-value ${health.metrics.community.status}">${health.metrics.community.status.replace(/_/g, ' ')} (${health.metrics.community.score}/4)</span>
                        </div>
                    </div>
                </div>
            `;
        }
        
        githubSection = `
            <div class="github-section">
                <h4><i class="fab fa-github"></i> GitHub Repository</h4>
                <div class="github-info">
                    <div class="detail-row">
                        <strong>Repository:</strong> 
                        <a href="${github.html_url}" target="_blank" rel="noopener noreferrer">${github.full_name}</a>
                    </div>
                    ${github.description ? `
                        <div class="detail-row">
                            <strong>Description:</strong> ${github.description}
                        </div>
                    ` : ''}
                    <div class="github-stats">
                        <div class="github-stat">
                            <i class="fas fa-star"></i> ${github.stargazers_count || 0} stars
                        </div>
                        <div class="github-stat">
                            <i class="fas fa-code-branch"></i> ${github.forks_count || 0} forks
                        </div>
                        <div class="github-stat">
                            <i class="fas fa-exclamation-circle"></i> ${github.open_issues_count || 0} open issues
                        </div>
                        ${github.language ? `
                            <div class="github-stat">
                                <i class="fas fa-code"></i> ${github.language}
                            </div>
                        ` : ''}
                        ${github.pushed_at ? `
                            <div class="github-stat">
                                <i class="fas fa-clock"></i> Last Updated: ${new Date(github.pushed_at).toLocaleDateString()}
                            </div>
                        ` : ''}
                    </div>
                    ${healthSection}
                </div>
            </div>
        `;
    }

    const popupContent = `
        <div class="node-details-popup">
            <h3>${dependency.name}</h3>
            <div class="detail-row">
                <strong>Role:</strong> ${role.replace(/[()]/g, '')}
            </div>
            <div class="detail-row">
                <strong>Version:</strong> ${dependency.version || 'Not specified'}
            </div>
            <div class="detail-row">
                <strong>Type:</strong> ${dependency.type || 'python'}
            </div>
            <div class="detail-row">
                <strong>Sub-dependencies:</strong> ${dependency.subdependencies ? dependency.subdependencies.length : 0}
            </div>
            ${dependency.subdependencies && dependency.subdependencies.length > 0 ? `
                <div class="subdeps-list">
                    <strong>Sub-dependencies:</strong>
                    <ul>
                        ${dependency.subdependencies.map(sub => `<li>${sub.name} (Sub-dependency)</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            <div class="security-section">
                <h4><i class="fas fa-shield-alt"></i> Security Assessment</h4>
                <div class="risk-summary risk-na">
                    <div class="risk-level">
                        <strong>Status:</strong> <span class="na-status">N/A</span>
                    </div>
                    <div class="recommendation">
                        <strong>Reason:</strong> ${vulnData.recommendation}
                    </div>
                </div>
            </div>
            ${githubSection}
        </div>
    `;
    showModal(popupContent);
}

function countTotalDependencies(dependencyTree) {
    let count = 0;
    for (const dep of dependencyTree) {
        count++; // Count the dependency itself
        if (dep.subdependencies) {
            count += dep.subdependencies.length; // Count sub-dependencies
        }
    }
    return count;
}

function findDependencyByName(name, dependencyTree) {
    // Recursively search for dependency by name (case-insensitive)
    const normalized = name.toLowerCase();
    for (const dep of dependencyTree) {
        if (dep.name && dep.name.toLowerCase() === normalized) return dep;
        if (dep.subdependencies) {
            const found = findDependencyByName(name, dep.subdependencies);
            if (found) return found;
        }
    }
    return null;
}

function showModal(content) {
    // Remove any existing modal first
    const existingModal = document.querySelector('.modal-overlay');
    if (existingModal) {
        document.body.removeChild(existingModal);
        // Re-enable scrolling when removing modal
        document.body.style.overflow = 'auto';
    }
    
    // Hide any existing tooltips
    const tooltips = document.querySelectorAll('.vis-tooltip');
    tooltips.forEach(tooltip => tooltip.style.display = 'none');
    
    // Disable scrolling on the background page
    document.body.style.overflow = 'hidden';
    
    // Create new modal
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    // Check if this is a node details popup and apply wide class to modal-content
    let modalContentClass = 'modal-content';
    if (content.includes('node-details-popup')) {
        modalContentClass += ' wide-node-modal';
    }
    modal.innerHTML = `
        <div class="${modalContentClass}">
            <span class="modal-close">&times;</span>
            ${content}
        </div>
    `;
    
    modal.querySelector('.modal-close').onclick = () => {
        document.body.removeChild(modal);
        // Re-enable scrolling when closing modal
        document.body.style.overflow = 'auto';
    };
    
    modal.onclick = (e) => {
        if (e.target === modal) {
            document.body.removeChild(modal);
            // Re-enable scrolling when clicking outside modal
            document.body.style.overflow = 'auto';
        }
    };
    
    document.body.appendChild(modal);
}

function initializeResults(data) {
    console.log('=== initializeResults Debug ===');
    console.log('Full SBOM data received:', data);
    console.log('Data keys:', Object.keys(data));
    
    // Extract SBOM data from the correct structure
    const sbomData = data.sbom || data;
    console.log('Extracted sbomData:', sbomData);
    console.log('sbomData keys:', Object.keys(sbomData));
    
    // Store vulnerability data globally for access in graph rendering
    // Use data from server session if available, otherwise fall back to data.vulnerabilities
    window.vulnerabilityData = window.vulnerabilityDataFromServer || data.vulnerabilities || {};
    console.log('Stored vulnerability data:', window.vulnerabilityData);
    console.log('Vulnerability data keys:', Object.keys(window.vulnerabilityData));
    
    // Debug: Show sample vulnerability data structure
    if (Object.keys(window.vulnerabilityData).length > 0) {
        const firstKey = Object.keys(window.vulnerabilityData)[0];
        console.log('Sample vulnerability data for', firstKey, ':', window.vulnerabilityData[firstKey]);
        
        // Check if vulnerabilities array exists and has content
        const sampleData = window.vulnerabilityData[firstKey];
        if (sampleData.vulnerabilities) {
            console.log('Vulnerabilities array length:', sampleData.vulnerabilities.length);
            if (sampleData.vulnerabilities.length > 0) {
                console.log('First vulnerability:', sampleData.vulnerabilities[0]);
            }
        }
    }
    
    // Log SBOM data for debugging
    console.log('SBOM dependencies field:', sbomData.dependencies);
    console.log('SBOM vulnerabilities field:', sbomData.vulnerabilities);
    console.log('SBOM security issues field:', sbomData.security_issues);
    
    // Display summary
    displaySummary(sbomData);
    
    // Load health data first, then render graph
    loadPackageHealthData().then(() => {
        // Display dependency graph after health data is loaded
        if (sbomData.dependency_tree) {
            console.log('Rendering dependency graph with:', sbomData.dependency_tree);
            renderDependencyGraph(sbomData.dependency_tree);
        } else {
            console.log('No dependency_tree found in sbomData');
        }
    }).catch(err => {
        console.error('Failed to load health data, rendering graph anyway:', err);
        // Fallback: render graph even if health data fails to load
        if (sbomData.dependency_tree) {
            console.log('Rendering dependency graph with:', sbomData.dependency_tree);
            renderDependencyGraph(sbomData.dependency_tree);
        }
    });
    
    // Log final data summary for debugging
    console.log('Final data summary:');
    console.log('Dependencies:', sbomData.dependencies);
    console.log('Dependency tree:', sbomData.dependency_tree);
}

// Helper to count unique dependencies in the full tree
function countUniqueDependencies(tree, seen = new Set()) {
    if (!Array.isArray(tree)) return 0;
    for (const dep of tree) {
        if (dep.name) {
            const normalizedName = dep.name.toLowerCase();
            if (!seen.has(normalizedName)) {
                seen.add(normalizedName);
                // Debug: log each unique dependency found (normalized)
                console.log('Counting dependency:', normalizedName);
                if (Array.isArray(dep.subdependencies)) {
                    countUniqueDependencies(dep.subdependencies, seen);
                }
            }
        } else {
            console.warn('Dependency without a name property:', dep);
        }
    }
    return seen.size;
}

// Update summary to use deduplicated nodes
function displaySummary(data) {
    console.log('Displaying summary with data:', data);
    const projectType = document.getElementById('project-type');
    const directDeps = document.getElementById('direct-deps');
    const totalDeps = document.getElementById('total-deps');
    if (projectType) projectType.textContent = typeof data.project_type === 'string' ? data.project_type : 'Unknown';
    const directDepsCount = Array.isArray(data.dependencies) ? data.dependencies.length : 0;
    // Use deduplicated nodes for total
    const { nodes } = deduplicateDependencies(data.dependency_tree);
    const totalDepsCount = nodes.length;
    if (directDeps) directDeps.textContent = directDepsCount;
    if (totalDeps) totalDeps.textContent = totalDepsCount;
    console.log('Updated summary stats:', {
        projectType: data.project_type,
        directDeps: directDepsCount,
        totalDeps: totalDepsCount
    });
    
    // Display dependencies lists
    if (Array.isArray(data.dependencies)) {
        displayDirectDependencies(data.dependencies);
    }
    if (data.dependency_tree) {
        displaySubDependencies(data.dependency_tree);
    }
}

// Enhanced toggleDependencies function to initialize search when expanded
function toggleDependencies(listId, iconId) {
    const list = document.getElementById(listId);
    const icon = document.getElementById(iconId);
    if (!list || !icon) return;
    const isCollapsed = list.classList.contains('collapsed');
    
    if (isCollapsed) {
        list.classList.remove('collapsed');
        list.classList.add('expanded');
        icon.classList.remove('fa-chevron-right');
        icon.classList.add('fa-chevron-down');
    } else {
        list.classList.remove('expanded');
        list.classList.add('collapsed');
        icon.classList.remove('fa-chevron-down');
        icon.classList.add('fa-chevron-right');
    }
}

// Function to ensure dependency sections start in correct collapsed state
function initializeDependencySections() {
    // Ensure direct dependencies section starts collapsed
    const directDepsList = document.getElementById('direct-dependencies-list');
    const directDepsIcon = document.getElementById('direct-deps-icon');
    if (directDepsList && directDepsIcon) {
        directDepsList.classList.remove('expanded');
        directDepsList.classList.add('collapsed');
        directDepsIcon.classList.remove('fa-chevron-down');
        directDepsIcon.classList.add('fa-chevron-right');
    }
    
    // Ensure sub-dependencies section starts collapsed
    const allDepsList = document.getElementById('all-dependencies-list');
    const allDepsIcon = document.getElementById('all-deps-icon');
    if (allDepsList && allDepsIcon) {
        allDepsList.classList.remove('expanded');
        allDepsList.classList.add('collapsed');
        allDepsIcon.classList.remove('fa-chevron-down');
        allDepsIcon.classList.add('fa-chevron-right');
    }
}

// Display direct dependencies in list format
function displayDirectDependencies(dependencies) {
    const directDepsList = document.getElementById("direct-dependencies-list");
    if (!directDepsList) return;
    
    if (!Array.isArray(dependencies) || dependencies.length === 0) {
        // Keep the search bar but replace the content area
        const searchBar = directDepsList.querySelector('.search-container');
        directDepsList.innerHTML = '';
        if (searchBar) {
            directDepsList.appendChild(searchBar);
        }
        const noDepsMsg = document.createElement('p');
        noDepsMsg.textContent = 'No direct dependencies found.';
        directDepsList.appendChild(noDepsMsg);
        return;
    }
    
    // Deduplicate dependencies by name (case-insensitive), keeping the highest version
    const deduplicatedDeps = [];
    const seenPackages = new Map(); // name.toLowerCase() -> {dep, version}
    
    dependencies.forEach(dep => {
        if (!dep.name) return;
        const key = dep.name.toLowerCase();
        const existing = seenPackages.get(key);
        
        if (!existing || compareVersions(dep.version, existing.version) > 0) {
            seenPackages.set(key, dep);
        }
    });
    
    // Convert back to array
    const uniqueDeps = Array.from(seenPackages.values());
    
    // Sort dependencies by risk level: critical -> high -> medium -> low -> safe -> na
    const riskPriority = {
        'critical': 6,
        'high': 5,
        'medium': 4,
        'low': 3,
        'safe': 2,
        'na': 1
    };
    function isFlexibleOrInvalidVersion(version) {
        if (!version) return true;
        if (typeof version !== 'string') version = String(version);
        return !(/[0-9]/.test(version)) || version.includes('*');
    }
    // Direct dependencies
    const sortedDeps = uniqueDeps.sort((a, b) => {
        function getRiskLevel(dep) {
            const vulnData = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[dep.name] ? window.vulnerabilityDataFromServer[dep.name] : null;
            if (!dep.version || typeof dep.version !== 'string' || !(/[0-9]/.test(dep.version)) || dep.version.includes('*')) {
                return 'na';
            }
            // If no vulnData, treat as 'na' (not 'safe')
            return vulnData ? vulnData.risk_level : 'na';
        }
        const riskLevelA = getRiskLevel(a);
        const riskLevelB = getRiskLevel(b);
        const priorityA = riskPriority[riskLevelA] || 0;
        const priorityB = riskPriority[riskLevelB] || 0;
        if (priorityA !== priorityB) {
            return priorityB - priorityA;
        }
        return (a.name || '').localeCompare(b.name || '');
    });
    
    // Preserve the search bar
    const searchBar = directDepsList.querySelector('.search-container');
    directDepsList.innerHTML = '';
    if (searchBar) {
        directDepsList.appendChild(searchBar);
    }
    
    // Create a container for the dependency items
    const itemsContainer = document.createElement('div');
    itemsContainer.id = 'direct-dependencies-items';
    
    sortedDeps.forEach(dep => {
        const vulnData = window.vulnerabilityDataFromServer && 
                        window.vulnerabilityDataFromServer[dep.name] ? 
                        window.vulnerabilityDataFromServer[dep.name] : null;
        const forceNA = !vulnData || (vulnData && vulnData.risk_level === 'na');
        const depItem = createDependencyItem(dep, false, forceNA, 'direct', false);
        itemsContainer.appendChild(depItem);
    });
    
    directDepsList.appendChild(itemsContainer);
}

// Display sub-dependencies in list format
function displaySubDependencies(dependencyTree) {
    const allDepsList = document.getElementById("all-dependencies-list");
    if (!allDepsList) return;
    
    // Get all unique dependencies from the tree (excluding direct dependencies)
    const subDeps = getSubDependenciesFromTree(dependencyTree);
    
    if (subDeps.length === 0) {
        // Keep the search bar but replace the content area
        const searchBar = allDepsList.querySelector('.search-container');
        allDepsList.innerHTML = '';
        if (searchBar) {
            allDepsList.appendChild(searchBar);
        }
        const noDepsMsg = document.createElement('p');
        noDepsMsg.textContent = 'No sub-dependencies found.';
        allDepsList.appendChild(noDepsMsg);
        return;
    }
    
    // Deduplicate sub-dependencies by name (case-insensitive), keeping the highest version
    const seenSubPackages = new Map(); // name.toLowerCase() -> {dep, version}
    
    subDeps.forEach(dep => {
        if (!dep.name) return;
        const key = dep.name.toLowerCase();
        const existing = seenSubPackages.get(key);
        
        if (!existing || compareVersions(dep.version, existing.version) > 0) {
            seenSubPackages.set(key, dep);
        }
    });
    
    // Convert back to array
    const uniqueSubDeps = Array.from(seenSubPackages.values());
    
    // Sort dependencies by risk level: critical -> high -> medium -> low -> safe -> na
    const riskPriority = {
        'critical': 6,
        'high': 5,
        'medium': 4,
        'low': 3,
        'safe': 2,
        'na': 1
    };
    function isFlexibleOrInvalidVersion(version) {
        if (!version) return true;
        if (typeof version !== 'string') version = String(version);
        return !(/[0-9]/.test(version)) || version.includes('*');
    }
    // Sub-dependencies
    const sortedSubDeps = uniqueSubDeps.sort((a, b) => {
        function getRiskLevel(dep) {
            const vulnData = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[dep.name] ? window.vulnerabilityDataFromServer[dep.name] : null;
            if (!dep.version || typeof dep.version !== 'string' || !(/[0-9]/.test(dep.version)) || dep.version.includes('*')) {
                return 'na';
            }
            return vulnData ? vulnData.risk_level : 'na';
        }
        const riskLevelA = getRiskLevel(a);
        const riskLevelB = getRiskLevel(b);
        const priorityA = riskPriority[riskLevelA] || 0;
        const priorityB = riskPriority[riskLevelB] || 0;
        if (priorityA !== priorityB) {
            return priorityB - priorityA;
        }
        return (a.name || '').localeCompare(b.name || '');
    });
    
    // Preserve the search bar
    const searchBar = allDepsList.querySelector('.search-container');
    allDepsList.innerHTML = '';
    if (searchBar) {
        allDepsList.appendChild(searchBar);
    }
    
    // Create a container for the dependency items
    const itemsContainer = document.createElement('div');
    itemsContainer.id = 'sub-dependencies-items';
    
    sortedSubDeps.forEach(dep => {
        const vulnData = window.vulnerabilityDataFromServer && 
                        window.vulnerabilityDataFromServer[dep.name] ? 
                        window.vulnerabilityDataFromServer[dep.name] : null;
        const forceNA = !vulnData || (vulnData && vulnData.risk_level === 'na');
        const depItem = createDependencyItem(dep, false, forceNA, 'sub', false);
        itemsContainer.appendChild(depItem);
    });
    
    allDepsList.appendChild(itemsContainer);
}

// Helper function to get sub-dependencies from the tree (excluding direct dependencies)
function getSubDependenciesFromTree(tree, seen = new Set(), directDeps = new Set()) {
    const subDeps = [];
    
    // First pass: collect direct dependency names
    if (Array.isArray(tree)) {
        tree.forEach(dep => {
            if (dep.name) {
                directDeps.add(dep.name.toLowerCase());
            }
        });
    }
    
    function traverse(node) {
        if (!node.name) return;
        
        const normalizedName = node.name.toLowerCase();
        
        // Only add if it's not a direct dependency and we haven't seen it before
        if (!directDeps.has(normalizedName) && !seen.has(normalizedName)) {
            seen.add(normalizedName);
            subDeps.push(node);
        }
        
        if (Array.isArray(node.subdependencies)) {
            node.subdependencies.forEach(traverse);
        }
    }
    
    if (Array.isArray(tree)) {
        tree.forEach(traverse);
    }
    
    return subDeps;
}

// Show dependency details when clicked
function showDependencyDetails(depName, depVersion, source) {
    console.log('Showing details for:', depName, depVersion, source);
    
    // Find the dependency in the appropriate data source
    let dependency = null;
    let dependencyTree = null;
    
    if (source === 'direct') {
        // Look in direct dependencies
        const directDeps = window.sbomDataFromServer && window.sbomDataFromServer.dependencies;
        if (Array.isArray(directDeps)) {
            dependency = directDeps.find(dep => dep.name === depName);
        }
    } else {
        // Look in all dependencies tree
        dependencyTree = window.sbomDataFromServer && window.sbomDataFromServer.dependency_tree;
        if (Array.isArray(dependencyTree)) {
            dependency = findDependencyByName(depName, dependencyTree);
        }
    }
    
    if (!dependency) {
        // Create a minimal dependency object if not found
        dependency = {
            name: depName,
            version: depVersion,
            type: 'python'
        };
    }
    
    // Get vulnerability data
    const vulnData = window.vulnerabilityDataFromServer && 
                    window.vulnerabilityDataFromServer[depName] ? 
                    window.vulnerabilityDataFromServer[depName] : null;
    
    // Show the details using existing modal system
    if (vulnData) {
        // Check if this is an N/A package (unknown version)
        if (vulnData.risk_level === 'na') {
            showNAPackageDetails(dependency, source, vulnData);
        } else {
            showVulnerabilityDetails(dependency, source, vulnData);
        }
    } else {
        showBasicNodeDetails(dependency, source);
    }
}

// Export SBOM analysis results to Excel
function exportToExcel() {
    // Show loading state
    const exportBtn = document.querySelector('.export-btn');
    const originalText = exportBtn.innerHTML;
    exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating Excel...';
    exportBtn.disabled = true;
    
    // Make request to server to generate Excel file
    fetch('/export_excel', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Export failed');
        }
        return response.blob();
    })
    .then(blob => {
        // Create download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sbom_analysis_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.xlsx`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        // Show success message
        alert('Excel report exported successfully!');
    })
    .catch(error => {
        console.error('Error exporting to Excel:', error);
        alert('Error exporting to Excel. Please try again.');
    })
    .finally(() => {
        // Restore button state
        exportBtn.innerHTML = originalText;
        exportBtn.disabled = false;
    });
}

function showError(message) {
    const container = document.querySelector('.results-container');
    if (container) {
        container.innerHTML = `
            <div class="error-message">
                <h3>Error</h3>
                <p>${message}</p>
            </div>
        `;
    }
} 

// Global health data storage
window.healthDataFromServer = null;

function loadPackageHealthData() {
    // Get scan_id from URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('scan_id');
    
    // Build the API URL with scan_id parameter if available
    let apiUrl = '/api/package_health';
    if (scanId) {
        apiUrl += `?scan_id=${scanId}`;
    }
    
    return fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            // Store health data globally
            window.healthDataFromServer = data;
            
            if (data.total_issues > 0) {
                displayPackageHealthWarning(data);
            }
            
            return data; // Return data for chaining
        })
        .catch(err => {
            console.error('Failed to fetch package health data:', err);
            throw err; // Re-throw for error handling
        });
}

// Function to check if a package has health issues
function getPackageHealthIssue(packageName) {
    if (!window.healthDataFromServer || !window.healthDataFromServer.issues) {
        return null;
    }
    
    return window.healthDataFromServer.issues.find(issue => 
        issue.package_name.toLowerCase() === packageName.toLowerCase()
    );
}

// Display package health warning
function displayPackageHealthWarning(healthData) {
    const warningDiv = document.getElementById('package-health-warning');
    const contentDiv = document.getElementById('package-health-content');
    
    if (!warningDiv || !contentDiv) return;
    
    let html = '';
    
    if (healthData.issues && healthData.issues.length > 0) {
        html += '<div class="health-issues-list">';
        healthData.issues.forEach(issue => {
            const severityClass = `health-${issue.severity}`;
            const severityIcon = issue.severity === 'critical' ? 'fas fa-radiation' :
                               issue.severity === 'high' ? 'fas fa-exclamation-triangle' :
                               issue.severity === 'medium' ? 'fas fa-exclamation-circle' :
                               'fas fa-info-circle';
            
            html += `
                <div class="health-issue ${severityClass}">
                    <div class="health-issue-header">
                        <i class="${severityIcon}"></i>
                        <strong>${issue.package_name}</strong>
                        ${issue.version ? `(${issue.version})` : ''}
                        <span class="severity-badge ${issue.severity}">${issue.severity.toUpperCase()}</span>
                    </div>
                    <div class="health-issue-details">
                        <p>${issue.details.warning}</p>
                        <p><strong>Recommendation:</strong> ${issue.details.recommendation}</p>
                        ${issue.details.replacement ? `<p><strong>Replacement:</strong> ${issue.details.replacement}</p>` : ''}
                    </div>
                </div>
            `;
        });
        html += '</div>';
    }
    
    contentDiv.innerHTML = html;
    warningDiv.style.display = 'block';
} 

// Graph filtering functionality
let currentGraphData = null;
let currentNetwork = null;
let selectedDependencies = new Set();

// Initialize graph filter dropdowns
function initializeGraphFilters() {
    const filterSelect = document.getElementById('graph-filter');
    const dependencyPanel = document.getElementById('dependency-selection-panel');
    
    if (!filterSelect) {
        console.log('Filter elements not found');
        return;
    }
    
    console.log('Initializing graph filters...');
    console.log('window.sbomDataFromServer:', window.sbomDataFromServer);
    
    // Populate dependency lists
    populateDependencyLists();
    
    // Show/hide dependency panel based on filter choice
    filterSelect.addEventListener('change', function() {
        console.log('Filter changed to:', this.value);
        if (this.value === 'select-direct') {
            dependencyPanel.style.display = 'block';
            console.log('Showing dependency selection panel');
        } else {
            dependencyPanel.style.display = 'none';
            console.log('Hiding dependency selection panel');
        }
    });
}

// Populate the available and selected dependency lists
function populateDependencyLists() {
    const availableList = document.getElementById('available-dependencies-list');
    const selectedList = document.getElementById('selected-dependencies-list');
    
    if (!availableList || !selectedList) return;
    
    console.log('Populating dependency lists');
    
    // Use the new function to update both lists
    updateBothDependencyLists();
}

// Create a dependency item element
function createDependencyItem(dep, isSelected, forceNA, source, isSelectionList) {
    const depItem = document.createElement('div');
    depItem.className = `dependency-item dep-item${isSelected ? ' selected' : ''}`;
    depItem.dataset.depId = dep.name.toLowerCase();

    // Get vulnerability data for color coding
    const vulnData = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[dep.name] ? window.vulnerabilityDataFromServer[dep.name] : null;
    // Check for health issues
    const healthIssue = getPackageHealthIssue(dep.name);
    let riskClass = 'risk-safe';
    let riskText = 'Safe';
    let borderColor = '#2ecc71';
    let vulnCount = 0;
    // If forceNA is true, always show as N/A and gray
    if (forceNA) {
        riskClass = 'risk-na';
        riskText = 'N/A';
        borderColor = '#95a5a6';
    } else if (vulnData) {
        if (vulnData.risk_level === 'critical' || vulnData.risk_level === 'high') {
            riskClass = 'risk-critical';
            riskText = vulnData.risk_level.toUpperCase();
            borderColor = '#dc3545';
        } else if (vulnData.risk_level === 'medium') {
            riskClass = 'risk-medium';
            riskText = 'MEDIUM';
            borderColor = '#f1c40f';
        } else if (vulnData.risk_level === 'low') {
            riskClass = 'risk-low';
            riskText = 'LOW';
            borderColor = '#2ecc71';
        } else if (vulnData.risk_level === 'safe') {
            riskClass = 'risk-safe';
            riskText = 'Safe';
            borderColor = '#2ecc71';
        }
        vulnCount = vulnData.vulnerability_count || 0;
    }
    depItem.style.borderLeft = `6px solid ${borderColor}`;
    depItem.style.cursor = 'pointer';

    const depInfo = document.createElement('div');
    depInfo.className = 'dep-info';

    // Left section: name and version
    const leftSection = document.createElement('div');
    leftSection.style.display = 'flex';
    leftSection.style.alignItems = 'center';
    leftSection.style.gap = '10px';
    const depName = document.createElement('span');
    depName.className = 'dependency-name';
    depName.textContent = dep.name;
    // Restore GitHub icon for direct dependencies with github info
    if (source === 'direct' && dep.github) {
        depName.innerHTML += githubIconSVG;
    }
    const depVersion = document.createElement('span');
    depVersion.className = 'dependency-version';
    depVersion.textContent = dep.version;
    leftSection.appendChild(depName);
    leftSection.appendChild(depVersion);

    // Right section: risk and vuln count
    const rightSection = document.createElement('div');
    rightSection.className = 'dep-right';
    const riskSpan = document.createElement('span');
    riskSpan.className = `dependency-risk ${riskClass}`;
    riskSpan.textContent = riskText;
    rightSection.appendChild(riskSpan);
    // Vulnerability count
    if (vulnData && vulnData.risk_level !== 'na' && vulnCount > 0) {
        const vulnSpan = document.createElement('span');
        vulnSpan.className = 'dependency-vulns';
        vulnSpan.textContent = `(${vulnCount} vuln${vulnCount === 1 ? '' : 's'})`;
        rightSection.appendChild(vulnSpan);
    }
    depInfo.appendChild(leftSection);
    depInfo.appendChild(rightSection);

    // Make the entire item clickable
    if (isSelectionList) {
        depItem.onclick = () => {
            if (isSelected) {
                removeDependency(dep.name.toLowerCase());
            } else {
                addDependency(dep.name.toLowerCase());
            }
        };
    } else {
        depItem.onclick = () => {
            showDependencyDetails(dep.name, dep.version, source || 'direct');
        };
    }
    depItem.appendChild(depInfo);
    return depItem;
}

// Add a dependency to the selection
function addDependency(depId) {
    selectedDependencies.add(depId);
    console.log('Added dependency:', depId);
    updateBothDependencyLists();
    applyGraphFilter();
}

// Remove a dependency from the selection
function removeDependency(depId) {
    selectedDependencies.delete(depId);
    console.log('Removed dependency:', depId);
    updateBothDependencyLists();
    applyGraphFilter();
}

// Clear all selected dependencies
function clearAllSelections() {
    selectedDependencies.clear();
    console.log('Cleared all selections');
    updateBothDependencyLists();
    applyGraphFilter();
}

// Update both available and selected dependency lists
function updateBothDependencyLists() {
    updateAvailableDependenciesList();
    updateSelectedDependenciesList();
}

// Update the available dependencies list
function updateAvailableDependenciesList() {
    const availableList = document.getElementById('available-dependencies-list');
    if (!availableList) return;
    
    let dependencies = [];
    
    // Get dependencies from sbomDataFromServer
    if (window.sbomDataFromServer && window.sbomDataFromServer.dependencies) {
        dependencies = window.sbomDataFromServer.dependencies;
    } else if (currentGraphData) {
        // Fallback to graph data
        const allNodes = currentGraphData.nodes.get();
        const allEdges = currentGraphData.edges.get();
        
        const directDeps = allEdges
            .filter(edge => edge.from === 'root')
            .map(edge => {
                const node = allNodes.find(n => n.id === edge.to);
                return node ? { name: node.package_name || node.id, version: node.version || 'unknown' } : null;
            })
            .filter(dep => dep !== null);
        
        dependencies = directDeps;
    }
    
    // Sort dependencies by risk level: critical > high > medium > low > safe > na
    const riskPriority = {
        'critical': 6,
        'high': 5,
        'medium': 4,
        'low': 3,
        'safe': 2,
        'na': 1
    };
    dependencies = dependencies.slice().sort((a, b) => {
        const vulnDataA = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[a.name] ? window.vulnerabilityDataFromServer[a.name] : null;
        const vulnDataB = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[b.name] ? window.vulnerabilityDataFromServer[b.name] : null;
        const riskLevelA = vulnDataA ? vulnDataA.risk_level : 'safe';
        const riskLevelB = vulnDataB ? vulnDataB.risk_level : 'safe';
        const priorityA = riskPriority[riskLevelA] || 0;
        const priorityB = riskPriority[riskLevelB] || 0;
        if (priorityA !== priorityB) {
            return priorityB - priorityA;
        }
        return (a.name || '').localeCompare(b.name || '');
    });

    // Clear existing list
    availableList.innerHTML = '';
    
    // Add only unselected dependencies to the available list
    dependencies.forEach(dep => {
        const depId = dep.name.toLowerCase();
        const vulnData = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[dep.name] ? window.vulnerabilityDataFromServer[dep.name] : null;
        const forceNA = !vulnData || (vulnData && vulnData.risk_level === 'na');
        if (!selectedDependencies.has(depId)) {
            const depItem = createDependencyItem(dep, false, forceNA, 'direct', true);
            availableList.appendChild(depItem);
        }
    });
    
    // Show message if no available dependencies
    if (availableList.children.length === 0) {
        availableList.innerHTML = '<div class="no-deps-message">All dependencies have been selected</div>';
    }
}

// Update the selected dependencies list
function updateSelectedDependenciesList() {
    const selectedList = document.getElementById('selected-dependencies-list');
    if (!selectedList) return;
    
    selectedList.innerHTML = '';
    
    if (selectedDependencies.size === 0) {
        selectedList.innerHTML = '<div class="no-deps-message">No dependencies selected</div>';
        return;
    }
    
    // Get dependencies from sbomDataFromServer
    let dependencies = [];
    if (window.sbomDataFromServer && window.sbomDataFromServer.dependencies) {
        dependencies = window.sbomDataFromServer.dependencies;
    }
    // Sort dependencies by risk level: critical > high > medium > low > safe > na
    const riskPriority = {
        'critical': 6,
        'high': 5,
        'medium': 4,
        'low': 3,
        'safe': 2,
        'na': 1
    };
    const selectedDeps = Array.from(selectedDependencies).map(depId => dependencies.find(d => d.name.toLowerCase() === depId)).filter(Boolean);
    const sortedSelectedDeps = selectedDeps.slice().sort((a, b) => {
        const vulnDataA = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[a.name] ? window.vulnerabilityDataFromServer[a.name] : null;
        const vulnDataB = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[b.name] ? window.vulnerabilityDataFromServer[b.name] : null;
        const riskLevelA = vulnDataA ? vulnDataA.risk_level : 'safe';
        const riskLevelB = vulnDataB ? vulnDataB.risk_level : 'safe';
        const priorityA = riskPriority[riskLevelA] || 0;
        const priorityB = riskPriority[riskLevelB] || 0;
        if (priorityA !== priorityB) {
            return priorityB - priorityA;
        }
        return (a.name || '').localeCompare(b.name || '');
    });
    // Add selected dependencies to the list
    sortedSelectedDeps.forEach(dep => {
        const vulnData = window.vulnerabilityDataFromServer && window.vulnerabilityDataFromServer[dep.name] ? window.vulnerabilityDataFromServer[dep.name] : null;
        const forceNA = !vulnData || (vulnData && vulnData.risk_level === 'na');
        const depItem = createDependencyItem(dep, true, forceNA, 'direct', true);
        selectedList.appendChild(depItem);
    });
}

// Apply graph filter based on current selection
function applyGraphFilter() {
    const filterSelect = document.getElementById('graph-filter');
    
    if (!filterSelect || !currentNetwork || !currentGraphData) return;
    
    const filterValue = filterSelect.value;
    
    console.log('Applying graph filter:', filterValue, Array.from(selectedDependencies));
    
    // Get all nodes and edges
    const allNodes = currentGraphData.nodes.get();
    const allEdges = currentGraphData.edges.get();
    
    // Determine which nodes to show based on filter
    const nodesToShow = new Set();
    const edgesToShow = [];
    
    // Always show root node
    nodesToShow.add('root');
    
    if (filterValue === 'all') {
        // Show all nodes and edges
        allNodes.forEach(node => nodesToShow.add(node.id));
        edgesToShow.push(...allEdges);
    } else if (filterValue === 'direct-only') {
        // Show only direct dependencies (nodes connected to root)
        const directDeps = allEdges
            .filter(edge => edge.from === 'root')
            .map(edge => edge.to);
        
        directDeps.forEach(dep => nodesToShow.add(dep));
        
        // Add edges from root to direct deps
        edgesToShow.push(...allEdges.filter(edge => edge.from === 'root'));
    } else if (filterValue === 'select-direct' && selectedDependencies.size > 0) {
        // Show selected direct dependencies and their sub-dependencies
        selectedDependencies.forEach(depId => {
            nodesToShow.add(depId);
            
            // Find all sub-dependencies of this dependency
            const subDeps = findSubDependencies(depId, allNodes, allEdges);
            subDeps.forEach(dep => nodesToShow.add(dep));
        });
        
        // Add edges within the selected dependency trees
        edgesToShow.push(...allEdges.filter(edge => 
            nodesToShow.has(edge.from) && nodesToShow.has(edge.to)
        ));
    }
    
    // Update graph visibility
    updateGraphVisibility(nodesToShow, edgesToShow);
}

// Find all sub-dependencies of a given dependency
function findSubDependencies(dependencyId, allNodes, allEdges) {
    const subDeps = new Set();
    const toVisit = [dependencyId];
    
    while (toVisit.length > 0) {
        const current = toVisit.pop();
        
        // Find all edges from current node
        const outgoingEdges = allEdges.filter(edge => edge.from === current);
        
        outgoingEdges.forEach(edge => {
            if (!subDeps.has(edge.to)) {
                subDeps.add(edge.to);
                toVisit.push(edge.to);
            }
        });
    }
    
    return Array.from(subDeps);
}

// Update graph visibility by showing/hiding nodes and edges
function updateGraphVisibility(nodesToShow, edgesToShow) {
    if (!currentNetwork || !currentGraphData) return;
    
    const allNodes = currentGraphData.nodes.get();
    const allEdges = currentGraphData.edges.get();
    
    // Hide all nodes first
    allNodes.forEach(node => {
        currentGraphData.nodes.update({
            id: node.id,
            hidden: !nodesToShow.has(node.id)
        });
    });
    
    // Hide all edges first
    allEdges.forEach(edge => {
        currentGraphData.edges.update({
            id: edge.id,
            hidden: true
        });
    });
    
    // Show only the edges we want
    edgesToShow.forEach(edge => {
        currentGraphData.edges.update({
            id: edge.id,
            hidden: false
        });
    });
    
    // Fit the graph to show visible nodes
    setTimeout(() => {
        currentNetwork.fit({
            animation: {
                duration: 500,
                easingFunction: 'easeInOutQuad'
            }
        });
    }, 100);
} 

// Filter available dependencies based on search input
function filterAvailableDependencies() {
    const searchInput = document.getElementById('dependency-search');
    const availableList = document.getElementById('available-dependencies-list');
    
    if (!searchInput || !availableList) return;
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    const depItems = availableList.querySelectorAll('.dep-item');
    
    depItems.forEach(item => {
        // Extract just the text content from dependency-name, excluding SVG icons
        const depNameElement = item.querySelector('.dependency-name');
        let depName = '';
        if (depNameElement) {
            // Get text content excluding SVG elements
            depName = Array.from(depNameElement.childNodes)
                .filter(node => node.nodeType === Node.TEXT_NODE)
                .map(node => node.textContent)
                .join('')
                .toLowerCase();
        }
        
        const depVersionElement = item.querySelector('.dependency-version');
        const depVersion = depVersionElement ? depVersionElement.textContent.toLowerCase() : '';
        
        // Check if search term matches name or version
        const matches = depName.includes(searchTerm) || depVersion.includes(searchTerm);
        
        if (matches || searchTerm === '') {
            item.classList.remove('hidden');
        } else {
            item.classList.add('hidden');
        }
    });
    
    // Show "no results" message if no items match
    const visibleItems = availableList.querySelectorAll('.dep-item:not(.hidden)');
    const noResultsMsg = availableList.querySelector('.no-results-message');
    
    if (visibleItems.length === 0 && searchTerm !== '') {
        if (!noResultsMsg) {
            const msg = document.createElement('div');
            msg.className = 'no-results-message';
            msg.textContent = `No dependencies found matching "${searchTerm}"`;
            availableList.appendChild(msg);
        }
    } else if (noResultsMsg) {
        noResultsMsg.remove();
    }
}

// Filter selected dependencies based on search input
function filterSelectedDependencies() {
    const searchInput = document.getElementById('selected-dependency-search');
    const selectedList = document.getElementById('selected-dependencies-list');
    
    if (!searchInput || !selectedList) return;
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    const depItems = selectedList.querySelectorAll('.dep-item');
    
    depItems.forEach(item => {
        // Extract just the text content from dependency-name, excluding SVG icons
        const depNameElement = item.querySelector('.dependency-name');
        let depName = '';
        if (depNameElement) {
            // Get text content excluding SVG elements
            depName = Array.from(depNameElement.childNodes)
                .filter(node => node.nodeType === Node.TEXT_NODE)
                .map(node => node.textContent)
                .join('')
                .toLowerCase();
        }
        
        const depVersionElement = item.querySelector('.dependency-version');
        const depVersion = depVersionElement ? depVersionElement.textContent.toLowerCase() : '';
        
        // Check if search term matches name or version
        const matches = depName.includes(searchTerm) || depVersion.includes(searchTerm);
        
        if (matches || searchTerm === '') {
            item.classList.remove('hidden');
        } else {
            item.classList.add('hidden');
        }
    });
    
    // Show "no results" message if no items match
    const visibleItems = selectedList.querySelectorAll('.dep-item:not(.hidden)');
    const noResultsMsg = selectedList.querySelector('.no-results-message');
    
    if (visibleItems.length === 0 && searchTerm !== '') {
        if (!noResultsMsg) {
            const msg = document.createElement('div');
            msg.className = 'no-results-message';
            msg.textContent = `No selected dependencies found matching "${searchTerm}"`;
            selectedList.appendChild(msg);
        }
    } else if (noResultsMsg) {
        noResultsMsg.remove();
    }
}

// Filter direct dependencies based on search input
function filterDirectDependencies() {
    const searchInput = document.getElementById('direct-dependencies-search');
    const directDepsList = document.getElementById('direct-dependencies-list');
    if (!searchInput || !directDepsList) return;
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    const depItems = directDepsList.querySelectorAll('.dependency-item');
    
    depItems.forEach(item => {
        // Extract just the text content from dependency-name, excluding SVG icons
        const depNameElement = item.querySelector('.dependency-name');
        let depName = '';
        if (depNameElement) {
            // Get text content excluding SVG elements
            depName = Array.from(depNameElement.childNodes)
                .filter(node => node.nodeType === Node.TEXT_NODE)
                .map(node => node.textContent)
                .join('')
                .toLowerCase();
        }
        
        const depVersionElement = item.querySelector('.dependency-version');
        const depVersion = depVersionElement ? depVersionElement.textContent.toLowerCase() : '';
        
        const matches = depName.includes(searchTerm) || depVersion.includes(searchTerm);
        item.classList.toggle('hidden', !matches && searchTerm !== '');
    });
    
    // Show "no results" message if no items match
    const visibleItems = directDepsList.querySelectorAll('.dependency-item:not(.hidden)');
    const noResultsMsg = directDepsList.querySelector('.no-results-message');
    
    if (visibleItems.length === 0 && searchTerm !== '') {
        if (!noResultsMsg) {
            const msg = document.createElement('div');
            msg.className = 'no-results-message';
            msg.textContent = `No direct dependencies found matching "${searchTerm}"`;
            directDepsList.appendChild(msg);
        }
    } else if (noResultsMsg) {
        noResultsMsg.remove();
    }
}

function filterSubDependencies() {
    const searchInput = document.getElementById('sub-dependencies-search');
    const allDepsList = document.getElementById('all-dependencies-list');
    if (!searchInput || !allDepsList) return;
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    const depItems = allDepsList.querySelectorAll('.dependency-item');
    
    depItems.forEach(item => {
        // Extract just the text content from dependency-name, excluding SVG icons
        const depNameElement = item.querySelector('.dependency-name');
        let depName = '';
        if (depNameElement) {
            // Get text content excluding SVG elements
            depName = Array.from(depNameElement.childNodes)
                .filter(node => node.nodeType === Node.TEXT_NODE)
                .map(node => node.textContent)
                .join('')
                .toLowerCase();
        }
        
        const depVersionElement = item.querySelector('.dependency-version');
        const depVersion = depVersionElement ? depVersionElement.textContent.toLowerCase() : '';
        
        const matches = depName.includes(searchTerm) || depVersion.includes(searchTerm);
        item.classList.toggle('hidden', !matches && searchTerm !== '');
    });
    
    // Show "no results" message if no items match
    const visibleItems = allDepsList.querySelectorAll('.dependency-item:not(.hidden)');
    const noResultsMsg = allDepsList.querySelector('.no-results-message');
    
    if (visibleItems.length === 0 && searchTerm !== '') {
        if (!noResultsMsg) {
            const msg = document.createElement('div');
            msg.className = 'no-results-message';
            msg.textContent = `No sub-dependencies found matching "${searchTerm}"`;
            allDepsList.appendChild(msg);
        }
    } else if (noResultsMsg) {
        noResultsMsg.remove();
    }
}

function exportToSpdx() {
    const exportBtns = document.querySelectorAll('.export-btn');
    const originalTexts = Array.from(exportBtns).map(btn => btn.innerHTML);
    exportBtns.forEach(btn => {
        if (btn.innerText.includes('SPDX')) {
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating SPDX...';
            btn.disabled = true;
        }
    });
    fetch('/export_spdx', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Export failed');
        }
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sbom_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.spdx.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        alert('SPDX file exported successfully!');
    })
    .catch(error => {
        console.error('Error exporting SPDX:', error);
        alert('Error exporting SPDX. Please try again.');
    })
    .finally(() => {
        exportBtns.forEach((btn, i) => {
            if (btn.innerText.includes('SPDX')) {
                btn.innerHTML = originalTexts[i];
                btn.disabled = false;
            }
        });
    });
}