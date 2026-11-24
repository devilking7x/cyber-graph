// CyberGraph seed — hand-written for this project (public knowledge, simplified
// educational summaries; verify details against NVD / CWE / CAPEC / MITRE ATT&CK).
// Loaded into a real Relate store by scripts/seed_store.py and into the browser
// Relate (WASM) engine by the web app on page load.

// ---- Vulnerabilities (CVE) ----
CREATE (:Vulnerability {id: 'CVE-2024-3094', name: 'xz Utils backdoor', cvss: 10.0, year: 2024});
CREATE (:Vulnerability {id: 'CVE-2021-44228', name: 'Log4Shell', cvss: 10.0, year: 2021});
CREATE (:Vulnerability {id: 'CVE-2014-0160', name: 'Heartbleed', cvss: 7.5, year: 2014});
CREATE (:Vulnerability {id: 'CVE-2017-0144', name: 'EternalBlue', cvss: 8.1, year: 2017});
CREATE (:Vulnerability {id: 'CVE-2019-0708', name: 'BlueKeep', cvss: 9.8, year: 2019});
CREATE (:Vulnerability {id: 'CVE-2021-34527', name: 'PrintNightmare', cvss: 8.8, year: 2021});
CREATE (:Vulnerability {id: 'CVE-2023-4863', name: 'libwebp heap buffer overflow', cvss: 8.8, year: 2023});
CREATE (:Vulnerability {id: 'CVE-2022-22965', name: 'Spring4Shell', cvss: 9.8, year: 2022});

// ---- Weaknesses (CWE) ----
CREATE (:Weakness {id: 'CWE-506', name: 'Embedded Malicious Code'});
CREATE (:Weakness {id: 'CWE-400', name: 'Uncontrolled Resource Consumption'});
CREATE (:Weakness {id: 'CWE-20', name: 'Improper Input Validation'});
CREATE (:Weakness {id: 'CWE-125', name: 'Out-of-bounds Read'});
CREATE (:Weakness {id: 'CWE-119', name: 'Improper Restriction of Operations within the Bounds of a Memory Buffer'});
CREATE (:Weakness {id: 'CWE-787', name: 'Out-of-bounds Write'});
CREATE (:Weakness {id: 'CWE-89', name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"});
CREATE (:Weakness {id: 'CWE-79', name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"});

// ---- Attack patterns (CAPEC) ----
CREATE (:AttackPattern {id: 'CAPEC-100', name: 'Overflow Buffers'});
CREATE (:AttackPattern {id: 'CAPEC-66', name: 'SQL Injection'});
CREATE (:AttackPattern {id: 'CAPEC-592', name: 'Stored Cross-Site Scripting'});
CREATE (:AttackPattern {id: 'CAPEC-131', name: 'Resource Depletion through Flooding'});
CREATE (:AttackPattern {id: 'CAPEC-233', name: 'Privilege Escalation'});
CREATE (:AttackPattern {id: 'CAPEC-94', name: 'Man in the Middle Attack'});

// ---- MITRE ATT&CK techniques ----
CREATE (:Technique {id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access'});
CREATE (:Technique {id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution'});
CREATE (:Technique {id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access'});
CREATE (:Technique {id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion'});
CREATE (:Technique {id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion'});
CREATE (:Technique {id: 'T1210', name: 'Exploitation of Remote Services', tactic: 'Lateral Movement'});

// ---- Products ----
CREATE (:Product {id: 'xz Utils', name: 'xz Utils', vendor: 'tukaani'});
CREATE (:Product {id: 'Apache Log4j', name: 'Apache Log4j', vendor: 'Apache'});
CREATE (:Product {id: 'OpenSSL', name: 'OpenSSL', vendor: 'OpenSSL'});
CREATE (:Product {id: 'Microsoft Windows', name: 'Microsoft Windows', vendor: 'Microsoft'});
CREATE (:Product {id: 'Spring Framework', name: 'Spring Framework', vendor: 'Spring'});
CREATE (:Product {id: 'libwebp', name: 'libwebp', vendor: 'Google'});

// ---- CVE -> CWE: root-cause weakness ----
MATCH (v:Vulnerability {id: 'CVE-2024-3094'}), (w:Weakness {id: 'CWE-506'}) CREATE (v)-[:HAS_WEAKNESS]->(w);
MATCH (v:Vulnerability {id: 'CVE-2021-44228'}), (w:Weakness {id: 'CWE-400'}) CREATE (v)-[:HAS_WEAKNESS]->(w);
MATCH (v:Vulnerability {id: 'CVE-2021-44228'}), (w:Weakness {id: 'CWE-20'}) CREATE (v)-[:HAS_WEAKNESS]->(w);
MATCH (v:Vulnerability {id: 'CVE-2014-0160'}), (w:Weakness {id: 'CWE-125'}) CREATE (v)-[:HAS_WEAKNESS]->(w);
MATCH (v:Vulnerability {id: 'CVE-2017-0144'}), (w:Weakness {id: 'CWE-119'}) CREATE (v)-[:HAS_WEAKNESS]->(w);
MATCH (v:Vulnerability {id: 'CVE-2019-0708'}), (w:Weakness {id: 'CWE-119'}) CREATE (v)-[:HAS_WEAKNESS]->(w);
MATCH (v:Vulnerability {id: 'CVE-2021-34527'}), (w:Weakness {id: 'CWE-787'}) CREATE (v)-[:HAS_WEAKNESS]->(w);
MATCH (v:Vulnerability {id: 'CVE-2023-4863'}), (w:Weakness {id: 'CWE-787'}) CREATE (v)-[:HAS_WEAKNESS]->(w);
MATCH (v:Vulnerability {id: 'CVE-2022-22965'}), (w:Weakness {id: 'CWE-20'}) CREATE (v)-[:HAS_WEAKNESS]->(w);

// ---- CAPEC -> CWE: attack pattern exploits weakness ----
MATCH (c:AttackPattern {id: 'CAPEC-100'}), (w:Weakness {id: 'CWE-787'}) CREATE (c)-[:EXPLOITS]->(w);
MATCH (c:AttackPattern {id: 'CAPEC-100'}), (w:Weakness {id: 'CWE-119'}) CREATE (c)-[:EXPLOITS]->(w);
MATCH (c:AttackPattern {id: 'CAPEC-100'}), (w:Weakness {id: 'CWE-125'}) CREATE (c)-[:EXPLOITS]->(w);
MATCH (c:AttackPattern {id: 'CAPEC-66'}), (w:Weakness {id: 'CWE-89'}) CREATE (c)-[:EXPLOITS]->(w);
MATCH (c:AttackPattern {id: 'CAPEC-592'}), (w:Weakness {id: 'CWE-79'}) CREATE (c)-[:EXPLOITS]->(w);
MATCH (c:AttackPattern {id: 'CAPEC-131'}), (w:Weakness {id: 'CWE-400'}) CREATE (c)-[:EXPLOITS]->(w);
MATCH (c:AttackPattern {id: 'CAPEC-233'}), (w:Weakness {id: 'CWE-787'}) CREATE (c)-[:EXPLOITS]->(w);
MATCH (c:AttackPattern {id: 'CAPEC-94'}), (w:Weakness {id: 'CWE-20'}) CREATE (c)-[:EXPLOITS]->(w);

// ---- Technique -> CAPEC: technique uses attack pattern ----
MATCH (t:Technique {id: 'T1190'}), (c:AttackPattern {id: 'CAPEC-100'}) CREATE (t)-[:USES]->(c);
MATCH (t:Technique {id: 'T1190'}), (c:AttackPattern {id: 'CAPEC-66'}) CREATE (t)-[:USES]->(c);
MATCH (t:Technique {id: 'T1059'}), (c:AttackPattern {id: 'CAPEC-592'}) CREATE (t)-[:USES]->(c);
MATCH (t:Technique {id: 'T1133'}), (c:AttackPattern {id: 'CAPEC-94'}) CREATE (t)-[:USES]->(c);
MATCH (t:Technique {id: 'T1055'}), (c:AttackPattern {id: 'CAPEC-233'}) CREATE (t)-[:USES]->(c);
MATCH (t:Technique {id: 'T1210'}), (c:AttackPattern {id: 'CAPEC-100'}) CREATE (t)-[:USES]->(c);

// ---- Technique -> CVE: technique targets vulnerability ----
MATCH (t:Technique {id: 'T1190'}), (v:Vulnerability {id: 'CVE-2021-44228'}) CREATE (t)-[:TARGETS]->(v);
MATCH (t:Technique {id: 'T1190'}), (v:Vulnerability {id: 'CVE-2022-22965'}) CREATE (t)-[:TARGETS]->(v);
MATCH (t:Technique {id: 'T1210'}), (v:Vulnerability {id: 'CVE-2017-0144'}) CREATE (t)-[:TARGETS]->(v);
MATCH (t:Technique {id: 'T1210'}), (v:Vulnerability {id: 'CVE-2019-0708'}) CREATE (t)-[:TARGETS]->(v);
MATCH (t:Technique {id: 'T1027'}), (v:Vulnerability {id: 'CVE-2024-3094'}) CREATE (t)-[:TARGETS]->(v);
MATCH (t:Technique {id: 'T1059'}), (v:Vulnerability {id: 'CVE-2024-3094'}) CREATE (t)-[:TARGETS]->(v);
MATCH (t:Technique {id: 'T1059'}), (v:Vulnerability {id: 'CVE-2021-44228'}) CREATE (t)-[:TARGETS]->(v);
MATCH (t:Technique {id: 'T1055'}), (v:Vulnerability {id: 'CVE-2021-34527'}) CREATE (t)-[:TARGETS]->(v);

// ---- CVE -> Product: vulnerability affects product ----
MATCH (v:Vulnerability {id: 'CVE-2024-3094'}), (p:Product {id: 'xz Utils'}) CREATE (v)-[:AFFECTS]->(p);
MATCH (v:Vulnerability {id: 'CVE-2021-44228'}), (p:Product {id: 'Apache Log4j'}) CREATE (v)-[:AFFECTS]->(p);
MATCH (v:Vulnerability {id: 'CVE-2014-0160'}), (p:Product {id: 'OpenSSL'}) CREATE (v)-[:AFFECTS]->(p);
MATCH (v:Vulnerability {id: 'CVE-2017-0144'}), (p:Product {id: 'Microsoft Windows'}) CREATE (v)-[:AFFECTS]->(p);
MATCH (v:Vulnerability {id: 'CVE-2019-0708'}), (p:Product {id: 'Microsoft Windows'}) CREATE (v)-[:AFFECTS]->(p);
MATCH (v:Vulnerability {id: 'CVE-2021-34527'}), (p:Product {id: 'Microsoft Windows'}) CREATE (v)-[:AFFECTS]->(p);
MATCH (v:Vulnerability {id: 'CVE-2023-4863'}), (p:Product {id: 'libwebp'}) CREATE (v)-[:AFFECTS]->(p);
MATCH (v:Vulnerability {id: 'CVE-2022-22965'}), (p:Product {id: 'Spring Framework'}) CREATE (v)-[:AFFECTS]->(p);
