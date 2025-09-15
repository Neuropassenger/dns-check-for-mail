import dns from 'dns/promises';
import net from 'net';
import { promisify } from 'util';

class EmailDeliverabilityChecker {
    constructor() {
        this.blacklists = [
            'zen.spamhaus.org',
            'b.barracudacentral.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'psbl.surriel.com',
            'ubl.unsubscore.com',
            'rbl.interserver.net',
            'virbl.dnsbl.bit.nl'
        ];

        this.results = {
            domain: '',
            timestamp: new Date().toISOString(),
            checks: {},
            score: 0,
            maxScore: 0,
            recommendations: []
        };
    }

    validateDomain(domain) {
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
        return domainRegex.test(domain);
    }

    async checkMXRecords(domain) {
        try {
            const mxRecords = await dns.resolveMx(domain);

            if (!mxRecords || mxRecords.length === 0) {
                return {
                    status: 'fail',
                    message: 'No MX records found',
                    score: 0,
                    records: []
                };
            }

            const sortedRecords = mxRecords.sort((a, b) => a.priority - b.priority);

            return {
                status: 'pass',
                message: `Found ${mxRecords.length} MX record(s)`,
                score: 20,
                records: sortedRecords,
                details: {
                    primary: sortedRecords[0],
                    backup: sortedRecords.length > 1 ? sortedRecords.slice(1) : []
                }
            };
        } catch (error) {
            return {
                status: 'fail',
                message: `MX record lookup failed: ${error.message}`,
                score: 0,
                records: []
            };
        }
    }

    async checkSPFRecord(domain) {
        try {
            const txtRecords = await dns.resolveTxt(domain);
            const spfRecord = txtRecords.find(record =>
                record.join('').toLowerCase().startsWith('v=spf1')
            );

            if (!spfRecord) {
                return {
                    status: 'fail',
                    message: 'No SPF record found',
                    score: 0,
                    record: null,
                    recommendations: ['Add SPF record to prevent email spoofing']
                };
            }

            const spfString = spfRecord.join('');
            const hasHardFail = spfString.includes('-all');
            const hasSoftFail = spfString.includes('~all');

            let score = 15;
            let message = 'SPF record found';
            const recommendations = [];

            if (hasHardFail) {
                score = 20;
                message += ' with hard fail policy';
            } else if (hasSoftFail) {
                score = 18;
                message += ' with soft fail policy';
                recommendations.push('Consider upgrading to hard fail (-all) for better security');
            } else {
                score = 10;
                message += ' but no fail policy detected';
                recommendations.push('Add fail policy (~all or -all) to SPF record');
            }

            return {
                status: 'pass',
                message,
                score,
                record: spfString,
                recommendations
            };
        } catch (error) {
            return {
                status: 'fail',
                message: `SPF record lookup failed: ${error.message}`,
                score: 0,
                record: null
            };
        }
    }

    async checkDKIMRecord(domain, selector = 'default') {
        const selectors = [selector, 'mail', 'google', 'k1', 'default', 'selector1', 'selector2'];
        const results = [];

        for (const sel of selectors) {
            try {
                const dkimDomain = `${sel}._domainkey.${domain}`;
                const txtRecords = await dns.resolveTxt(dkimDomain);
                const dkimRecord = txtRecords.find(record =>
                    record.join('').toLowerCase().includes('v=dkim1')
                );

                if (dkimRecord) {
                    results.push({
                        selector: sel,
                        record: dkimRecord.join('')
                    });
                }
            } catch (error) {
                // DKIM selector not found, continue to next
            }
        }

        if (results.length === 0) {
            return {
                status: 'fail',
                message: 'No DKIM records found',
                score: 0,
                records: [],
                recommendations: ['Configure DKIM signing for better email authentication']
            };
        }

        return {
            status: 'pass',
            message: `Found ${results.length} DKIM record(s)`,
            score: 20,
            records: results
        };
    }

    async checkDMARCRecord(domain) {
        try {
            const dmarcDomain = `_dmarc.${domain}`;
            const txtRecords = await dns.resolveTxt(dmarcDomain);
            const dmarcRecord = txtRecords.find(record =>
                record.join('').toLowerCase().startsWith('v=dmarc1')
            );

            if (!dmarcRecord) {
                return {
                    status: 'fail',
                    message: 'No DMARC record found',
                    score: 0,
                    record: null,
                    recommendations: ['Implement DMARC policy for email authentication']
                };
            }

            const dmarcString = dmarcRecord.join('');
            const policyMatch = dmarcString.match(/p=([^;]+)/);
            const policy = policyMatch ? policyMatch[1] : 'none';

            let score = 15;
            let message = `DMARC record found with policy: ${policy}`;
            const recommendations = [];

            switch (policy.toLowerCase()) {
                case 'reject':
                    score = 25;
                    break;
                case 'quarantine':
                    score = 20;
                    recommendations.push('Consider upgrading DMARC policy to "reject" for maximum security');
                    break;
                case 'none':
                    score = 10;
                    recommendations.push('Upgrade DMARC policy from "none" to "quarantine" or "reject"');
                    break;
            }

            return {
                status: 'pass',
                message,
                score,
                record: dmarcString,
                policy,
                recommendations
            };
        } catch (error) {
            return {
                status: 'fail',
                message: `DMARC record lookup failed: ${error.message}`,
                score: 0,
                record: null
            };
        }
    }

    async checkBlacklists(domain) {
        const results = [];
        let blacklistedCount = 0;

        for (const blacklist of this.blacklists) {
            try {
                const reverseQuery = `${domain}.${blacklist}`;
                await dns.resolve4(reverseQuery);
                results.push({
                    blacklist,
                    status: 'blacklisted'
                });
                blacklistedCount++;
            } catch (error) {
                results.push({
                    blacklist,
                    status: 'clean'
                });
            }
        }

        const score = blacklistedCount === 0 ? 15 : Math.max(0, 15 - (blacklistedCount * 3));

        return {
            status: blacklistedCount === 0 ? 'pass' : 'warning',
            message: blacklistedCount === 0 ?
                'Domain not found on any blacklists' :
                `Domain found on ${blacklistedCount} blacklist(s)`,
            score,
            blacklistedCount,
            results,
            recommendations: blacklistedCount > 0 ?
                ['Contact blacklist providers for delisting'] : []
        };
    }

    async checkMailServerConnectivity(mxRecords) {
        if (!mxRecords || mxRecords.length === 0) {
            return {
                status: 'fail',
                message: 'No MX records to test',
                score: 0
            };
        }

        const results = [];
        let connectableServers = 0;

        for (const mx of mxRecords) {
            const server = mx.exchange;
            console.log(`   Testing connection to ${server}:25...`);

            try {
                await new Promise((resolve, reject) => {
                    const socket = net.createConnection(25, server);
                    let connected = false;

                    socket.setTimeout(10000); // Увеличил таймаут до 10 секунд

                    socket.on('connect', () => {
                        connected = true;
                        socket.destroy();
                        resolve();
                    });

                    socket.on('error', (error) => {
                        if (!connected) {
                            // Более детальная информация об ошибке
                            let errorType = 'Connection failed';
                            if (error.code === 'ECONNREFUSED') {
                                errorType = 'Connection refused (port may be closed)';
                            } else if (error.code === 'ETIMEDOUT') {
                                errorType = 'Connection timeout (firewall or network issue)';
                            } else if (error.code === 'EHOSTUNREACH') {
                                errorType = 'Host unreachable';
                            } else if (error.code === 'ENETUNREACH') {
                                errorType = 'Network unreachable';
                            }
                            reject(new Error(`${errorType}: ${error.code || error.message}`));
                        }
                    });

                    socket.on('timeout', () => {
                        if (!connected) {
                            socket.destroy();
                            reject(new Error('Connection timeout after 10 seconds'));
                        }
                    });
                });

                results.push({
                    server,
                    priority: mx.priority,
                    status: 'connectable'
                });
                connectableServers++;
                console.log(`   ✓ ${server} - Connected successfully`);
            } catch (error) {
                results.push({
                    server,
                    priority: mx.priority,
                    status: 'not connectable',
                    error: error.message
                });
                console.log(`   ✗ ${server} - ${error.message}`);
            }
        }

        const score = connectableServers > 0 ? 10 : 0;

        // Добавляем предупреждение если все соединения не удались
        const warnings = [];
        if (connectableServers === 0) {
            warnings.push('Note: Port 25 may be blocked by your ISP or firewall');
            warnings.push('This doesn\'t necessarily mean the mail servers are down');
        }

        return {
            status: connectableServers > 0 ? 'pass' : 'fail',
            message: `${connectableServers}/${mxRecords.length} mail servers connectable`,
            score,
            connectableServers,
            totalServers: mxRecords.length,
            results,
            warnings
        };
    }

    async checkDNSPropagation(domain) {
        const dnsServers = ['8.8.8.8', '1.1.1.1', '208.67.222.222'];
        const results = [];

        for (const server of dnsServers) {
            try {
                const resolver = new dns.Resolver();
                resolver.setServers([server]);

                const mxRecords = await resolver.resolveMx(domain);
                results.push({
                    server,
                    status: 'resolved',
                    recordCount: mxRecords.length
                });
            } catch (error) {
                results.push({
                    server,
                    status: 'failed',
                    error: error.message
                });
            }
        }

        const successfulQueries = results.filter(r => r.status === 'resolved').length;
        const score = (successfulQueries / dnsServers.length) * 10;

        return {
            status: successfulQueries > 0 ? 'pass' : 'fail',
            message: `DNS resolves on ${successfulQueries}/${dnsServers.length} servers`,
            score: Math.round(score),
            results
        };
    }

    displayRawDNSRecords() {
        const { checks } = this.results;

        console.log('\n' + '='.repeat(60));
        console.log('DNS RECORDS FOUND');
        console.log('='.repeat(60));

        // MX Records
        if (checks.mxRecords && checks.mxRecords.records && checks.mxRecords.records.length > 0) {
            console.log('\n📧 MX Records:');
            checks.mxRecords.records.forEach(record => {
                console.log(`   ${record.priority} ${record.exchange}`);
            });
        } else {
            console.log('\n📧 MX Records: None found');
        }

        // SPF Record
        console.log('\n🛡️  SPF Record:');
        if (checks.spfRecord && checks.spfRecord.record) {
            console.log(`   ${checks.spfRecord.record}`);
        } else {
            console.log('   None found');
        }

        // DKIM Records
        console.log('\n🔐 DKIM Records:');
        if (checks.dkimRecords && checks.dkimRecords.records && checks.dkimRecords.records.length > 0) {
            checks.dkimRecords.records.forEach(record => {
                console.log(`   Selector: ${record.selector}`);
                console.log(`   Record: ${record.record}`);
                console.log('');
            });
        } else {
            console.log('   None found');
        }

        // DMARC Record
        console.log('📋 DMARC Record:');
        if (checks.dmarcRecord && checks.dmarcRecord.record) {
            console.log(`   ${checks.dmarcRecord.record}`);
        } else {
            console.log('   None found');
        }
    }

    generateReport() {
        const { checks, score, maxScore } = this.results;
        const percentage = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;

        console.log('\n '.repeat(3));
        console.log('='.repeat(60));
        console.log(`EMAIL DELIVERABILITY ANALYSIS FOR: ${this.results.domain.toUpperCase()}`);
        console.log('='.repeat(60));
        console.log('\n')
        console.log(`Generated: ${this.results.timestamp}`);
        console.log(`Overall Score: ${score}/${maxScore} (${percentage}%)`);

        let status = 'EXCELLENT';
        if (percentage < 90) status = 'GOOD';
        if (percentage < 70) status = 'FAIR';
        if (percentage < 50) status = 'POOR';

        console.log(`Status: ${status}\n`);

        for (const [checkName, result] of Object.entries(checks)) {
            const statusIcon = result.status === 'pass' ? '✅' :
                              result.status === 'warning' ? '⚠️' : '❌';

            console.log(`${statusIcon} ${checkName.toUpperCase()}`);
            console.log(`   ${result.message} (Score: ${result.score})`);

            // Show detailed analysis
            if (checkName === 'mxRecords' && result.records && result.records.length > 0) {
                console.log('   Analysis:');
                console.log(`   • Primary mail server: ${result.details.primary.exchange} (priority ${result.details.primary.priority})`);
                if (result.details.backup.length > 0) {
                    console.log(`   • Backup servers: ${result.details.backup.length}`);
                } else {
                    console.log('   • No backup mail servers configured (consider adding for redundancy)');
                }
            }

            if (checkName === 'spfRecord' && result.record) {
                console.log('   Analysis:');
                if (result.record.includes('include:')) {
                    const includes = result.record.match(/include:[^\s]+/g);
                    if (includes) {
                        console.log(`   • Authorized senders: ${includes.join(', ')}`);
                    }
                }
                if (result.record.includes('ip4:')) {
                    const ips = result.record.match(/ip4:[^\s]+/g);
                    if (ips) {
                        console.log(`   • Authorized IP ranges: ${ips.join(', ')}`);
                    }
                }
            }

            if (checkName === 'dmarcRecord' && result.record) {
                console.log('   Analysis:');
                console.log(`   • Policy: ${result.policy}`);
                const pct = result.record.match(/pct=(\d+)/);
                if (pct) {
                    console.log(`   • Percentage applied: ${pct[1]}%`);
                }
                const rua = result.record.match(/rua=([^;]+)/);
                if (rua) {
                    console.log(`   • Aggregate reports sent to: ${rua[1]}`);
                }
                const ruf = result.record.match(/ruf=([^;]+)/);
                if (ruf) {
                    console.log(`   • Forensic reports sent to: ${ruf[1]}`);
                }
            }

            if (checkName === 'blacklists' && result.results) {
                console.log('   Analysis:');
                const blacklisted = result.results.filter(r => r.status === 'blacklisted');
                const clean = result.results.filter(r => r.status === 'clean');
                console.log(`   • Clean on ${clean.length} blacklists`);
                if (blacklisted.length > 0) {
                    console.log(`   • Found on: ${blacklisted.map(b => b.blacklist).join(', ')}`);
                }
            }

            if (checkName === 'mailServerConnectivity' && result.results) {
                console.log('   Analysis:');
                result.results.forEach(server => {
                    const status = server.status === 'connectable' ? '✓' : '✗';
                    const errorInfo = server.error ? ` - ${server.error}` : '';
                    console.log(`   ${status} ${server.server} (priority ${server.priority})${errorInfo}`);
                });

                if (result.warnings && result.warnings.length > 0) {
                    console.log('   Warnings:');
                    result.warnings.forEach(warning => {
                        console.log(`   ⚠️ ${warning}`);
                    });
                }
            }

            if (result.recommendations && result.recommendations.length > 0) {
                console.log('   Recommendations:');
                result.recommendations.forEach(rec => {
                    console.log(`   • ${rec}`);
                });
            }
            console.log('');
        }

        if (this.results.recommendations.length > 0) {
            console.log('OVERALL RECOMMENDATIONS:');
            this.results.recommendations.forEach(rec => {
                console.log(`• ${rec}`);
            });
        }

        console.log('='.repeat(60));
    }

    async runAllChecks(domain) {
        if (!this.validateDomain(domain)) {
            throw new Error('Invalid domain format');
        }

        this.results.domain = domain;

        console.log(`Checking email deliverability for: ${domain}`);
        console.log('This may take a few moments...\n');

        // Run all checks
        console.log('🔍 Checking MX records...');
        this.results.checks.mxRecords = await this.checkMXRecords(domain);
        this.results.score += this.results.checks.mxRecords.score;
        this.results.maxScore += 20;

        console.log('🛡️  Checking SPF record...');
        this.results.checks.spfRecord = await this.checkSPFRecord(domain);
        this.results.score += this.results.checks.spfRecord.score;
        this.results.maxScore += 20;

        console.log('🔐 Checking DKIM records...');
        this.results.checks.dkimRecords = await this.checkDKIMRecord(domain);
        this.results.score += this.results.checks.dkimRecords.score;
        this.results.maxScore += 20;

        console.log('📋 Checking DMARC record...');
        this.results.checks.dmarcRecord = await this.checkDMARCRecord(domain);
        this.results.score += this.results.checks.dmarcRecord.score;
        this.results.maxScore += 25;

        console.log('🚫 Checking blacklists...');
        this.results.checks.blacklists = await this.checkBlacklists(domain);
        this.results.score += this.results.checks.blacklists.score;
        this.results.maxScore += 15;

        console.log('🌐 Checking DNS propagation...');
        this.results.checks.dnsPropagation = await this.checkDNSPropagation(domain);
        this.results.score += this.results.checks.dnsPropagation.score;
        this.results.maxScore += 10;

        console.log('📡 Testing mail server connectivity...');
        this.results.checks.mailServerConnectivity = await this.checkMailServerConnectivity(
            this.results.checks.mxRecords.records
        );
        this.results.score += this.results.checks.mailServerConnectivity.score;
        this.results.maxScore += 10;

        // Collect all recommendations
        Object.values(this.results.checks).forEach(check => {
            if (check.recommendations) {
                this.results.recommendations.push(...check.recommendations);
            }
        });

        // Display raw DNS records first
        this.displayRawDNSRecords();

        // Then generate analysis report
        this.generateReport();
        return this.results;
    }
}

// CLI Interface
async function main() {
    const domain = process.argv[2];

    if (!domain) {
        console.log('Usage: node index.js <domain>');
        console.log('Example: node index.js example.com');
        process.exit(1);
    }

    try {
        const checker = new EmailDeliverabilityChecker();
        await checker.runAllChecks(domain);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}

export default EmailDeliverabilityChecker;