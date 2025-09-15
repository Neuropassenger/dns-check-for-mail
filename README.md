# DNS Check for Mail - Email Deliverability Checker

Comprehensive domain email deliverability checker that validates all critical DNS records and configurations needed for reliable email delivery.

## Features

✅ **MX Records Check** - Validates mail exchange records
🛡️ **SPF Record Analysis** - Sender Policy Framework validation
🔐 **DKIM Records Detection** - DomainKeys Identified Mail authentication
📋 **DMARC Policy Verification** - Domain-based Message Authentication
🚫 **Blacklist Monitoring** - Checks against major email blacklists
🌐 **DNS Propagation Test** - Multi-server DNS resolution verification
📡 **Mail Server Connectivity** - Tests SMTP server accessibility

## Quick Start

1. Clone or download this project
2. Run the checker:
   ```bash
   node index.js your-domain.com
   ```

## Example Usage

```bash
node index.js gmail.com
node index.js your-company.com
```

## What It Checks

### DNS Records
- **MX Records**: Ensures mail servers are configured
- **SPF Record**: Validates sender authorization
- **DKIM Records**: Checks for email signing configuration
- **DMARC Policy**: Verifies email authentication policy

### Security & Reputation
- **Blacklist Status**: Tests against 8 major email blacklists
- **DNS Propagation**: Verifies records resolve across multiple DNS servers
- **SMTP Connectivity**: Tests if mail servers accept connections

## Scoring System

The tool provides a comprehensive score out of 120 points:
- MX Records: 20 points
- SPF Record: 20 points
- DKIM Records: 20 points
- DMARC Policy: 25 points
- Blacklist Status: 15 points
- DNS Propagation: 10 points
- Mail Server Connectivity: 10 points

## Sample Output

```
============================================================
EMAIL DELIVERABILITY REPORT FOR: EXAMPLE.COM
============================================================
Generated: 2025-09-15T18:30:00.000Z
Overall Score: 95/120 (79%)
Status: GOOD

✅ MX RECORDS
   Found 2 MX record(s) (Score: 20)

✅ SPF RECORD
   SPF record found with hard fail policy (Score: 20)

❌ DKIM RECORDS
   No DKIM records found (Score: 0)
   Recommendations:
   • Configure DKIM signing for better email authentication

✅ DMARC RECORD
   DMARC record found with policy: quarantine (Score: 20)
   Recommendations:
   • Consider upgrading DMARC policy to "reject" for maximum security
```

## Understanding the Results

### Status Levels
- **EXCELLENT** (90-100%): Domain is optimally configured
- **GOOD** (70-89%): Minor improvements needed
- **FAIR** (50-69%): Several issues require attention
- **POOR** (<50%): Significant problems affect deliverability

### Common Recommendations
- Add missing SPF record with proper fail policy
- Configure DKIM signing for all outgoing mail
- Implement DMARC policy (start with p=none, progress to p=reject)
- Remove domain from blacklists if detected
- Ensure all MX records point to functioning mail servers

## Technical Details

The checker uses Node.js built-in DNS resolution and implements:
- Multiple DNS server queries for propagation testing
- SMTP port 25 connectivity testing
- Comprehensive regex validation for domain format
- Timeout handling for network operations
- Detailed scoring algorithm with weighted importance

## Requirements

- Node.js 14+ (uses ES modules and dns/promises)
- Internet connection for DNS queries and blacklist checks
- No external dependencies required

## License

MIT