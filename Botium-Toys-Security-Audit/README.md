# Botium Toys: Security Audit

**Scenario and template from the Google Cybersecurity Professional Certificate (Coursera)**

## Scenario
Botium Toys is a small U.S. toy company with a physical store and a growing online business that serves customers worldwide, including in the E.U. The IT manager requested an internal audit of the company's security program to assess its controls and compliance with PCI DSS, GDPR, and SOC requirements.

## My Approach
- Reviewed the company's assets and the IT manager's risk assessment
- Evaluated 14 security controls using the NIST Cybersecurity Framework
- Assessed compliance with PCI DSS, GDPR, and SOC type 1/type 2 best practices
- Prioritized recommendations based on risk to customer data and business operations

## Key Findings
- **Overall risk score: 8/10 (high)**
- All employees can access cardholder data and customer PII/SPII (no least privilege or separation of duties)
- Credit card data is not encrypted, so the company does not comply with PCI DSS
- No disaster recovery plan or backups of critical data
- No intrusion detection system (IDS)
- Weak password policy with no centralized password management
- **Strengths:** firewall, antivirus, physical security (locks, CCTV, fire detection), GDPR breach notification plan

## Top Recommendations
1. Implement least privilege, separation of duties, and encryption to protect payment and customer data
2. Create a disaster recovery plan and schedule regular backups
3. Strengthen the password policy and deploy a password management system
4. Install an IDS to detect suspicious network activity
5. Build an asset inventory and formalize legacy system maintenance

## Files
- [Controls_and_Compliance_Checklist.pdf](./Controls_and_Compliance_Checklist.pdf): completed audit checklist with recommendations

## Skills Demonstrated
Security auditing · Risk assessment · NIST CSF · PCI DSS · GDPR · SOC 1/SOC 2 · Security controls
