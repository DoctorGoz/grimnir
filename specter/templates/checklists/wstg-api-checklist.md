# WSTG v5.0 API-Relevant Testing Checklist

## WSTG-INFO: Information Gathering
- [ ] INFO-01: Search engine discovery
- [ ] INFO-02: Web server fingerprinting
- [ ] INFO-04: Attack surface enumeration
- [ ] INFO-05: Source code / JS analysis
- [ ] INFO-08: Application fingerprinting

## WSTG-CONF: Configuration Testing
- [ ] CONF-02: File extension handling
- [ ] CONF-05: HTTP method enumeration
- [ ] CONF-06: HSTS enforcement
- [ ] CONF-07: Cross-domain policy (CORS)
- [ ] CONF-11: Cloud storage permissions
- [ ] CONF-12: Content Security Policy

## WSTG-ATHN: Authentication Testing
- [ ] ATHN-01: Credentials over encrypted channel
- [ ] ATHN-02: Default credentials
- [ ] ATHN-03: Weak lockout mechanism
- [ ] ATHN-04: Authentication bypass
- [ ] ATHN-07: Weak password policy
- [ ] ATHN-09: Weak password reset
- [ ] ATHN-10: Weaker auth in alternative channel
- [ ] ATHN-11: MFA testing

## WSTG-ATHZ: Authorization Testing
- [ ] ATHZ-02: Authorization bypass
- [ ] ATHZ-03: Privilege escalation
- [ ] ATHZ-04: IDOR
- [ ] ATHZ-05: OAuth weaknesses

## WSTG-SESS: Session Management
- [ ] SESS-01: Session schema analysis
- [ ] SESS-02: Cookie attributes
- [ ] SESS-03: Session fixation
- [ ] SESS-05: CSRF
- [ ] SESS-07: Session timeout
- [ ] SESS-10: JWT testing

## WSTG-INPV: Input Validation
- [ ] INPV-01: Reflected XSS
- [ ] INPV-02: Stored XSS
- [ ] INPV-03: HTTP verb tampering
- [ ] INPV-05: SQL injection
- [ ] INPV-12: Command injection
- [ ] INPV-18: SSTI
- [ ] INPV-19: SSRF
- [ ] INPV-20: Mass assignment

## WSTG-BUSL: Business Logic
- [ ] BUSL-01: Data validation
- [ ] BUSL-04: Race conditions
- [ ] BUSL-05: Function usage limits
- [ ] BUSL-06: Workflow circumvention
- [ ] BUSL-10: Payment functionality

## WSTG-APIT: API Testing
- [ ] APIT-01: API reconnaissance
- [ ] APIT-02: BOLA testing
- [ ] APIT-99: GraphQL testing
