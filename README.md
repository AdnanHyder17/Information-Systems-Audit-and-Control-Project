# Information-Systems-Audit-and-Control-Project
A PHP-based security auditing tool that scans Apache configurations in XAMPP environments, identifying vulnerabilities and providing actionable hardening recommendations. Checks include version disclosure, SSL settings, directory permissions, PHP/MYSQL configurations, and XAMPP-specific security issues.

### Features
1. **Apache Configuration Audit**
   - Server version disclosure (ServerTokens)
   - Directory listing prevention (Options -Indexes)
   - HTTP method restrictions (LimitExcept)
   - TRACE/TRACK method detection
   - SSL/TLS protocol validation
   - Error log configuration checks
   - Timeout and KeepAlive settings
   - Server signature exposure
   - Proxy and CGI module security

2. **XAMPP-Specific Checks**
   - Default installation file detection (xampp/, webalizer/)
   - XAMPP security file verification
   - PHPMyAdmin directory permissions
   - Apache log file permissions

3. **PHP Configuration Audit**
   - display_errors/expose_php settings
   - allow_url_fopen verification
   - Dangerous function disabling (exec, shell_exec)
   - File upload settings

4. **MySQL Security Checks**
   - Network binding (bind-address)
   - Skip-networking verification
   - Root password strength warning

5. **Advanced Security**
   - MIME type handling risks
   - Symlink protection (FollowSymLinks)
   - Server-status page exposure
   - HTTP header security (X-Powered-By)
   - User-agent logging privacy

6. **Reporting**
   - Color-coded risk assessment (Critical/Warning/OK)
   - Detailed remediation instructions
   - Configuration snippet examples
   - Priority-based recommendations

### Requirements
1. **Software**
   - XAMPP for Windows (v8.0+ recommended)
   - PHP 7.4 or higher (included in XAMPP)
   - Apache 2.4+ (included in XAMPP)
   - Modern web browser (Chrome/Firefox/Edge)

2. **System**
   - Windows 10/11 (64-bit)
   - Minimum 2GB RAM
   - 500MB free disk space
   - Administrator privileges (for service control)

3. **Permissions**
   - Read access to Apache config files
   - Write access to htdocs directory
   - Execution rights for PHP scripts

### Usage Instructions
1. **Initial Setup**
   - Place the auditor in `C:\xampp\htdocs\apache-auditor\`
   - Ensure XAMPP services are stopped during installation

2. **Running Audits**
   - http://localhost/apache-auditor/

3. **Interpreting Results**
- **Critical (Red)**: Immediate vulnerabilities requiring action
  Example: "Directory listing enabled - add Options -Indexes"
- **Warning (Yellow)**: Security improvements recommended
  Example: "KeepAliveTimeout too high - set below 15 seconds"
- **OK (Green)**: Properly secured configurations
  Example: "SSL properly configured with TLS 1.2+"

4. **Implementing Fixes**
- For each finding:
  1. Locate the referenced config file (e.g., httpd.conf)
  2. Apply the recommended change
  3. Restart Apache via XAMPP Control Panel
  4. Re-run scan to verify

5. **Advanced Options**
- Custom config paths: Edit `includes/config.php`
- Exclude checks: Comment out in `runFullAudit()`
- Automated reporting: Call `scan.php` with `?format=json`

6. **Maintenance**
- Run audits after:
  - XAMPP updates
  - New virtual host additions
  - Security policy changes
- Compare results over time by saving JSON reports
