<?php
class ApacheSecurityAudit {
    private $parser;
    
    public function __construct($parser) {
        $this->parser = $parser;
    }
    
    public function runQuickScan() {
        $results = [];
        $results['version_disclosure'] = $this->checkServerTokens();
        $results['directory_listing'] = $this->checkDirectoryListing();
        $results['http_methods'] = $this->checkHttpMethods();
        $results['ssl_enabled'] = $this->checkSSLEnabled();
        return $results;
    }
    
    public function runFullAudit() {
        $quickScan = $this->runQuickScan();
        $fullScan = [
            'server_signature' => $this->checkServerSignature(),
            'trace_method' => $this->checkTraceMethod(),
            'insecure_directives' => $this->checkInsecureDirectives(),
            'module_security' => $this->checkModuleSecurity(),
            'php_config' => $this->checkPhpConfig(),
            'mysql_config' => $this->checkMysqlConfig(),
            'file_permissions' => $this->checkFilePermissions(),
            'default_files' => $this->checkDefaultFiles(),
            'error_logging' => $this->checkErrorLogging(),
            'http_headers' => $this->checkHttpHeaders(),
            'timeout_settings' => $this->checkTimeoutSettings(),
            'keepalive_settings' => $this->checkKeepaliveSettings(),
            'indexes_settings' => $this->checkIndexesSettings(),
            'user_agent_logging' => $this->checkUserAgentLogging(),
            'server_limit' => $this->checkServerLimit(),
            'symlink_protection' => $this->checkSymlinkProtection(),
            'mime_types' => $this->checkMimeTypes(),
            'cgi_settings' => $this->checkCgiSettings(),
            'proxy_settings' => $this->checkProxySettings(),
            'dns_lookups' => $this->checkDNSLookups(),
            'server_status' => $this->checkServerStatus(),
            'xampp_security' => $this->checkXamppSecurity()
        ];
        return array_merge($quickScan, $fullScan);
    }
    
    private function checkServerTokens() {
        $directives = $this->parser->findDirective('ServerTokens');
        if (empty($directives)) {
            return [
                'status' => 'critical',
                'message' => 'Server version exposure: ServerTokens directive missing. '
                           . 'Apache shows full version details including OS and module info. '
                           . 'Fix: Add "ServerTokens Prod" to httpd.conf to only show "Apache"'
            ];
        }
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (stripos($value, 'ServerTokens Prod') !== false) {
                    return [
                        'status' => 'ok',
                        'message' => 'Server version hidden: ServerTokens set to minimal (shows only "Apache")'
                    ];
                }
            }
        }
        
        return [
            'status' => 'critical',
            'message' => 'Server version exposure: Current setting reveals detailed server info. '
                       . 'Helps attackers identify vulnerabilities. '
                       . 'Action: Replace with "ServerTokens Prod" in httpd.conf'
        ];
    }
    
    private function checkDirectoryListing() {
        $directives = $this->parser->findDirective('Options');
        if (empty($directives)) {
            return [
                'status' => 'critical',
                'message' => 'Directory listing risk: No Options directive found. '
                           . 'Default allows directory browsing in all folders. '
                           . 'Fix: Add "Options -Indexes" inside <Directory> blocks'
            ];
        }
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (strpos($value, 'Indexes') !== false) {
                    return [
                        'status' => 'critical',
                        'message' => 'Directory listing enabled: Shows all files when no index.html exists. '
                                   . 'Extreme security risk! '
                                   . 'Immediate action: Change to "Options -Indexes"'
                    ];
                }
            }
        }
        
        return [
            'status' => 'ok',
            'message' => 'Directory protection: Listings disabled via Options -Indexes'
        ];
    }
    
    private function checkHttpMethods() {
        $allowedMethods = ['GET', 'POST', 'HEAD'];
        $dangerousMethods = ['PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'];
        
        $limitDirectives = $this->parser->findDirective('Limit');
        $limitExceptDirectives = $this->parser->findDirective('LimitExcept');
        
        if (empty($limitDirectives) && empty($limitExceptDirectives)) {
            return [
                'status' => 'critical',
                'message' => 'HTTP Method Risk: No restrictions detected. '
                           . 'Dangerous methods like DELETE/PUT are allowed. '
                           . 'Fix: Add "LimitExcept GET POST HEAD" to httpd.conf'
            ];
        }
        
        foreach ($dangerousMethods as $method) {
            foreach ($limitDirectives as $file => $directives) {
                foreach ($directives as $directive) {
                    if (preg_match("/Limit\s+{$method}/i", $directive)) {
                        return [
                            'status' => 'critical',
                            'message' => "Dangerous method allowed: {$method} can modify/delete resources. "
                                       . "Fix: Remove or restrict with LimitExcept"
                        ];
                    }
                }
            }
        }
        
        foreach ($limitExceptDirectives as $file => $directives) {
            foreach ($directives as $directive) {
                if (preg_match("/LimitExcept\s+([^\s>]+)/i", $directive, $matches)) {
                    $methods = array_map('strtoupper', preg_split('/\s+/', $matches[1]));
                    $unsafeMethods = array_diff($methods, $allowedMethods);
                    if (empty($unsafeMethods)) {
                        return [
                            'status' => 'ok',
                            'message' => 'HTTP Methods secured: Only safe methods (GET/POST/HEAD) allowed'
                        ];
                    }
                }
            }
        }
        
        return [
            'status' => 'warning',
            'message' => 'HTTP Method Review Needed: Current restrictions may allow unsafe methods. '
                       . 'Recommendation: Use "LimitExcept GET POST HEAD"'
        ];
    }
    
    private function checkSSLEnabled() {
        if (!function_exists('apache_get_modules') || !in_array('mod_ssl', apache_get_modules())) {
            return [
                'status' => 'critical',
                'message' => 'SSL Not Enabled: mod_ssl module not loaded. '
                           . 'All traffic is unencrypted! '
                           . 'Fix: Uncomment "LoadModule ssl_module" in httpd.conf'
            ];
        }
        
        $sslConfig = $this->parser->findDirective('SSLEngine');
        if (empty($sslConfig)) {
            return [
                'status' => 'warning',
                'message' => 'SSL Not Configured: mod_ssl loaded but no virtual hosts use SSL. '
                           . 'Fix: Create <VirtualHost *:443> with SSLEngine On'
            ];
        }
        
        $sslProtocols = $this->parser->findDirective('SSLProtocol');
        $strongProtocols = false;
        
        foreach ($sslProtocols as $file => $directives) {
            foreach ($directives as $directive) {
                if (preg_match('/SSLProtocol\s+(.+)/i', $directive, $matches)) {
                    $protocols = explode(',', strtoupper($matches[1]));
                    if (in_array('TLSV1.2', $protocols) || in_array('TLSV1.3', $protocols)) {
                        $strongProtocols = true;
                        break 2;
                    }
                }
            }
        }
        
        if (!$strongProtocols) {
            return [
                'status' => 'critical',
                'message' => 'Weak SSL Protocols: Using outdated TLS versions vulnerable to attacks. '
                           . 'Fix: Set "SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1"'
            ];
        }
        
        return [
            'status' => 'ok',
            'message' => 'SSL Properly Configured: Strong protocols (TLS 1.2+) enabled'
        ];
    }
    
    private function checkServerSignature() {
        $directives = $this->parser->findDirective('ServerSignature');
        if (empty($directives)) {
            return [
                'status' => 'warning',
                'message' => 'Server Signature Exposure: Default shows server version on error pages. '
                           . 'Fix: Add "ServerSignature Off" to httpd.conf'
            ];
        }
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (stripos($value, 'ServerSignature Off') !== false) {
                    return [
                        'status' => 'ok',
                        'message' => 'Server Signature Hidden: Error pages wont reveal server info'
                    ];
                }
            }
        }
        
        return [
            'status' => 'warning',
            'message' => 'Server Signature Exposure: Reveals server details on error pages. '
                       . 'Fix: Set "ServerSignature Off"'
        ];
    }
    
    private function checkTraceMethod() {
        $directives = $this->parser->findDirective('TraceEnable');
        if (empty($directives)) {
            return [
                'status' => 'critical',
                'message' => 'TRACE Method Enabled: Default allows cross-site tracing attacks. '
                           . 'Fix: Add "TraceEnable Off" to httpd.conf'
            ];
        }
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (stripos($value, 'TraceEnable Off') !== false) {
                    return [
                        'status' => 'ok',
                        'message' => 'TRACE Method Disabled: Cross-site tracing prevented'
                    ];
                }
            }
        }
        
        return [
            'status' => 'critical',
            'message' => 'TRACE Method Enabled: Allows dangerous cross-site tracing. '
                       . 'Immediate fix: Add "TraceEnable Off"'
        ];
    }
    
    private function checkInsecureDirectives() {
        $insecureDirectives = [
            'AllowOverride' => [
                'options' => ['None'],
                'message' => 'Security risk: Allows .htaccess overrides. Set to "AllowOverride None"'
            ],
            'EnableSendfile' => [
                'options' => ['Off'],
                'message' => 'Potential vulnerability: Disable with "EnableSendfile Off"'
            ],
            'UseCanonicalName' => [
                'options' => ['Off'],
                'message' => 'Info disclosure: Set "UseCanonicalName Off" to hide server names'
            ]
        ];
        
        $issues = [];
        $worstStatus = 'ok';
        
        foreach ($insecureDirectives as $directive => $config) {
            $found = $this->parser->findDirective($directive);
            $status = 'ok';
            $message = "{$directive} properly configured";
            
            if (!empty($found)) {
                foreach ($found as $file => $values) {
                    foreach ($values as $value) {
                        $matched = false;
                        foreach ($config['options'] as $option) {
                            if (stripos($value, "{$directive} {$option}") !== false) {
                                $matched = true;
                                break;
                            }
                        }
                        if (!$matched) {
                            $status = 'warning';
                            $message = $config['message'];
                            $issues[] = $message;
                            break 2;
                        }
                    }
                }
            } else {
                $status = 'warning';
                $message = "{$directive} not set (default may be insecure)";
                $issues[] = $message;
            }
            
            if ($status === 'critical' || ($status === 'warning' && $worstStatus !== 'critical')) {
                $worstStatus = $status;
            }
        }
        
        if (empty($issues)) {
            return [
                'status' => 'ok',
                'message' => 'All security directives properly configured'
            ];
        }
        
        return [
            'status' => $worstStatus,
            'message' => 'Insecure Directives Found: ' . implode('; ', $issues) . '. '
                       . 'Edit httpd.conf to apply recommended settings'
        ];
    }
    
    private function checkModuleSecurity() {
        $dangerousModules = [
            'mod_php' => 'Security risk: Use mod_php alternatives like PHP-FPM',
            'mod_perl' => 'Potential vulnerability: Only enable if required',
            'mod_python' => 'Security concern: Disable if not in use',
            'mod_rewrite' => 'Can be dangerous: Audit all RewriteRules carefully'
        ];
        
        $loadedModules = apache_get_modules();
        $problemModules = [];
        
        foreach ($dangerousModules as $module => $reason) {
            if (in_array($module, $loadedModules)) {
                $problemModules[$module] = $reason;
            }
        }
        
        if (empty($problemModules)) {
            return [
                'status' => 'ok',
                'message' => 'Module Security: No high-risk modules detected'
            ];
        }
        
        $message = 'Potentially Dangerous Modules: ';
        $details = [];
        foreach ($problemModules as $module => $reason) {
            $details[] = "{$module} ({$reason})";
        }
        
        return [
            'status' => 'warning',
            'message' => $message . implode(', ', $details) . '. '
                       . 'Recommendation: Disable unused modules in httpd.conf'
        ];
    }

    private function checkPhpConfig() {
        $phpini = @parse_ini_file('D:/xampp/php/php.ini');
        if (!$phpini) {
            return [
                'status' => 'critical',
                'message' => 'PHP Config Missing: Cannot read php.ini. '
                           . 'Verify file exists at D:/xampp/php/php.ini'
            ];
        }
    
        $checks = [
            'display_errors' => [
                'expected' => 'Off',
                'message' => 'Security risk: Shows errors to users. Set display_errors=Off'
            ],
            'expose_php' => [
                'expected' => 'Off',
                'message' => 'Info disclosure: Shows PHP version. Set expose_php=Off'
            ],
            'allow_url_fopen' => [
                'expected' => 'Off',
                'message' => 'Dangerous: Allows remote file inclusion. Set allow_url_fopen=Off'
            ],
            'disable_functions' => [
                'expected' => 'system,passthru,exec,shell_exec',
                'message' => 'Critical: Dangerous functions enabled. Add to disable_functions: '
                           . 'exec,passthru,shell_exec,system,proc_open,popen'
            ]
        ];
    
        $issues = [];
        foreach ($checks as $key => $config) {
            if (!isset($phpini[$key])) {
                $issues[] = "{$key} not configured";
            } elseif ($phpini[$key] != $config['expected']) {
                $issues[] = "{$config['message']} (Current: {$phpini[$key]})";
            }
        }
    
        return empty($issues) 
            ? [
                'status' => 'ok',
                'message' => 'PHP Hardened: Secure configuration detected'
              ]
            : [
                'status' => 'critical',
                'message' => 'PHP Security Issues: ' . implode('; ', $issues) . '. '
                           . 'Edit D:/xampp/php/php.ini and restart Apache'
              ];
    }
    
    private function checkMysqlConfig() {
        $myini = @file_get_contents('D:/xampp/mysql/my.ini');
        if (!$myini) {
            return [
                'status' => 'warning',
                'message' => 'MySQL Config: File not found at D:/xampp/mysql/my.ini. '
                           . 'Using default insecure settings'
            ];
        }
    
        $checks = [
            'skip-networking' => [
                'expected' => true,
                'message' => 'Security: Enable skip-networking if remote access not needed'
            ],
            'bind-address' => [
                'expected' => '127.0.0.1',
                'message' => 'Risk: MySQL listening externally. Set bind-address=127.0.0.1'
            ]
        ];
    
        $issues = [];
        foreach ($checks as $key => $config) {
            if (strpos($myini, $key) === false) {
                $issues[] = $config['message'];
            }
        }
    
        return empty($issues) 
            ? [
                'status' => 'ok',
                'message' => 'MySQL Secured: Proper network restrictions configured'
              ]
            : [
                'status' => 'warning',
                'message' => 'MySQL Configuration Issues: ' . implode('; ', $issues) . '. '
                           . 'Edit D:/xampp/mysql/my.ini and restart MySQL'
              ];
    }
    
    private function checkFilePermissions() {
        $criticalPaths = [
            'D:/xampp/htdocs' => 0755,
            'D:/xampp/phpmyadmin' => 0755,
            'D:/xampp/apache/logs' => 0700
        ];
    
        $issues = [];
        foreach ($criticalPaths as $path => $recommended) {
            if (!file_exists($path)) continue;
            
            $perms = fileperms($path) & 0777;
            if ($perms != $recommended) {
                $humanPerms = substr(sprintf('%o', $perms), -4);
                $humanRec = substr(sprintf('%o', $recommended), -4);
                $issues[] = "{$path} permissions are {$humanPerms} (should be {$humanRec})";
            }
        }
    
        return empty($issues) 
            ? [
                'status' => 'ok',
                'message' => 'File Permissions Secure: Critical directories properly restricted'
              ]
            : [
                'status' => 'critical',
                'message' => 'Dangerous Permissions: ' . implode('; ', $issues) . '. '
                           . 'Immediate action required: Run these commands in XAMPP shell: '
                           . 'chmod 755 htdocs phpmyadmin && chmod 700 apache/logs'
              ];
    }
    
    private function checkDefaultFiles() {
        $dangerousFiles = [
            'D:/xampp/htdocs/xampp',
            'D:/xampp/htdocs/webalizer',
            'D:/xampp/htdocs/dashboard'
        ];
    
        $found = [];
        foreach ($dangerousFiles as $file) {
            if (file_exists($file)) {
                $found[] = str_replace('D:/xampp/htdocs/', '', $file);
            }
        }
    
        return empty($found) 
            ? [
                'status' => 'ok',
                'message' => 'Default Files: No XAMPP test pages found in webroot'
              ]
            : [
                'status' => 'critical',
                'message' => 'Default XAMPP Files Exposed: ' . implode(', ', $found) . ' accessible. '
                           . 'Critical risk! Remove these or password protect: '
                           . 'rm -rf htdocs/{xampp,webalizer,dashboard}'
              ];
    }
    
    private function checkXamppSecurity() {
        $securityFile = 'D:/xampp/security/xampp.users';
        if (!file_exists($securityFile)) {
            return [
                'status' => 'critical',
                'message' => 'XAMPP Protection Missing: No password set for admin tools. '
                           . 'Anyone can access phpMyAdmin! '
                           . 'Fix: Run "xampp\xampp_security.bat" and set passwords'
            ];
        }
    
        $content = file_get_contents($securityFile);
        if (empty($content)) {
            return [
                'status' => 'critical',
                'message' => 'XAMPP Security Misconfigured: Password file empty. '
                           . 'Run security setup again: xampp_security.bat'
            ];
        }
    
        return [
            'status' => 'ok',
            'message' => 'XAMPP Secured: Password protection enabled for admin tools'
        ];
    }

    private function checkErrorLogging() {
        $directives = $this->parser->findDirective('ErrorLog');
        $logLevel = $this->parser->findDirective('LogLevel');
        
        $issues = [];
        if (empty($directives)) {
            $issues[] = 'Error logging not configured (critical for troubleshooting)';
        }
        
        if (empty($logLevel)) {
            $issues[] = 'LogLevel not set (defaults to warn)';
        } else {
            foreach ($logLevel as $values) {
                foreach ($values as $value) {
                    if (stripos($value, 'LogLevel debug') !== false) {
                        $issues[] = 'Debug logging enabled (exposes sensitive data)';
                    }
                }
            }
        }
        
        return empty($issues) 
            ? [
                'status' => 'ok',
                'message' => 'Error Logging: Properly configured with secure levels'
              ]
            : [
                'status' => 'warning',
                'message' => 'Logging Issues: ' . implode('; ', $issues) . '. '
                           . 'Recommendation: Set "ErrorLog logs/error.log" and "LogLevel warn"'
              ];
    }
    
    private function checkHttpHeaders() {
        $headers = [
            'X-Powered-By' => 'Exposes PHP version',
            'Server' => 'Shows Apache version',
            'X-AspNet-Version' => 'Reveals ASP.NET info'
        ];
        
        $issues = [];
        foreach ($headers as $header => $risk) {
            $directives = $this->parser->findDirective("Header unset $header");
            if (empty($directives)) {
                $issues[] = "{$header} ({$risk})";
            }
        }
        
        return empty($issues) 
            ? [
                'status' => 'ok',
                'message' => 'HTTP Headers Secure: Sensitive headers removed'
              ]
            : [
                'status' => 'warning',
                'message' => 'Exposed Headers: ' . implode(', ', $issues) . '. '
                           . 'Fix: Add "Header unset X-Powered-By" etc. to httpd.conf'
              ];
    }
    
    private function checkTimeoutSettings() {
        $directives = $this->parser->findDirective('Timeout');
        $recommended = 60;
        
        if (empty($directives)) {
            return [
                'status' => 'warning',
                'message' => 'Timeout Not Set: Using default 300 seconds. '
                           . 'Recommendation: Set "Timeout 60"'
            ];
        }
        
        foreach ($directives as $values) {
            foreach ($values as $value) {
                if (preg_match('/Timeout\s+(\d+)/', $value, $matches)) {
                    $current = (int)$matches[1];
                    if ($current > $recommended) {
                        return [
                            'status' => 'warning',
                            'message' => "High Timeout: {$current} seconds (max should be 60). "
                                       . 'Allows DoS attacks. Set "Timeout 60"'
                        ];
                    }
                }
            }
        }
        
        return [
            'status' => 'ok',
            'message' => 'Timeout Properly Set: Protects against slowloris attacks'
        ];
    }

    private function checkKeepaliveSettings() {
        $directives = $this->parser->findDirective('KeepAlive');
        $timeout = $this->parser->findDirective('KeepAliveTimeout');
        
        $issues = [];
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (stripos($value, 'KeepAlive Off') !== false) {
                    $issues[] = 'KeepAlive disabled (hurts performance)';
                }
            }
        }
        
        foreach ($timeout as $file => $values) {
            foreach ($values as $value) {
                if (preg_match('/KeepAliveTimeout\s+(\d+)/', $value, $matches)) {
                    $current = (int)$matches[1];
                    if ($current > 15) {
                        $issues[] = "KeepAliveTimeout too high ({$current}s)";
                    }
                }
            }
        }
        
        return empty($issues) 
            ? [
                'status' => 'ok',
                'message' => 'KeepAlive Optimized: Proper balance of performance/security'
              ]
            : [
                'status' => 'warning',
                'message' => 'KeepAlive Issues: ' . implode('; ', $issues) . '. '
                           . 'Recommended: "KeepAlive On" with "KeepAliveTimeout 5"'
              ];
    }
    
    private function checkIndexesSettings() {
        $directives = $this->parser->findDirective('DirectoryIndex');
        
        if (empty($directives)) {
            return [
                'status' => 'warning',
                'message' => 'DirectoryIndex Not Set: Defaults to index.html only. '
                           . 'Recommendation: Set priority (e.g. "DirectoryIndex index.php index.html")'
            ];
        }
        
        $riskyFiles = [];
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (preg_match('/DirectoryIndex\s+(.+)/i', $value, $matches)) {
                    $files = explode(' ', $matches[1]);
                    foreach ($files as $file) {
                        $file = strtolower($file);
                        if (in_array($file, ['index.php', 'index.pl', 'index.cgi'])) {
                            $riskyFiles[] = $file . ' (execute code if uploaded)';
                        }
                    }
                }
            }
        }
        
        return empty($riskyFiles) 
            ? [
                'status' => 'ok',
                'message' => 'DirectoryIndex Secure: No executable default files'
              ]
            : [
                'status' => 'warning',
                'message' => 'Risky Default Files: ' . implode(', ', $riskyFiles) . '. '
                           . 'Audit uploads or change order: "DirectoryIndex index.html index.php"'
              ];
    }
    
    private function checkUserAgentLogging() {
        $directives = $this->parser->findDirective('CustomLog');
        $hasUserAgent = false;
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (strpos($value, '%{User-agent}i') !== false || 
                    strpos($value, 'combined') !== false) {
                    $hasUserAgent = true;
                    break 2;
                }
            }
        }
        
        return $hasUserAgent
            ? [
                'status' => 'warning',
                'message' => 'User Agent Logging: Recording browser info raises privacy concerns. '
                           . 'Consider using "common" log format instead'
              ]
            : [
                'status' => 'ok',
                'message' => 'Privacy Protected: No user agent logging detected'
              ];
    }
    
    private function checkServerLimit() {
        $directives = $this->parser->findDirective('ServerLimit');
        
        if (empty($directives)) {
            return [
                'status' => 'ok',
                'message' => 'ServerLimit: Using default value (no overcommit)'
            ];
        }
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (preg_match('/ServerLimit\s+(\d+)/', $value, $matches)) {
                    $limit = (int)$matches[1];
                    if ($limit > 256) {
                        return [
                            'status' => 'warning',
                            'message' => "High ServerLimit: {$limit} may cause memory exhaustion. "
                                       . 'Set below 256 unless server has 8GB+ RAM'
                        ];
                    }
                }
            }
        }
        
        return [
            'status' => 'ok',
            'message' => 'ServerLimit: Within safe boundaries'
        ];
    }
    
    private function checkSymlinkProtection() {
        $directives = $this->parser->findDirective('Options');
        $hasFollowSymLinks = false;
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (strpos($value, 'FollowSymLinks') !== false && 
                    strpos($value, '-FollowSymLinks') === false) {
                    $hasFollowSymLinks = true;
                    break 2;
                }
            }
        }
        
        return $hasFollowSymLinks
            ? [
                'status' => 'critical',
                'message' => 'Symlink Vulnerability: FollowSymLinks allows directory traversal. '
                           . 'Immediate fix: Replace with "SymLinksIfOwnerMatch"'
              ]
            : [
                'status' => 'ok',
                'message' => 'Symlink Protection: FollowSymLinks disabled or properly restricted'
              ];
    }
    
    private function checkMimeTypes() {
        $configPath = $this->parser->getConfigPath();
        $mimeFiles = [
            $configPath . 'mime.types',
            $configPath . 'extra/mime.types'
        ];
        
        $dangerousTypes = [
            'application/x-httpd-php' => 'Can execute PHP in uploads',
            'application/x-httpd-cgi' => 'Allows CGI execution',
            'application/x-shockwave-flash' => 'Vulnerable Flash content'
        ];
        
        $found = [];
        foreach ($mimeFiles as $file) {
            if (file_exists($file)) {
                $content = file_get_contents($file);
                foreach ($dangerousTypes as $type => $risk) {
                    if (strpos($content, $type) !== false) {
                        $found[] = "{$type} ({$risk})";
                    }
                }
            }
        }
        
        return empty($found)
            ? [
                'status' => 'ok',
                'message' => 'MIME Types: No dangerous content handlers found'
              ]
            : [
                'status' => 'warning',
                'message' => 'Risky MIME Types: ' . implode(', ', $found) . '. '
                           . 'Audit file uploads or remove these associations'
              ];
    }
    
    private function checkCgiSettings() {
        $directives = $this->parser->findDirective('ScriptAlias');
        $cgiEnabled = $this->parser->checkModuleLoaded('cgi');
        
        if (!$cgiEnabled) {
            return [
                'status' => 'ok',
                'message' => 'CGI Security: Module not loaded (recommended)'
            ];
        }
        
        $issues = [];
        if (!empty($directives)) {
            $issues[] = 'ScriptAlias directives found (CGI enabled)';
        }
        
        $execDirectives = $this->parser->findDirective('AddHandler cgi-script');
        if (!empty($execDirectives)) {
            $issues[] = 'CGI execution allowed for some extensions';
        }
        
        return empty($issues)
            ? [
                'status' => 'ok',
                'message' => 'CGI Secured: No active CGI configurations found'
              ]
            : [
                'status' => 'critical',
                'message' => 'CGI Risks: ' . implode('; ', $issues) . '. '
                           . 'Disable mod_cgi if not required, or audit all scripts'
              ];
    }
    
    private function checkProxySettings() {
        $proxyEnabled = $this->parser->checkModuleLoaded('proxy');
        
        if (!$proxyEnabled) {
            return [
                'status' => 'ok',
                'message' => 'Proxy Security: Module not loaded (recommended)'
            ];
        }
        
        $directives = array_merge(
            $this->parser->findDirective('ProxyRequests'),
            $this->parser->findDirective('ProxyVia')
        );
        
        $issues = [];
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (stripos($value, 'ProxyRequests On') !== false) {
                    $issues[] = 'Open proxy enabled (extremely dangerous)';
                }
                if (stripos($value, 'ProxyVia On') !== false) {
                    $issues[] = 'ProxyVia headers enabled (info disclosure)';
                }
            }
        }
        
        return empty($issues)
            ? [
                'status' => 'warning',
                'message' => 'Proxy Module Loaded: No active configurations found. '
                           . 'Recommendation: Disable mod_proxy if unused'
              ]
            : [
                'status' => 'critical',
                'message' => 'Proxy Risks: ' . implode('; ', $issues) . '. '
                           . 'Immediate action: Set "ProxyRequests Off" and "ProxyVia Off"'
              ];
    }
    
    private function checkDNSLookups() {
        $directives = $this->parser->findDirective('HostnameLookups');
        
        if (empty($directives)) {
            return [
                'status' => 'ok',
                'message' => 'DNS Lookups: Disabled by default (recommended)'
            ];
        }
        
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (stripos($value, 'HostnameLookups On') !== false) {
                    return [
                        'status' => 'warning',
                        'message' => 'DNS Lookups Enabled: Causes performance issues. '
                                   . 'Set "HostnameLookups Off"'
                    ];
                }
            }
        }
        
        return [
            'status' => 'ok',
            'message' => 'DNS Lookups: Properly disabled'
        ];
    }
    
    private function checkServerStatus() {
        $directives = $this->parser->findDirective('Location /server-status');
        
        if (empty($directives)) {
            return [
                'status' => 'ok',
                'message' => 'Server Status: Monitoring page disabled (recommended)'
            ];
        }
        
        $issues = [];
        foreach ($directives as $file => $values) {
            foreach ($values as $value) {
                if (strpos($value, 'Require local') === false && 
                    strpos($value, 'Require ip 127.0.0.1') === false) {
                    $issues[] = 'Accessible from remote (security risk)';
                }
            }
        }
        
        return empty($issues)
            ? [
                'status' => 'warning',
                'message' => 'Server Status Page: Enabled but restricted to localhost. '
                           . 'Recommendation: Disable if unused'
              ]
            : [
                'status' => 'critical',
                'message' => 'Server Status Exposure: ' . implode('; ', $issues) . '. '
                           . 'Immediate fix: Add "Require local" or disable completely'
              ];
    }
}
?>