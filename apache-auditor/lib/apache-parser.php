

<?php
class ApacheConfigParser {
    private $configPath;
    private $configFiles = [
        'httpd.conf',
        'extra/httpd-vhosts.conf', 
        'extra/httpd-ssl.conf',
        'extra/httpd-default.conf'
    ];
    
    public function __construct($configPath) {
        $this->configPath = $configPath;
    }
    
    // Add this new method
    public function getConfigPath() {
        return $this->configPath;
    }
    
    public function getAllConfigs() {
        $configs = [];
        foreach ($this->configFiles as $file) {
            $fullPath = $this->configPath . $file;
            if (file_exists($fullPath)) {
                $content = @file_get_contents($fullPath);
                if ($content === false) {
                    throw new Exception("Failed to read config file: $fullPath");
                }
                $configs[$file] = $content;
            }
        }
        return $configs;
    }
    
    public function findDirective($directive, $exactMatch = false) {
        $results = [];
        $configs = $this->getAllConfigs();
        
        // Escape the directive and use proper delimiters
        $escaped = preg_quote($directive, '/');
        $pattern = $exactMatch 
            ? "/^\s*".$escaped."\s+/i" 
            : "/".$escaped."/i";
        
        foreach ($configs as $file => $content) {
            $lines = explode("\n", $content);
            foreach ($lines as $line) {
                if (preg_match($pattern, $line) && !preg_match('/^\s*#/', $line)) {
                    $results[$file][] = trim($line);
                }
            }
        }
        
        return $results;
    }
    
    public function checkSSLEnabled() {
        $sslConfig = $this->configPath . 'extra/httpd-ssl.conf';
        return file_exists($sslConfig);
    }
    
    public function findInFiles($pattern) {
        $results = [];
        $configs = $this->getAllConfigs();
        
        foreach ($configs as $file => $content) {
            if (preg_match_all($pattern, $content, $matches)) {
                $results[$file] = $matches[0];
            }
        }
        
        return $results;
    }
    
    public function checkModuleLoaded($moduleName) {
        $modules = [];
        exec('httpd -M 2>&1', $modules);
        
        foreach ($modules as $module) {
            if (strpos($module, $moduleName) !== false) {
                return true;
            }
        }
        return false;
    }
}
?>