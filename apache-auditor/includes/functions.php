<?php
function getApacheVersion() {
    exec('httpd -v', $output);
    return $output[0] ?? 'Unknown';
}

function parseApacheConfig($filePath) {
    if (!file_exists($filePath)) {
        return false;
    }
    
    $config = file_get_contents($filePath);
    return $config;
}

function checkModuleEnabled($moduleName) {
    exec('httpd -M', $modules);
    foreach ($modules as $module) {
        if (strpos($module, $moduleName) !== false) {
            return true;
        }
    }
    return false;
}

function scanDirectory($path) {
    $results = [];
    if (is_dir($path)) {
        $items = scandir($path);
        foreach ($items as $item) {
            if ($item !== '.' && $item !== '..') {
                $results[] = $item;
            }
        }
    }
    return $results;
}
?>