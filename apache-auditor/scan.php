<?php
// Start output buffering to prevent any output
ob_start();

// Error reporting should be at the VERY TOP
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Now start the session
session_start();

require_once 'includes/config.php';
require_once 'includes/functions.php';
require_once 'lib/apache-parser.php';
require_once 'lib/security-checks.php';

try {
    $scanType = $_GET['type'] ?? 'quick';
    $parser = new ApacheConfigParser(APACHE_CONFIG_PATH);
    $auditor = new ApacheSecurityAudit($parser);

    if ($scanType === 'quick') {
        $results = $auditor->runQuickScan();
    } else {
        $results = $auditor->runFullAudit();
    }

    $_SESSION['scan_results'] = $results;
    $_SESSION['scan_type'] = $scanType;

    // Clear the buffer before redirecting
    ob_end_clean();
    header('Location: results.php');
    exit;
} catch (Exception $e) {
    // Handle errors gracefully
    ob_end_clean();
    die('An error occurred: ' . $e->getMessage());
}
?>