<?php
session_start();
require_once 'includes/header.php';

if (!isset($_SESSION['scan_results'])) {
    header('Location: index.php');
    exit;
}

$results = $_SESSION['scan_results'];
$scanType = $_SESSION['scan_type'];

// Function to safely get status from a result (handles both direct and nested results)
function getResultStatus($result) {
    if (isset($result['status'])) {
        return $result['status'];
    }
    // If it's an array of results, find the worst status
    if (is_array($result)) {
        $statuses = array_column($result, 'status');
        if (in_array('critical', $statuses)) return 'critical';
        if (in_array('warning', $statuses)) return 'warning';
        return 'ok';
    }
    return 'ok';
}

// Function to safely get message from a result
function getResultMessage($result) {
    if (isset($result['message'])) {
        return $result['message'];
    }
    if (is_array($result)) {
        return implode('; ', array_column($result, 'message'));
    }
    return 'No message available';
}
?>
<div class="container">
    <h1>Scan Results: <?php echo ucfirst($scanType); ?> Scan</h1>
    
    <div class="card mb-4">
        <div class="card-header">
            <h2>Summary</h2>
        </div>
        <div class="card-body">
            <?php
            $critical = 0;
            $warnings = 0;
            $ok = 0;
            
            foreach ($results as $result) {
                $status = getResultStatus($result);
                if ($status === 'critical') $critical++;
                if ($status === 'warning') $warnings++;
                if ($status === 'ok') $ok++;
            }
            ?>
            
            <div class="row">
                <div class="col-md-4">
                    <div class="alert alert-danger">
                        <h4>Critical: <?php echo $critical; ?></h4>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="alert alert-warning">
                        <h4>Warnings: <?php echo $warnings; ?></h4>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="alert alert-success">
                        <h4>Passed: <?php echo $ok; ?></h4>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header">
            <h2>Detailed Results</h2>
        </div>
        <div class="card-body">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Check</th>
                        <th>Status</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($results as $check => $result): 
                        $status = getResultStatus($result);
                        $message = getResultMessage($result);
                    ?>
                    <tr>
                        <td><?php echo ucfirst(str_replace('_', ' ', $check)); ?></td>
                        <td>
                            <span class="badge badge-<?php 
                                echo $status === 'critical' ? 'danger' : 
                                    ($status === 'warning' ? 'warning' : 'success'); 
                            ?>">
                                <?php echo ucfirst($status); ?>
                            </span>
                        </td>
                        <td><?php echo htmlspecialchars($message); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    
    <div class="mt-4">
        <a href="index.php" class="btn btn-primary">Run Another Scan</a>
    </div>
</div>

<?php 
unset($_SESSION['scan_results']);
unset($_SESSION['scan_type']);
require_once 'includes/footer.php'; 
?>