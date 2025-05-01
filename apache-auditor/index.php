<?php include 'includes/header.php'; ?>

<div class="container">
    <h1>Apache Web Server Auditor</h1>
    <p class="lead">Scan your Apache configuration for security issues and best practices</p>
    
    <div class="row">
        <div class="col-md-6">
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Quick Scan</h5>
                    <p class="card-text">Perform a basic scan of common Apache security settings.</p>
                    <a href="scan.php?type=quick" class="btn btn-primary">Run Quick Scan</a>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Full Audit</h5>
                    <p class="card-text">Comprehensive analysis of all Apache configuration files.</p>
                    <a href="scan.php?type=full" class="btn btn-secondary">Run Full Audit</a>
                </div>
            </div>
        </div>
    </div>
    
    <div class="mt-4">
        <h3>How it works:</h3>
        <ol>
            <li>Our tool analyzes your Apache configuration files</li>
            <li>Checks against security best practices</li>
            <li>Provides actionable recommendations</li>
        </ol>
    </div>
</div>

<?php include 'includes/footer.php'; ?>