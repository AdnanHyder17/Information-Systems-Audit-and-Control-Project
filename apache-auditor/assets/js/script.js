document.addEventListener('DOMContentLoaded', function() {
    // Add any interactive functionality here
    console.log('Apache Auditor loaded');
    
    // Example: Confirm before running full audit
    const fullAuditBtn = document.querySelector('a[href*="type=full"]');
    if (fullAuditBtn) {
        fullAuditBtn.addEventListener('click', function(e) {
            if (!confirm('Full audit may take several minutes. Continue?')) {
                e.preventDefault();
            }
        });
    }
});