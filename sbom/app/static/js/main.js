// Main JavaScript for SBOM Analyzer

document.addEventListener('DOMContentLoaded', function() {
    const uploadForm = document.getElementById('upload-form');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    
    if (uploadForm) {
        uploadForm.addEventListener('submit', handleFileUpload);
    }
    
    function handleFileUpload(event) {
        event.preventDefault();
        
        const formData = new FormData(uploadForm);
        const fileInput = document.getElementById('sbom-file');
        
        if (!fileInput.files[0]) {
            alert('Please select a file to upload');
            return;
        }
        
        // Add configuration parameters
        const maxDepth = document.getElementById('max-depth')?.value || 1;
        const maxPackagesPerLevel = document.getElementById('max-packages-per-level')?.value || 20;
        
        formData.append('max_depth', maxDepth); // Will always be 1, but we keep it for future use
        formData.append('max_packages_per_level', maxPackagesPerLevel);
        
        // Show loading
        loading.classList.remove('hidden');
        results.classList.add('hidden');
        
        // Send file to server
        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            loading.classList.add('hidden');
            
            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }
            
            // Only redirect to results page; scan data is fetched there
            window.location.href = data.redirect_url || '/results';
        })
        .catch(error => {
            loading.classList.add('hidden');
            console.error('Error:', error);
            alert('An error occurred during analysis. Please try again.');
        });
    }
    
    // File input change handler
    const fileInput = document.getElementById('sbom-file');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                // Validate file type
                const allowedTypes = ['.txt', '.toml'];
                const fileName = file.name;
                const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
                
                if (!allowedTypes.includes(fileExtension) && fileName !== 'Pipfile') {
                    alert('Invalid file type. Please select a supported dependency file.');
                    fileInput.value = '';
                    return;
                }
                
                // Validate file size (max 10MB)
                if (file.size > 10 * 1024 * 1024) {
                    alert('File size too large. Please select a file smaller than 10MB.');
                    fileInput.value = '';
                    return;
                }
                
                console.log('Selected file:', file.name);
            }
        });
    }
}); 