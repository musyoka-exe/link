document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('shorten-form');
    const resultDiv = document.getElementById('result');
    const errorMessageDiv = document.getElementById('error-message');
    const originalUrlEl = document.getElementById('original-url');
    const shortUrlEl = document.getElementById('short-url');
    const qrCodeImg = document.getElementById('qr-code-img');
    const downloadQrLink = document.getElementById('download-qr');
    
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const urlInput = document.getElementById('url');
        const url = urlInput.value.trim();
        
        if (!url) {
            showError('Please enter a URL');
            return;
        }
        
        // Show loading state
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.textContent = 'Shortening...';
        submitBtn.disabled = true;
        
        // Send request to shorten URL
        fetch('/shorten', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `url=${encodeURIComponent(url)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showError(data.error);
            } else {
                // Update the result elements
                originalUrlEl.textContent = data.original_url;
                originalUrlEl.href = data.original_url;
                shortUrlEl.textContent = data.short_url;
                shortUrlEl.href = data.short_url;
                
                // Update QR code
                qrCodeImg.src = data.qr_code_path;
                downloadQrLink.href = data.qr_code_path;
                downloadQrLink.download = `qr_${data.short_code}.png`;
                
                // Show result and hide error
                resultDiv.classList.remove('d-none');
                errorMessageDiv.classList.add('d-none');
                
                // Scroll to result
                resultDiv.scrollIntoView({ behavior: 'smooth' });
            }
        })
        .catch(error => {
            showError('An error occurred while shortening the URL. Please try again.');
            console.error('Error:', error);
        })
        .finally(() => {
            // Reset button state
            submitBtn.textContent = originalText;
            submitBtn.disabled = false;
        });
    });
    
    function showError(message) {
        document.getElementById('error-text').textContent = message;
        errorMessageDiv.classList.remove('d-none');
        resultDiv.classList.add('d-none');
        errorMessageDiv.scrollIntoView({ behavior: 'smooth' });
    }
});