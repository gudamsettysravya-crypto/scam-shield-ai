/**
 * SCAMSHIELD AI - Analyzer UI Interactions, OCR Trigger, Sample Loaders & Agent Pipeline Animator
 */

document.addEventListener('DOMContentLoaded', () => {
    const messageInput = document.getElementById('message_text');
    const screenshotInput = document.getElementById('screenshot');
    const imagePreviewContainer = document.getElementById('imagePreviewContainer');
    const imagePreview = document.getElementById('imagePreview');
    const ocrStatus = document.getElementById('ocrStatus');
    const analyzeForm = document.getElementById('analyzeForm');
    const submitBtn = document.getElementById('submitBtn');
    const pipelineContainer = document.getElementById('pipelineContainer');

    // 1. Screenshot Upload Preview & Instant OCR Call
    if (screenshotInput) {
        screenshotInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                // Show Image Preview
                const reader = new FileReader();
                reader.onload = (event) => {
                    imagePreview.src = event.target.result;
                    imagePreviewContainer.style.display = 'block';
                };
                reader.readAsDataURL(file);

                // Perform AJAX OCR Extraction
                if (ocrStatus) {
                    ocrStatus.style.display = 'block';
                    ocrStatus.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> 🤖 Extracting text from screenshot via AI Vision...';
                }

                const formData = new FormData();
                formData.append('file', file);

                fetch('/analyze/api_ocr', {
                    method: 'POST',
                    body: formData
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success && data.extracted_text) {
                        if (messageInput) {
                            messageInput.value = data.extracted_text;
                        }
                        if (ocrStatus) {
                            ocrStatus.className = 'alert alert-success mt-2';
                            ocrStatus.innerHTML = `✔ Text extracted successfully using ${data.method || 'OCR'}. You can edit it below before analysis.`;
                        }
                    } else {
                        if (ocrStatus) {
                            ocrStatus.className = 'alert alert-warning mt-2';
                            ocrStatus.innerHTML = `⚠️ ${data.error || 'Could not auto-read text. Please type or edit the message manually.'}`;
                        }
                    }
                })
                .catch(err => {
                    console.error("OCR Error:", err);
                    if (ocrStatus) {
                        ocrStatus.className = 'alert alert-warning mt-2';
                        ocrStatus.innerHTML = '⚠️ OCR server notice: Please review or edit the message manually.';
                    }
                });
            }
        });
    }

    // 2. Preloaded Demo Sample Loaders
    const sampleButtons = document.querySelectorAll('.sample-btn');
    sampleButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const sampleType = btn.getAttribute('data-sample');
            let text = "";
            if (sampleType === 'prize') {
                text = "Congratulations! You have won ₹50,000 in Tata Lottery. Pay ₹499 processing fee immediately and click the link below to claim your reward: http://tata-lottery-claim.xyz/reward";
            } else if (sampleType === 'otp') {
                text = "Dear Customer, your SBI account is suspended due to pending KYC verification. Update immediately at http://192.168.1.55/sbi/login.php or share your OTP with our officer calling from 9876543210.";
            } else if (sampleType === 'job') {
                text = "Part-time Job Offer! Earn ₹3,000/day by liking YouTube videos. Registration fee ₹200 required. Contact HR on Telegram @easy_jobs_online.";
            } else if (sampleType === 'low') {
                text = "Dear customer, your Amazon order #402-9918231-1928312 has been dispatched. Track delivery directly on official Amazon app.";
            }

            if (messageInput) {
                messageInput.value = text;
                messageInput.focus();
            }
        });
    });

    // 3. AI Agent Pipeline Visualizer Animation
    if (analyzeForm) {
        analyzeForm.addEventListener('submit', (e) => {
            if (!messageInput || !messageInput.value.strip ? !messageInput.value.trim() : false) {
                return; // Let HTML validation show
            }

            // Show Pipeline Animator
            if (pipelineContainer) {
                e.preventDefault();
                pipelineContainer.style.display = 'block';
                if (submitBtn) submitBtn.disabled = true;

                const steps = document.querySelectorAll('.pipeline-step');
                let currentStep = 0;

                const stepInterval = setInterval(() => {
                    if (currentStep > 0) {
                        steps[currentStep - 1].classList.remove('active');
                        steps[currentStep - 1].classList.add('completed');
                    }
                    if (currentStep < steps.length) {
                        steps[currentStep].classList.add('active');
                        currentStep++;
                    } else {
                        clearInterval(stepInterval);
                        // Submit form after animation sequence
                        analyzeForm.submit();
                    }
                }, 350);
            }
        });
    }
});
