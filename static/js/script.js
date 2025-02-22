

        // FAQ Accordion functionality
        document.querySelectorAll('.faq-question').forEach(question => {
            question.addEventListener('click', () => {
                const faqItem = question.parentElement;
                
                // Close other open FAQs
                document.querySelectorAll('.faq-item').forEach(item => {
                    if (item !== faqItem && item.classList.contains('active')) {
                        item.classList.remove('active');
                    }
                });
                
                // Toggle current FAQ
                faqItem.classList.toggle('active');
            });
        });

        const video = document.getElementById('revv-video');

        // Example: Play video when the user clicks anywhere on the page
        document.addEventListener('click', () => {
            if (video.paused) {
                video.play();
            }
        });
        