document.addEventListener('DOMContentLoaded', function() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            navItems.forEach(navItem => navItem.classList.remove('active'));
            this.classList.add('active');
        });
    });

    const expandIcon = document.querySelector('.expand-icon');
    const sidebar = document.querySelector('.sidebar');
    expandIcon.addEventListener('click', function() {
        sidebar.classList.toggle('collapsed');
    });

    const startAttackBtn = document.getElementById('startAttackBtn');
    const stopBtn = document.getElementById('stopBtn');
    const ipInput = document.querySelector('input[type="text"]'); // Get the input field

    startAttackBtn.addEventListener('click', function() {
        const ipRange = ipInput.value; // Get the IP range from the input
        const tools = ['nmap', 'openvas']; // Specify the tools you want to use

        // Make an AJAX call to start the scan
        fetch('/start_scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ipRange: ipRange, tools: tools })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Scan started with ID:', data.scan_id);
            this.style.display = 'none';
            stopBtn.style.display = 'inline-block';
        })
        .catch((error) => {
            console.error('Error starting scan:', error);
        });
    });

    stopBtn.addEventListener('click', function() {
        this.style.display = 'none';
        startAttackBtn.style.display = 'inline-block';
    });
});