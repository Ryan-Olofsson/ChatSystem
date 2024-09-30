export async function initializeUser() {
    const username = prompt("Please enter your username:");
    if (username) {
        const public_key = Math.floor(Math.random() * 1000); // Replace with actual key generation logic
        console.log("Public Key:", public_key);
        await sendHelloMessage(public_key);
    } else {
        alert("Username is required to connect.");
    }
}

export async function sendHelloMessage(publicKey) {
const message = {
    data: {
        type: "hello",
        public_key: publicKey
    }
};

// Emit the JSON package to the server
fetch('/api/message', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(message)
})
.then(response => {
    if (!response.ok) {
        throw new Error('Network response was not ok');
    }
    return response.json();
})
.then(data => {
    console.log("Response from server:", data);
})
.catch(error => {
    console.error("Error:", error);
});
}
