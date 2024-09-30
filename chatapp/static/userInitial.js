const socket = io(); 

export async function initializeUser() {
    const username = prompt("Please enter your username:");
    if (username) {
        console.log("username", username);
        const response = await fetch('/initialize_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });
        const data = await response.json();
        if (response.ok) {
            const public_key = data.public_key;
            socket.emit("addUser", {username, public_key});
            console.log("Public Key:", public_key);
            await sendHelloMessage(public_key);
        } else {
            alert("Username is required to connect.");
        }
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
