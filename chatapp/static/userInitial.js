/* Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935 */
let socket;
let userFingerprint;

// Function to initialize the socket
function initializeSocket() {
    if (!socket) {
        socket = io(); // Initialize socket only if it's not already initialized
    }
}
 
export async function initializeUser() {
    initializeSocket();
    let username = "";
    while (!username) {
        username = prompt("Please enter your username:");
        if (!username) {
            alert("Username is required to connect.");
        }
    }

    if (username) {
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
            userFingerprint = data.fingerprint;
            socket.emit("addUser", {username, public_key});
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
    console.log("Response from server:", "successful connection");
})
.catch(error => {
    console.error("Error:", error);
});
}

export function updateSelectedChat() {
    const dropdown = document.getElementById("onlineUsersDropdown");
    const selectedFingerprint = dropdown.value; // Get the selected value
    const selectedChatElement = document.getElementById("selectedChat");

    if (selectedFingerprint) {
        selectedChatElement.textContent = `Talking to: ${selectedFingerprint}`; // Update the text
    } else {
        selectedChatElement.textContent = "Talking to: None"; // Reset if no selection
    }
}

export function getUserFingerprint() {
    return userFingerprint;
}