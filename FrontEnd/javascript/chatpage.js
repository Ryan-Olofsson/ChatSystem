const socket = new WebSocket("ws://localhost:5500");
// Connection console log
socket.onopen = function(event) {
    console.log("Request accepted");
}

// Send message
function sendMessage(event) {
    event.preventDefault();

    const input = document.querySelector('input');
    if (input.value) {
        socket.send(input.value)
        input.value = "";
    }
    input.focus();
}

document.querySelector('form').addEventListener('submit', sendMessage);

// Listen for messages
socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    if (message.type === 'userList') {
        updateOnlineUsersList(message.users);
    } else {
        const li = document.createElement('li');
        li.textContent = message.text;
        document.querySelector('ul#styledList').appendChild(li);
    }
});

// Retrive online users
function retriveOnlineUsers() {

}

// Update list of online users
function updateOnlineUsersList() {

}

// Changes recipient of message
function recipientSelection() {

}

// Retreive chat history
function retrieveChatHistory() {

} 

// Upload files to submit
function uploadFiles() {

}

function selectUser(element) {
    const selectedUser = element.textContent;
    document.getElementById('dropdownOnlineUsers').textContent = selectedUser;
    document.getElementById('selectedChat').textContent = 'Talking to: ' + selectedUser;
}

// Function to update the user list
function updateOnlineUsersList(users) {
    const userList = document.getElementById('userList');
    userList.innerHTML = ''; // Clear existing list
    users.forEach(user => {
        const li = document.createElement('li');
        li.innerHTML = `<a class="dropdown-item" href="#" onclick="selectUser(this)">${user}</a>`;
        userList.appendChild(li);
    });
}