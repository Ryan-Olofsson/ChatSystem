// const socket = new WebSocket("ws://localhost:5500");
// // Connection console log
// socket.onopen = function(event) {
//     console.log("Request accepted");
// }

// // Send message
// function sendMessage(event) {
//     event.preventDefault();

//     const input = document.querySelector('input');
//     if (input.value) {
//         socket.send(input.value)
//         input.value = "";
//     }
//     input.focus();
// }

// document.querySelector('form').addEventListener('submit', sendMessage);

// // Listen for messages
// socket.addEventListener('message', ({ data }) => {
//     const li = document.createElement('li');
//     li.textContent = data;
//     document.querySelector('ul').appendChild(li);
// });

// // Retrive online users
// function retriveOnlineUsers() {

// }

// // Update list of online users
// function updateOnlineUsersList() {

// }

// // Changes recipient of message
// function recipientSelection() {

// }

// // Retreive chat history
// function retrieveChatHistory() {

// } 

// // Upload files to submit
// function uploadFiles() {

// }