# Olaf's Neighbourhood Protocol (ONP)

Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935, Isaak Goodwin.

This is a simple implementation of a secure messaging system using WebSockets and Flask.

## Requirements

To compile and run this project, you'll need:

- A python interpreter
- Flask
- Flask-SocketIO
- cryptography
- requests
- websocket-client

## Compilation

To compile the project, first install the requirements by running: pip install -r requirements.txt

## Program Functionality

Once python serverStart.py has been executed, it will act as the hub for all server responses/messages.

For each client instance, run python clientStart.py. This can be accessible by navigating to the URL 127.0.0.1:5000 in any browser.

The username entry prompt is used to identify users in the system. It is required to enter a username to proceed.

Once the username has been entered, the rest of the site can be accessed. 

Once multiple clients are running, the refresh button can be clicked to update the list of online users. This can be accessed in the dropdown.

Based on the list of online users, messages can be sent to specific users. It will indicate which user the message is sent to on the application.

Group chat button opens a modal where multiple users can be selected to send a group message to.

Unfortunately, whilst we can encrypt with the sender and decrypt with the reciever, we are unable to get it to show on the recievers screen.

Files can be uploaded to the site by clicked the Upload File button, then clicking on the Browse button, selecting a valid file, and finally clicking the Upload button. On a successful upload, a message will be displayed with the URL of the uploaded file.

Files can be retrieved by entering the url provided in the upload message into the web browser url.

Once finished, you can remove the dependencies by running: pip uninstall -r requirements.txt and then deleting the cloned folder.
