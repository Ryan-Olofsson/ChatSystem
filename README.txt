# Olaf's Neighbourhood Protocol (ONP) --- THIS IS PURPOSEFULLY VULNERABLE CODE, UNFINISHED CODE, RUN WITH CAUTION

Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935

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

Then run the program itself with: python run.py

Once finished, you can remove the dependencies by running: pip uninstall -r requirements.txt and then deleting the cloned folder.

## Program Functionality

Once python run.py has been executed, the messaging platform can be accessed using the URL 127.0.0.1:5000

Currently, the username entry prompt when visting the site is simply used for debugging purposes and is irrelevant to functionality.

Once the username has been entered, the rest of the site can be accessed. Currently there is very minimal functionality available. New instances of the client can be created by making a new tab with the same URL. When this is done, the number of online users dropdown selection will update to display the fingerprint of all other online users who can be messaged. The list can be updated by pressing the button next to the dropdown selector.

The messaging functionality doesn't interact with the website currently and there is no action executed when the Submit or Chat in Group buttons.

Files can be uploaded to the site by clicked the Upload File button, then clicking on the Browse button, selecting a valid file, and finally clicking the Upload button. On a successful upload, a message will be displayed with the URL of the uploaded file. This URL doesn't work and can't be used to download the file.

