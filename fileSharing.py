import requests
import os

def upload_file(server_url, file_path):
    """Uploads a file to the server."""

    max_file_size = 5 * 1024 * 1024  #  5 MB limit
    file_size = os.path.getsize(file_path)

    if file_size > max_file_size:
        print("Error: File size too large.")
        return None

    with open(file_path, 'rb') as file:
        response = requests.post(f"{server_url}/api/upload", files={'file': file})
    
    if response.status_code == 200:
        return response.json().get('file_url')
    elif response.status_code == 413:
        print("Error: File size too large.")
    else:
        print(f"Error: Unable to upload file. Status code: {response.status_code}")

def retrieve_file(file_url, download_path="downloaded_file"):
    """Retrieves a file from the server."""
    # Add error handling for the file retrieval process
    try:
        response = requests.get(file_url)
        response.raise_for_status()  # Raise an error for bad responses
        with open(download_path, 'wb') as file:
            file.write(response.content)
        print("File downloaded successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to retrieve file. {e}")