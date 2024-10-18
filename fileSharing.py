# Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935
import requests
import os

def upload_file(server_url, file_path):
    """Uploads a file to the server."""
    print(file_path)
    print(server_url)
    # chcks if server_url is valid
    if not server_url.startswith('http://') and not server_url.startswith('https://'):
        print("Error: Invalid server URL.")
        return None

    # checks if file_path is valid
    if not os.path.exists(file_path):
        print("Error: File path is invalid.")
        return None

    max_file_size = 5 * 1024 * 1024  #  5 MB limit
    file_size = os.path.getsize(file_path)

    if file_size > max_file_size:
        print("Error: File size too large.")
        return None
    
    file_url = f"{server_url}/{os.path.basename(file_path)}"
    print(file_url)

    return {
        "body": {
            "file_url": file_url
        }
    }

def retrieve_file(file_url, download_path="downloaded_file"):
    """Retrieves a file from the server."""
    # Add error handling for the file retrieval process
    try:
        # checks if file_url is valid
        if not file_url.startswith('http://') and not file_url.startswith('https://'):
            print("Error: Invalid file URL.")
            return None

        response = requests.get(file_url)
        response.raise_for_status()  # Raise an error for bad responses
        with open(download_path, 'wb') as file:
            file.write(response.content)
        print("File downloaded successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to retrieve file. {e}")