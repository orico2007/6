import os
import requests
from hashlib import sha256


path = "C:/Users/orico/Downloads"

key = input("Your API Key: ")

def HashFile(path):
    sha256_hash = sha256()
    with open(path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def VirusCheck(file):
    global key
    try:
        hashed = HashFile(file)
    except PermissionError: #print iif its
        
        return
    url = f"https://www.virustotal.com/api/v3/files/{hashed}"

    headers = {
        "accept": "application/json",
        "x-apikey": f"{key}"
    }

    response = requests.get(url, headers=headers)
    
    last_analysis_stats = response.text[response.text.find("last_analysis_stats")::] 
    last_analysis_stats = last_analysis_stats[0 : last_analysis_stats.find('}') + 1]
    
    last_analysis_stats = last_analysis_stats.split("\n")
    
    for word in last_analysis_stats[1:-1]:
        if "malicious" in word:
            count = int(word[word.find(':') + 2:-1])
            if count > 0:
                print(f"{file} contains {count} malicious files!")
                
    for word in last_analysis_stats[1:-1]:
        if "suspicious" in word:
            count = int(word[word.find(':') + 2:-1])
            if count > 0:
                print(f"{file} contains {count} suspicious files!")

    print(response.text)

def folder_search(path):

    for file in os.listdir(path):
        str = path + "/" + file
        if os.path.splitext(file)[1] == "":
            try:
                folder_search(str)
            except NotADirectoryError:
                VirusCheck(str)
        else:
            VirusCheck(str)
        
folder_search(path)


