import os
import requests
from hashlib import sha256
from tkinter import *

win = Tk()
win.geometry("850x850")
win.title("Anti Virus")
win.config(background='#0c1345')
win.iconphoto(True,PhotoImage(file='Anti_Virus/Icon.png'))
title = Label(win, text = 'Anti Virus By Ori Cohen', font = ('Arial',25), bg = '#0c1345',fg = 'white')
title.pack()

text = Label(win,text='API Key Here: ',font=('Arial',20), bg = '#0c1345',fg = 'white')
text.place(x=50,y=100)

input = Entry(win,font=('Arial',15),width=int(850 * 0.6 / 10))
input.place(x=50,y=150)

AIP = Button(win,text='Set AIP',font=('Arial',15),bg='#161625',fg = 'white')
AIP.place(x=650,y=155)

scan = Button(win,text='scan',font=('Arial',15),bg='#161625',fg = 'white')
scan.place(x=375,y=200)



def main():
    global path 
    path = "C:/Users/orico/Downloads/Hxd"
    global key
    key = input("Your API Key: ")
    global scanned
    scanned = 0

    def culc(path):
        count = 0
        for file in os.listdir(path):
            str = path + "/" + file
            if os.path.splitext(file)[1] == "":
                try:
                    count += culc(str)
                except NotADirectoryError:
                    count += 1
            else:
                count += 1
        return count
                
    totalFiles = culc(path)
        
    def HashFile(path):
        sha256_hash = sha256()
        with open(path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def VirusCheck(file):
        global scanned
        global key
        global path
        lastPrecent = 0
        scanned += 1
        try:
            hashed = HashFile(file)
        except PermissionError:
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
                    print(f"{file} Contains {count} Malicious Files!")
                    
        for word in last_analysis_stats[1:-1]:
            if "suspicious" in word:
                count = int(word[word.find(':') + 2:-1])
                if count > 0:
                    print(f"{file} Contains {count} Suspicious Files!")
                    
        lastPrecent = precent
        precent = round(scanned / totalFiles * 100)
        if(precent != lastPrecent):
            print(f"{precent} % Done!")
            
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

win.mainloop()
main()
