import os
import requests
from hashlib import sha256
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from PIL import ImageTk, Image
from tkinter import ttk
import ttkbootstrap as tb
from ttkbootstrap.scrolled import ScrolledFrame

#Window Setup
win = tk.Tk()
width= win.winfo_screenwidth()
height= win.winfo_screenheight()
win.geometry("%dx%d" % (width, height))
win.state('zoomed')
win.title("Anti Virus")
icon = PhotoImage(file='Anti_Virus/Icon.png')
win.iconphoto(True, icon)
win.config(bg='#e9bf73')
style = tb.Style(theme="solar")

#Title
label = Label(win, text="Anti Virus By Ori Cohen", font=('Arial', 35), fg='White')
label.pack(pady=20)

scanText = "Scans..."

def Load():
    def apiCheck():
        url = "https://www.virustotal.com/api/v3/files/59fce88da57e076536ccece2cd0b005991450b472d5de6de4f554d3ea1452ed5"
        headers = {"accept": "application/json","x-apikey": f"{key}"}
        response = requests.get(url, headers=headers)
        message = response.text[response.text.find("message")::]
        message = message[0: message.find("\n")]
        if "Wrong API key" in message:
            keyClear()
            keyEntry.insert(0,"Error: API key is not Valid")
            return 1
        return 0
    def pathCheck():
        if (not os.path.isdir(pathEntry.get())):
            pathClear()
            pathEntry.insert(0,"Error: Invalid path")
            return 1
        pathEntry.config(state=DISABLED)
        return 0

    def keySet():
        global key
        key = keyEntry.get()
        keyEntry.config(state=DISABLED)  
         
    def keyClear():
        global key
        key = ""
        keyEntry.config(state=NORMAL)
        keyEntry.delete(0,END)
        
    def pathClear():
        pathEntry.config(state=NORMAL)
        pathEntry.delete(0,END)
        
    def browseFile():
        pathEntry.config(state=NORMAL)
        filename = filedialog.askdirectory()
        pathEntry.delete(0,END)
        pathEntry.insert(0, filename)

    def validateUser():
        keySet()
        Error_counter = 0

        Error_counter += apiCheck()
        Error_counter += pathCheck()
        if (len(keyEntry.get()) == 0):
            Error_counter += 1

        if Error_counter == 0:
            Scan(pathEntry.get())
     
    topFrame = Frame(win, width=width, height=450)
    topFrame.pack()

    spaceFrame = Label(topFrame, text="",width=50)
    spaceFrame.pack(side=LEFT)
    
    frameLeft = Frame(topFrame, width=900, height=450)
    frameLeft.pack(side=LEFT, anchor=NW)
    frameLeftUp = Frame(frameLeft, width=900, height=200)
    frameLeftUp.pack(anchor=W)
    frameLeftCenter = Frame(frameLeft, width=900, height=200)
    frameLeftCenter.pack(anchor=W)
    frameLeftDown = Frame(frameLeft, width=900, height=50)
    frameLeftDown.pack(anchor=W)
    
    pathMargin = Label(frameLeftUp, text="", height=1)
    pathMargin.pack()

    pathLabel = Label(frameLeftUp, text="Path for scan", font=('Arial', 20), fg='White')
    pathLabel.pack(side=TOP, anchor=NW)

    pathEntry = Entry(frameLeftUp, font=("Arial", 23),width= 40)
    pathEntry.pack(side=LEFT)

    pathBottonMargin = Label(frameLeftUp, text="", width=1)
    pathBottonMargin.pack(side=LEFT)

    pathBrowse = Button(frameLeftUp,text="Browse", font=("Arial", 15),width= 7,height=1,command=browseFile)
    pathBrowse.pack(side=LEFT)

    keysMargin = Label(frameLeftUp, text="", width=1)
    keysMargin.pack(side=LEFT)

    clearPathButton = Button(frameLeftUp, text="Clear", font=("Arial", 15), width= 7,height=1 ,command=pathClear)
    clearPathButton.pack(side=LEFT)
    
    marg_down = Label(frameLeftCenter, text="",height=5)
    marg_down.pack()
    keyLabel = Label(frameLeftCenter, text="API Key here", font=('Arial', 20), fg='White')
    keyLabel.pack(side=TOP, anchor=NW)
    keyEntry = Entry(frameLeftCenter, font=("Arial", 23),width= 40)
    keyEntry.pack(side=LEFT)
    keyMargin = Label(frameLeftCenter, text="", width=1)
    keyMargin.pack(side=LEFT)

    keyButton = Button(frameLeftCenter, text="Set Key", font=("Arial", 15), width= 7,height=1 ,command=keySet)
    keyButton.pack(side=LEFT)
    keysMargin1 = Label(frameLeftCenter, text="", width=1)
    keysMargin1.pack(side=LEFT)

    clearKeyButton = Button(frameLeftCenter, text="Clear", font=("Arial", 15), width= 7,height=1 ,command=keyClear)
    clearKeyButton.pack(side=LEFT)
   


    imgFrame = Frame(topFrame, width=650, height=450,bg='red')
    imgFrame.pack(side=LEFT, anchor=NW)

    global big_image
    big_image = PhotoImage(file = "Anti_Virus/Icon.png")
    canvas = Canvas(imgFrame,width = 400, height = 350)
    canvas.create_image(200, 200, image = big_image)
    canvas.pack(side=RIGHT, anchor=N)

    scan_marg_top = Label(frameLeftDown, text="", height=2)
    scan_marg_top.pack()

    scanMarginLeft = Label(frameLeftDown, text="", width=59)
    scanMarginLeft.pack(side=LEFT)

    scanButton = Button(frameLeftDown, text="Scan", font=("Arial", 23) ,command=validateUser)
    scanButton.pack()

    
    frameDown = Frame(win, width=width, height=500)
    frameDown.pack()
    
    global proggressbarLabel
    global scanText
    proggressbarLabel = Label(frameDown, text=scanText, font=("ariel", 40), fg='white')
    proggressbarLabel.pack_forget()

    global proggressbar
    proggressbar = ttk.Progressbar(frameDown, orient='horizontal',mode='determinate',length=500)
    proggressbar.pack_forget()

    #margin
    proggressbarMargin = Label(frameDown, text="", height=4)
    proggressbarMargin.pack()
    
    # display viruses
    global scrollbarLabel
    scrollbarLabel = ScrolledFrame(frameDown, autohide=False, width=1000, height=350)
    scrollbarLabel.pack_forget()



Load()


def Scan(path):
    global scanText
    def frameClear(frame: Frame):
        for widget in frame.winfo_children():
            widget.destroy()
    def deleteFile(path, frame: Frame):
        os.remove(path)
        frame.destroy()
        print("deleting: " + path)


    global scannedFiles
    scannedFiles = 0


    def displayVirus(data):
        fileName = data[0][::-1]
        fileName = fileName[0: fileName.find('/')][::-1]
        virusFrame = Frame(scrollbarLabel, width=800, height=200, bg='red')
        virusFrame.pack()
        virus_name = Label(virusFrame, text=fileName, font=("Arial", 15), height=3)
        virus_name.pack(side=LEFT)
        #margin
        virusMargin = Label(virusFrame, text="", width=5)
        virusMargin.pack(side=LEFT)

        returnedData = Label(virusFrame, text=f"Malicious: {data[1][0]}", font=("Arial", 15))
        returnedData.pack(side=LEFT)
        
        buttonMargin = Label(virusFrame, text="", width=5)
        buttonMargin.pack(side=LEFT)
        
        deleteVirus = Button(virusFrame, text="Delete", font=("Arial", 23) ,command=lambda: deleteFile(data[0], virusFrame))
        deleteVirus.pack(side=LEFT)
        win.update()

    def hash(path):
        sha256_hash = sha256()
        with open(path,"rb") as f:
            for byte in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte)
        return sha256_hash.hexdigest()
    def fileCount(path):
        files = 0
        for file in os.listdir(path):
            try:
                if (os.path.splitext(file)[1] == ""):
                    files += fileCount(path + "/" + file)
                else:
                    files += 1
            except NotADirectoryError:
                files += 1
        return files
    def openFolder(path):
        for file in os.listdir(path):
            try:
                if (os.path.splitext(file)[1] == ""):
                    openFolder(path + "/" + file)
                else:
                    virusDetector(path + "/" + file)
            except NotADirectoryError:
                virusDetector(path + "/" + file)
    def responseAnalysition(resp, path):
        if (resp.text.find("error")):
            analysis = resp.text[resp.text.find("error"): resp.text.find("message")]
            analysis = analysis[int(analysis.find("code")): int(analysis.find(","))]
            analysis = analysis[analysis.find(':') + 3 : -1]
            if (analysis == "QuotaExceededError"):
                raise BaseException("QuotaExceededError")
        analysis = resp.text[resp.text.find("last_analysis_stats")::]
        analysis = analysis[0:analysis.find("}") + 1]

        malicious = analysis[analysis.find("malicious")::]#find the amount
        malicious = malicious[malicious.find(":") + 1: malicious.find(",")]

        suspicious = analysis[analysis.find("suspicious")::] # find the amount
        suspicious = suspicious[suspicious.find(":") + 1: suspicious.find(",")]

        try:
            malicious = int(malicious)
            suspicious = int(suspicious)
        except ValueError:
            return

        if malicious > 0 or suspicious > 0:
            displayVirus((path, [malicious, suspicious]))

        
    def virusDetector(path):
        global scannedFiles
        scannedFiles += 1
        try:
            hashed_file = hash(path)
        except PermissionError:
            return
        url = f"https://www.virustotal.com/api/v3/files/{hashed_file}" 
        global key
        headers = {
            "accept": "application/json",
            "x-apikey": f"{key}"
        }
        response = requests.get(url, headers=headers)
        try:
            responseAnalysition(response, path)
        except BaseException:
            raise BaseException("QuotaExceededError")

        proggressbar["value"] = scannedFiles / numberOfFiles * 100
        win.update()

    
    pathToScan = f"{path}"
    numberOfFiles = fileCount(pathToScan)
    
    global viruses
    viruses = {}

    frameClear(scrollbarLabel)

    proggressbarLabel.pack()
    proggressbar.pack()
    proggressbar['value'] = 0
    
    scrollbarLabel.pack(pady=15, padx=15, fill=BOTH, expand=YES)

    try:
        openFolder(pathToScan)
    except BaseException:
        scanText = "You Run Out Of The 500 Scans Per Day Limit!"
        win.update()
    else:
        scanText = "Done Scanning!"
        win.update()


win.mainloop()