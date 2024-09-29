from pwn import *
import os
from threading import Thread

class pwnio:
    def __init__(self, binary, use_remote: bool, use_debugger: bool, debugger="r2", remote_ip="", remote_port=-1, libc=None, ld=None):
        self.binary = binary
        self.use_remote = use_remote
        self.use_debugger = use_debugger
        self.debugger = debugger
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.libc = libc
        self.ld = ld
    
    def connect(self):
        if self.use_remote:
            if self.remote_ip == "" or self.remote_port == -1:
                print(f"Invalid remote IP or Port: {self.remote_ip}:{self.remote_port}")
                return None
            self.io = remote(self.remote_ip, self.remote_port)
        else:
            if self.libc != None and self.ld != None:
                self.io = process([self.ld.path, self.binary.path], env={"LD_PRELOAD": self.libc.path})
            else:
                self.io = process(self.binary.path)
        return self.io
    
    def debug(self, script=""):
        if self.use_debugger:
            if not self.use_remote: 
                if self.debugger == "r2":
                    attachr2(self.io, script)
                elif self.debugger == "gdb":
                    gdb.attach(self.io, script)
                input("Press Enter to continue...")
            else:
                print("Not attaching debugger on remote...")

# R2ATTACH
def attachr2(io, r2_script=None):
    r2 = r2Attach(io, terminal=["alacritty", "-e"])

    def dbg(r2, dbgscript=None):
        print("Attaching with script:", dbgscript)
        r2.attach(dbgscript)

    dbg_thread = Thread(target = dbg, args=[r2, r2_script])
    dbg_thread.start()

class r2Attach:
    def __init__ (self, process, terminal=None):
        if isinstance(process, pwnlib.tubes.process.process):
            self.pid = process.pid
            self.debuggee = process.program
        else:
            raise Exception ("Insert a correct pwntools process object")
        
        # Terminal preferences
        if terminal != None:
            self.terminal = terminal
        else:
            self.terminal = ["tmux", 'splitw', '-h']

        self.r2template ="""#!/usr/bin/env python
import os, r2pipe
r2 = r2pipe.open()

def load_modules():
    modules = r2.cmdj("dmmj")
    for module in modules:
        if '{mod_name:s}' == os.path.basename(module['file']):
            command = "oba {{addr:d}} {{file_name:s}}".format(file_name=module['file'], addr=module['address'])
            r2.cmd(command)

load_modules()
r2.cmd('ib') # Reload the buffer info

{user_commands:s}"""
    def attach(self, r2script=None):
        if r2script != None:
            script_file = os.path.join ("/tmp/", self.debuggee + ".py")
            with open(script_file,"w+") as f:
                f.write(self.r2template.format(mod_name=os.path.basename(self.debuggee), user_commands=r2script))
            command = self.terminal + ['r2', "-i", script_file, "-d", str(self.pid)]
        else:
            command = self.terminal + ['r2', '-d', str(self.pid)]
        
        subprocess.call (command)
        