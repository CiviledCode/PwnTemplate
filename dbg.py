from pwn import *
import os
from threading import Thread

class pwnio:
    def __init__(self, binary, use_remote: bool, use_debugger: bool, debugger="r2", remote_ip="", remote_port=-1, libc=None, ld=None, terminal=["alacritty", "-e"]):
        self.binary = binary
        self.use_remote = use_remote
        self.use_debugger = use_debugger
        self.debugger = debugger
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.libc = libc
        self.ld = ld
        self.terminal = terminal
    
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
    
    def debug(self, r2_script=None, gdb_script=None):
        if self.use_debugger:
            if not self.use_remote: 
                if self.debugger == "r2":
                    r2 = r2Attach(self.io, self)

                    def dbg(r2, dbgscript=None):
                        r2.attach(dbgscript)

                    dbg_thread = Thread(target = dbg, args=[r2, r2_script])
                    dbg_thread.start()
                elif self.debugger == "gdb":
                    gdb.attach(self.io, gdb_script)
                input("Press Enter to continue...")
            else:
                print("Not attaching debugger on remote...")

class r2Attach:
    def __init__ (self, process, ctx):
        if isinstance(process, pwnlib.tubes.process.process):
            self.pid = process.pid
            self.target = process.program
        else:
            raise Exception ("Insert a correct pwntools process object")
        
        self.ctx = ctx
            
    def attach(self, r2script=None):
        script_template = """#!/usr/bin/env python
import os, r2pipe
r2 = r2pipe.open()
"""
        if r2script != None:
            x = r2script.split("\n")
            for y in x:
                if y == "":
                    continue
                script_template += f"print(r2.cmd('{y}'), end='')\n"
            
            script_template += "r2.quit()\n"
            with open('/tmp/pwn.py', 'w') as file:
                file.write(script_template)
            command = self.ctx.terminal + ['r2', '-i', '/tmp/pwn.py', '-d', str(self.pid)]
        else:
            command = self.ctx.terminal + ['r2', '-d', str(self.pid)]
        subprocess.call(command)
        