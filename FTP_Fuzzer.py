from pydbg import *   
from pydbg.defines import *
import os.path
import sys
import thread
import time
import socket
import os
import mechanize

class NetworkFuzzer(object):
    
    def __init__(self,path,target,port,process_type,init_count,time_sleep):
        self.path = os.path.normpath(path)      # Fuzz edilecek uygulamanın adresi
        self.target = target                    # Ip adresi
        self.port = port                        # Port
        self.count = int(init_count)            # Fuzzing işlemi için deneme başlangıç sayısı
        self.initial = int(init_count)
        self.process_type = process_type        # FTP, WEB_SERVER yazılacak,ileride yeni modüller eklendiğinde kullanılacak
        self.sleep = time_sleep                 # Fuzzing işlemi arasında beklenen süre. saniye olarak yazılacak
        self.sample = ["MKD","CWD"]
        self.selectedSample = 0
        
    def crash_log_handler(self,debugger):
        try:
            print   
            print "[*] Crash logs... \n" 
            print                          
            synopsis = debugger.dump_context(debugger.context,0, print_dots=False)                   
            print("\n" + synopsis)
	    debugger.terminate_process()
            return DBG_EXCEPTION_HANDLED
        except:
            print(sys.exc_info()[0])
                        
    def get_crash(self):                                                       # Fuzzing verilerinin gönderildiği bölüm
        if self.selectedSample < len(self.sample):
            self.count = self.initial
            print "\n-----------------------------\n   [+] Launching fuzzer for " + self.sample[self.selectedSample] + " ...\n"           
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                connect=s.connect((self.target, int(self.port)))
            except:
                print "   [!] Connection failed!"               
            if self.process_type == "FTP":
                try:       
                    s.recv(1024) 
                    s.send('USER anonymous\r\n') 
                    s.recv(1024)
                    s.send('PASS anonymous\r\n') 
                    s.recv(1024)
                    while(1):                    
                        print "   [+] Trying ...Count >>  " + str(self.count) + "..."     
                        time.sleep(self.sleep)
                        try:
                            val = "A" * self.count                          
                            strr = self.sample[self.selectedSample] + " "  + val + '\r\n'
                            self.count += 50
                            s.send(strr)
                            time.sleep(self.sleep)
                            s.recv(1024)                                  
                        except: # Program crash olduğunda tekrar çalıştırılır.
                            self.selectedSample += 1
                            if self.selectedSample < len(self.sample):
                                thread.start_new_thread(self.start_thread,())
                                self.get_crash()
                                break
                            else:
                                print "[*] Fuzzing completed successfully... \n"
                                thread.exit_thread()
                                sys.exit(0)                              
                except:
                    pass
            else:
                print "Incorrect parameter! ex: FTP"
                return
        else:
            sys.exit(0)
           
    def start_thread(self):    # Debugger  thread içerisinde çalıştırmak lazım. yoksa process kilitleniyor.
        dbg = pydbg()        
        dbg.load(self.path)
        dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.crash_log_handler)        
        dbg.debug_event_loop()
        
    def start(self):
        print("[**] Fuzzing has been started successfully. Please, wait during fuzzing ...")
        thread.start_new_thread(self.start_thread,())
        self.get_crash()
        

    
