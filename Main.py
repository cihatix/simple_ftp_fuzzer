from FTP_Fuzzer import *

fuzz = NetworkFuzzer("FTPServer.exe","127.0.0.1",21,"FTP",1,0.5)
fuzz.start()

while True:
    pass
