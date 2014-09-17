from FTP_Fuzzer import *

fuzz = NetworkFuzzer("C:\Documents and Settings\Administrator\Desktop\FTPServer.exe","192.168.96.128",21,"FTP",1,0.5)
fuzz.start()

while True:
    pass
