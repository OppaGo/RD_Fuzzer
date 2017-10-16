from subprocess import call
import os

def SetCommandLine(Fuzzer, DeviceName, Ioctl_Code):
        Command = [Fuzzer, '-n', DeviceName, '-c']
        for ioctl in Ioctl_Code:
                Command.append(hex(ioctl))

def Dumpdir(path):
        if not os.path.isdir(path):
                os.mkdir(path)

def windbglog(path):
        kd_log = open(path + "/windbg.log", "wb")
        call(["C:\\Program Files\\Debugging Tools for Windows (x64)\\kd.exe", "-z", path, "-c", "$$<crash_processing\\kd_batch_commands.txt;Q"], stdout=kd_log)
        kd_log.close()

def ExecuteCommand(Command):
        try:
                call(Command)
        except:
                pass

def Cleanup():
        call(['taskkill', '/f', '/im', 'notepad.exe'])
        call(['del', '*.log'], shell=True)
        call(['shutdown', '-r'])

def main():
        global Fuzzer
        global DeviceName
        global Ioctl_Code
        global Path

        Command = SetCommandLine(Fuzzer, DeviceName, Ioctl_Code)
        Dumpdir(Path)
        windbglog(Path)
        ExecuteCommand(Command)
        Cleanup()

if __name__ == "__main__":
        Fuzzer='RD_Driver_Fuzzer.exe'
        DeviceName = 'MonitorFunction0'
        Ioctl_Code = [0x222000, 0x222004, 0x222008, 0x22200C, 0x222010, 0x222014]
        Path = ".\\CrashDump"

        main()