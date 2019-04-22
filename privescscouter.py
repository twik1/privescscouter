#!/usr/bin/env python3
import sys
import argparse
import subprocess as sub

# ToDo print/save all history files found
# Add an object with info accessible to other commands

# ToDo dump memory on kernel <3.0

result = []

sysInfo = {"Operating System": {"cmd": "cat /etc/issue", "result": result},
           "Hostname": {"cmd": "hostname", "result": result},
           "Kernel ring buffer": {"cmd": "dmesg", "result": result},
           "Kernel loaded modules": {"cmd": "lsmod", "result": result},
           "System up-time": {"cmd": "uptime", "result":result}
           }

driveInfo = {"Mount results": {"cmd": "mount", "result": result},
             "Fstab entries": {"cmd": "cat /etc/fstab 2>/dev/null", "result": result},
             "List block devices": {"cmd":"lsblk","result": result}
             }

userInfo = {"Current User": {"cmd": "whoami", "result": result},
            "Current User ID": {"cmd": "id", "result": result},
            "All users": {"cmd": "cat /etc/passwd", "result": result},
            "Super Users Found:": {"cmd": "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'",
                                   "result": result},
            "Root and current user history (depends on privs)": {
                "cmd": "ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null",
                "result": result},
            "Environment": {"cmd": "env 2>/dev/null | grep -v 'LS_COLORS'", "result": result},
            "Sudoers (privileged)": {"cmd": "cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "result": result},
            "Logged in User Activity": {"cmd": "w 2>/dev/null", "result": result},
            }

netInfo = {"Network interfaces": {"cmd": "ip addr", "result": result},
           "Routing": {"cmd": "ip route", "result": result}
           }

# Use SUID and SGID to find flaws to gain root

fdPerms = {"World Writeable Directories for User/Group 'Root'": {
    "cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root",
    "result": result},
    "World Writeable Directories for Users other than Root": {
        "cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root",
        "result": result},
    "World Writable Files": {
        "cmd": "find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null",
        "result": result},
    "SUID/SGID Files and Directories": {"cmd": "find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null",
                                        "result": result},
    "Checking if root's home folder is accessible": {"cmd": "ls -ahlR /root 2>/dev/null", "result": result}
}

pwdFiles = {"Logs containing keyword 'password'": {
    "cmd": "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null",
    "result": result},
    "Config files containing keyword 'password'": {
        "cmd": "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null",
        "result": result},
    "Shadow File (Privileged)": {"cmd": "cat /etc/shadow 2>/dev/null", "result": result}
}

getAppProc = {"Current processes": {"cmd": "ps aux | awk '{print $1,$2,$9,$10,$11}'", "result": result},
              }

devTools = {
    "Installed Tools": {"cmd": "which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null",
                        "result": result}}

escapeCmd = {"vi": [":!bash", ":set shell=/bin/bash:shell"], "awk": ["awk 'BEGIN {system(\"/bin/bash\")}'"],
             "perl": ["perl -e 'exec \"/bin/bash\";'"],
             "find": ["find / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;"], "nmap": ["--interactive"]}

cmdList = [sysInfo, driveInfo, userInfo, fdPerms, pwdFiles, devTools, netInfo]


class Output:
    def __init__(self, lflags, filename):
        self.flags = lflags
        if 'log' in self.flags:
            try:
                self.file = open(filename, "w")
            except IOError:
                print('Unable to open log file: {}'.format(args.log))
                sys.exit(1)
        else:
            self.file = False

    def out(self, buffer):
        if 'print' in self.flags:
            print(buffer)
        if self.file:
            try:
                self.file.write(buffer + '\n')
            except IOError:
                print('Unable to log to file: {}'.format(args.log))


class CmdInstance:
    def __init__(self, cmdDict, loutput):
        self.cmdDict = cmdDict
        self.output = loutput
        self.done = False

    def query_yes_no(self, question, default="yes"):
        valid = {"yes": True, "y": True, "ye": True,
                 "no": False, "n": False}
        if default is None:
            prompt = " [y/n] "
        elif default == "yes":
            prompt = " [Y/n] "
        elif default == "no":
            prompt = " [y/N] "
        else:
            raise ValueError("invalid default answer: '%s'" % default)

        while True:
            sys.stdout.write(question + prompt)
            choice = input().lower()
            if default is not None and choice == '':
                return valid[default]
            elif choice in valid:
                return valid[choice]
            else:
                sys.stdout.write("Please respond with 'yes' or 'no' "
                                 "(or 'y' or 'n').\n")

    def outcmd(self, cmdpart, header, log=False):
        self.output.out('*** {}'.format(header))
        self.output.out('Command: {}'.format(cmdpart['cmd']))

    def outnotrun(self):
        self.output.out('Choosed not to run the command\n')
        self.output.out('-------------------------------------------------------------\n')

    def outres(self, cmdpart):
        for line in range(len(cmdpart['result'])):
            self.output.out('{}'.format(cmdpart['result'][line].decode('utf-8')))
        self.output.out('-------------------------------------------------------------\n')

    def runcmd(self, cmdpart):
        out, error = sub.Popen([cmdpart['cmd']], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
        cmdpart['result'] = out.split(b'\n')

    def getcmd(self):
        instlist = []
        for header, cmdpart in self.cmdDict.items():
            instlist.append(cmdpart["cmd"].split(" ")[0])
        # print(instlist)

    def run(self, flags, file):
        for header, cmdpart in self.cmdDict.items():
            self.outcmd(cmdpart, header)

            run = True
            if 'confirm' in flags:
                run = self.query_yes_no('Would you like to run this command?')
            if run:
                self.runcmd(cmdpart)
                self.done = True
            else:
                self.outnotrun()
                continue

            self.outres(cmdpart)


class Alias(CmdInstance):
    def __init__(self, loutput):
        cmdDict = {"Alias listing": {"cmd": "bash -i -c 'source $HOME/.bashrc;alias'", "result": result}}
        CmdInstance.__init__(self, cmdDict, loutput)

    def check(self, cmd):
        for header, cmdpart in self.cmdDict.items():
            for line in range(len(cmdpart['result'])):
                if len(cmdpart['result'][line].decode('utf-8')) > 5:
                    if cmd == cmdpart['result'][line].decode('utf-8').split("=")[0].split(" ")[1]:
                        return True
        return False


class Dist(CmdInstance):
    def __init__(self, loutput):
        cmdDict = {"Kernel": {"cmd": "cat /proc/version", "result": result}}
        CmdInstance.__init__(self, cmdDict, loutput)

    def debian(self):
        for header, cmdpart in self.cmdDict.items():
            for line in range(len(cmdpart['result'])):
                if 'ubuntu' in cmdpart['result'][line].decode('utf-8') or 'debian' in cmdpart['result'][line].decode(
                        'utf-8'):
                    return True
        return False

    def packagescmd(self):
        if self.debian():
            getPkgs = "dpkg -l | grep ^ii | awk '{print $0}'"
        else:
            getPkgs = "rpm -qa | sort -u"
        return {"Installed Packages": {"cmd": getPkgs, "result": result}}


class History(CmdInstance):
    def __init__(self, loutput):
        cmdDict = {"Root and current user history (depends on privs)": {
            "cmd": "ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null",
            "result": result}}
        CmdInstance.__init__(self, cmdDict, loutput)

    def historycmd(self):
        cmdadd = {}
        count = 0
        global result
        for header, cmdpart in self.cmdDict.items():
            for line in range(len(cmdpart['result'])):
                cmdtiny = {}
                historyline = cmdpart['result'][line].decode('utf-8').split(' ')
                if (len(historyline) > 1):
                    cmdtiny["cmd"] = "cat {}".format(historyline[-1])
                    cmdtiny["result"] = result
                    cmdadd["print history {}".format(count)] = cmdtiny
                    count+=1
        return(cmdadd)



if __name__ == '__main__':
    privesc_parameter = {}
    parser = argparse.ArgumentParser(description='Linux Privilege Escalation Scouter v0.1')
    parser.add_argument('-p', '--print', help='Print command and output on std out', action="store_true",
                        required=False)
    parser.add_argument('-c', '--confirm', help='Confirm every command', action="store_true",
                        required=False)
    parser.add_argument('-l', '--log', help='Log output to file', required=False)
    args = parser.parse_args()

    flags = {}
    if args.print:
        flags['print'] = True
    if args.confirm:
        flags['confirm'] = True
    if args.log:
        flags['log'] = True

    file = False
    output = Output(flags, args.log)

    output.out('\nLinux Privilege Escalation Scouter v.0.1')
    output.out('------------------------------------------\n\n')

    # Get all aliases so that no command is changed
    # Maybe not needed since alias is not available default
    alias = Alias(output)
    alias.run(flags, file)

    # Check which dist branch it is to choose package utility
    dist = Dist(output)
    dist.run(flags, file)
    if dist.done:
        cmdList.append(dist.packagescmd())

    history = History(output)
    history.run(flags, file)
    if history.done:
        cmdList.append(history.historycmd())

    # Loop through commands and print/log
    cmdObjects = []
    for i in range(len(cmdList)):
        cmdObjects.append(CmdInstance(cmdList[i], output))
        if alias.check(cmdObjects[i].getcmd()):
            output.out('Command -{}- has an alias defined ignoring'.format(cmdObjects[i].getcmd()))
            output.out('-------------------------------------------------------------\n')
        else:
            cmdObjects[i].run(flags, file)
