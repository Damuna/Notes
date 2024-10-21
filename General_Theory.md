# Linux

## Fundamentals

Everything is in a file

### File system hierarchy

| Location |                                                              |
| -------- | ------------------------------------------------------------ |
| `/`      | The top-level directory is the root filesystem and contains all of the files required to boot the operating system before other filesystems are mounted, as well as the files required to boot the other filesystems. After boot, all of the other filesystems are mounted at standard mount points as subdirectories of the root. |
| `/bin`   | Contains essential command binaries.                         |
| `/boot`  | Consists of the static bootloader, kernel executable, and files required to boot the Linux OS. |
| `/dev`   | Contains device files to facilitate access to every hardware device attached to the system. |
| `/etc`   | Local system configuration files. Configuration files for installed applications may be saved here as well. |
| `/home`  | Each user on the system has a subdirectory here for storage. |
| `/lib`   | Shared library files that are required for system boot.      |
| `/media` | External removable media devices such as USB drives are mounted here. |
| `/mnt`   | Temporary mount point for regular filesystems.               |
| `/opt`   | Optional files such as third-party tools can be saved here.  |
| `/root`  | The home directory for the root user.                        |
| `/sbin`  | This directory contains executables used for system administration (binary system files). |
| `/tmp`   | The operating system and many programs use this directory to store temporary files. This directory is generally cleared upon system boot and may be deleted at other times without any warning. |
| `/usr`   | Contains executables, libraries, man files, etc.             |
| `/var`   | This directory contains variable data files such as log files, email in-boxes, web application related files, cron files, and more. |

 ### The Shell

#### Prompt description

```text-plain
<username>@<hostname><current working directory>$
```

The dollar sign, in this case, stands for a user. As soon as we log in as `root`, the character changes to a `hash` <`#`>

when we upload and run a shell on the target system, we may not see the username, hostname, and current working directory. This may be due to the PS1 (prompt string 1) variable in the environment not being set correctly.

The prompt can be customized using special characters and variables in the shell’s configuration file (`.bashrc` for the Bash shell).

| **Special Character** | **Description**                            |
| --------------------- | ------------------------------------------ |
| `\d`                  | Date (Mon Feb 6)                           |
| `\D{%Y-%m-%d}`        | Date (YYYY-MM-DD)                          |
| `\H`                  | Full hostname                              |
| `\j`                  | Number of jobs managed by the shell        |
| `\n`                  | Newline                                    |
| `\r`                  | Carriage return                            |
| `\s`                  | Name of the shell                          |
| `\t`                  | Current time 24-hour (HH:MM:SS)            |
| `\T`                  | Current time 12-hour (HH:MM:SS)            |
| `\@`                  | Current time                               |
| `\u`                  | Current username                           |
| `\w`                  | Full path of the current working directory |

 

#### Getting help

Use `man` to access the manual

```text-plain
Damuna-1@htb[/htb]$ man <tool>
```

Also `--help` or `-h` are similar

```text-plain
Damuna-1@htb[/htb]$ <tool> --help
```

A nice beginner tool is `apropos` which gives a short description of the function of the tool

```text-plain
Damuna-1@htb[/htb]$ apropos <keyword>
```

 

#### System Information commands

| **Command** | **Description**                                              |
| ----------- | ------------------------------------------------------------ |
| `whoami`    | Displays current username.                                   |
| `id`        | Returns users identity, to see what access a user has.the `adm` group means that the user can read log files in `/var/log` , `sudo` group can run some or all commands as the `root` user. |
| `hostname`  | Prints the name of current host system (name of the computer) |
| `uname`     | Prints basic information about the operating system name and system hardware.With the kernel release you can search for potential kernel exploits quickly |
| `pwd`       | Returns working directory name.                              |
| `ifconfig`  | The ifconfig utility is used to assign or to view an address to a network interface and/or configure network interface parameters. |
| `ip`        | Ip is a utility to show or manipulate routing, network devices, interfaces and tunnels. |
| `netstat`   | Shows network status.                                        |
| `ss`        | Another utility to investigate sockets.                      |
| `ps`        | Shows process status.                                        |
| `who`       | Displays who is logged in.                                   |
| `env`       | Prints environment or sets and executes command.             |
| `lsblk`     | Lists block devices.                                         |
| `lsusb`     | Lists USB devices                                            |
| `lsof`      | Lists opened files.                                          |
| `lspci`     | Lists PCI devices.                                           |



### File Descriptors

When you open a file, the operating system creates an entry to represent  that file and store the information about that opened file. The entries of the file are file descriptors, uniquely representing an opened file.

We know most famous file descriptors are 0, 1 and 2.  0 corresponds to `STDIN`, 1 to `STDOUT`, and 2 to `STDERR`.