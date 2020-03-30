# Event log to remote syslog realtime sensor

This service subscribes to all event log events and streams them live to a syslog server via UDP.

Installation: evtsyslog.exe install

(will copy the exe file to %APPDATA%\\Local\\Programs and install the service)

Settings: *HKLM\\Software\\Evtsyslog*

    ------ ------------ -----------------------------
    REG_SZ *SyslogHost* remote hostname or IP address

    REG_SZ *SyslogPort* remote UDP port number
    ------ ------------ -----------------------------

