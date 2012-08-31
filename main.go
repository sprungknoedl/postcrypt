package main

import (
    "flag"
    "log/syslog"
)

type Command struct {
    Name string
    Run  func(cmd *Command, args []string)
}

var commands = []*Command{
    cmdEncrypt,
    cmdAddKey,
    cmdListKeys,
}

const SyslogLevel = syslog.LOG_INFO
const KeyringPath = "/var/lib/postcrypt/keyring.gpg"

func main() {
    flag.Parse()
    args := flag.Args()

    if len(args) < 1 {
        return
    }

    logger, _ := syslog.New(SyslogLevel, "postcrypt")
    for _, cmd := range commands {
        if cmd.Name == args[0] && cmd.Run != nil {
            args = args[1:]
            logger.Debug("Starting ...")
            cmd.Run(cmd, args)
            logger.Debug("Stopping ...")
            return
        }
    }
}
