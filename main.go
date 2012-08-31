package main

import (
	"flag"
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

const KeyringPath = "keyring.gpg"

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		return
	}

	for _, cmd := range commands {
		if cmd.Name == args[0] && cmd.Run != nil {
			args = args[1:]
			cmd.Run(cmd, args)
			return
		}
	}
}
