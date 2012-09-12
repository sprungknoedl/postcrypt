package main

import (
	"fmt"
	"os"
	"os/exec"

	"code.google.com/p/go.crypto/openpgp"
)

var cmdAddKey = &Command{
	Run: runAddKey,

	Name:  "add-key",
	Short: "adds a key to postcrypt's gpg keyring",
	Long: `
Usage: postcrypt add-key <keyid>

Help:
Adds a key to postcrypt's keyring. The keyid can be specified by any format
the gpg binary knows to add keys.

This command is just a shortcut to:
    
    gpg --no-default-keyring --keyring $options[keyring] --recv-keys <keyid>

The location of the keyring file can be changed via the configuration
option "keyring".

To print all keys postcrypt knows, see 'postcrypt help list-keys'.
`,
}

var cmdListKeys = &Command{
	Run: runListKeys,

	Name:  "list-keys",
	Short: "prints all to postcrypt known public keys and identities",
	Long: `
Usage: postcrypt list-keys

Help:
Prints all to postcrypt known public keys and associated identities.

To add keys, see 'postcrypt help add-key'.
`,
}

func runAddKey(cmd *Command, args []string) {
	var err error

	log := NewTee("postcrypt")
	path, _ := cmd.Config.GetString("", "keyring")

	if len(args) < 1 {
		log.Err("too few arguments. run `go help " + cmd.Name + "`.")
		return
	}

	log.Info("Adding key " + args[0])

	exe := exec.Command("gpg", "--keyring", path, "--no-default-keyring", "--recv-keys", args[0])
	err = exe.Run()
	if err != nil {
		log.Err("gpg returned: " + err.Error())
		return
	}
}

func runListKeys(cmd *Command, args []string) {
	var err error

	log := NewTee("postcrypt")
	path, _ := cmd.Config.GetString("", "keyring")

	// open gpg keyring file
	fh, _ := os.Open(path)
	if err != nil {
		log.Crit("could not open keyring: " + err.Error())
		return
	}

	// read keyring
	keyring, err := openpgp.ReadKeyRing(fh)
	if err != nil {
		log.Crit("could not read keyring: " + err.Error())
		return
	}

	for _, entity := range keyring {
		fmt.Printf("%s:\n", getKeyId(entity))
		for _, ident := range entity.Identities {
			fmt.Printf("\t%s\n", ident.Name)
		}
	}
}
