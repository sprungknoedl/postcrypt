package main

import (
    "fmt"
    "os"
    "os/exec"

    "code.google.com/p/go.crypto/openpgp"
)

var cmdAddKey = &Command{
    Run: runAddKey,

    Name: "add-key",
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

    Name: "list-keys",
    Short: "prints all to postcrypt known public keys and identities",
    Long: `
Usage: postcrypt list-keys

Help:
Prints all to postcrypt known public keys and associated identities.

To add keys, see 'postcrypt help add-key'.
`,
}

func runAddKey(cmd *Command, args []string) {
    // get path to keyring from configruation
    path, err := Config.GetString("", "keyring")
    if err != nil {
        fmt.Printf("Error: Could not read configuration `keyring`. %s\n", err)
        return
    }

    if len(args) < 1 {
        fmt.Printf("Error: To few arguments. Run `go help %s`\n", cmd.Name)
        return
    }

    fmt.Printf("adding key %s ...\n", args[0])
    exe := exec.Command("gpg", "--keyring", path, "--no-default-keyring", "--recv-keys", args[0])
    err = exe.Run()
    if err != nil {
        fmt.Printf("Error: gpg returned: %s\n", err)
        return
    }
}

func runListKeys(cmd *Command, args []string) {
    // get path to keyring from configruation
    path, err := Config.GetString("", "keyring")
    if err != nil {
        fmt.Printf("Error: Could not read configuration `keyring`. %s\n", err)
        return
    }

    // open gpg keyring file
    keyringFile, err := os.Open(path)
    if err != nil {
        fmt.Printf("Error: %s\n", err)
        return
    }

    // read keyring
    keyring, err := openpgp.ReadKeyRing(keyringFile)
    if err != nil {
        fmt.Printf("Error: %s\n", err)
        return
    }
    defer keyringFile.Close()

    for _, entity := range keyring {
        keyid := fmt.Sprintf("%X", entity.PrimaryKey.KeyId)
        fmt.Printf("%s:\n", keyid[8:])
        for _, ident := range entity.Identities {
            fmt.Printf("\t%s\n", ident.Name)
        }
    }
}
