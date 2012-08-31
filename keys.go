package main

import (
    "fmt"
    "os"
    "os/exec"

    "code.google.com/p/go.crypto/openpgp"
)

var cmdAddKey = &Command{
    Name: "add-key",
    Run: runAddKey,
}

var cmdListKeys = &Command{
    Name: "list-keys",
    Run: runListKeys,
}

func runAddKey(cmd *Command, args []string) {
    if len(args) < 1 {
        return
    }

    fmt.Printf("adding key %s ...\n", args[0])
    exe := exec.Command("gpg", "--keyring", KeyringPath, "--no-default-keyring", "--recv-keys", args[0])
    err := exe.Run()
    if err != nil {
        fmt.Printf("error: gpg returned: %s\n", err)
        return
    }
}

func runListKeys(cmd *Command, args []string) {
    // open gpg keyring file
    keyringFile, err := os.Open(KeyringPath)
    if err != nil {
        fmt.Printf("error: %s\n", err)
        return
    }

    // read keyring
    keyring, err := openpgp.ReadKeyRing(keyringFile)
    if err != nil {
        fmt.Printf("error: %s\n", err)
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
