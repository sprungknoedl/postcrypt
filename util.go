package main

import (
    "io"
    "fmt"
    "time"
    "crypto/sha1"

    "code.google.com/p/go.crypto/openpgp"
)

// Generates a pseudo random string.
// Warning: The string is the sha1 hash of the curren ttime, so it should 
// under no circumstances be used in cryptography or for passwords!
func generateRandomString() string {
    hash := sha1.New()
    io.WriteString(hash, time.Now().String())
    return fmt.Sprintf("%x", hash.Sum(nil))
}


// Return the first Entity from keyring wich matches the given email address.
func getKeysByEmail(keyring openpgp.EntityList, emails []string) []*openpgp.Entity {
    var keys []*openpgp.Entity

    for _, entity := range keyring {
        for _, identity := range entity.Identities {

            for _, email := range emails {
                if identity.UserId.Email == email {
                    keys = append(keys, entity)
                    continue    // enough if one addr per key matches
                }
            }

        }
    }

    return keys
}
