package main

import (
    "io"
    "fmt"
    "time"
    "crypto/sha1"
)

func generateRandomString() string {
    hash := sha1.New()
    io.WriteString(hash, time.Now().String())
    return fmt.Sprintf("%x", hash.Sum(nil))
}
