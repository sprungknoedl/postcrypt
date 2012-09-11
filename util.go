package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"time"

	"code.google.com/p/go.crypto/openpgp"
)

type Tee struct {
	prefix  string
	log     *syslog.Writer
	console *os.File
}

func NewTee(prefix string) *Tee {
	l, _ := syslog.New(syslog.LOG_INFO, prefix)

	return &Tee{
		prefix:  prefix,
		log:     l,
		console: os.Stdout,
	}
}

func (t *Tee) Info(m string) {
	t.log.Info("[info]" + m)
	fmt.Fprintf(t.console, "[info] %s: %s\n", t.prefix, m)
}

func (t *Tee) Warn(m string) {
	t.log.Warning("[warning]" + m)
	fmt.Fprintf(t.console, "[warning] %s: %s\n", t.prefix, m)
}

func (t *Tee) Err(m string) {
	t.log.Err("[error]" + m)
	fmt.Fprintf(t.console, "[error] %s: %s\n", t.prefix, m)
}

func (t *Tee) Crit(m string) {
	t.log.Crit("[critical]" + m)
	fmt.Fprintf(t.console, "[critical] %s: %s\n", t.prefix, m)
}

// Generates a pseudo random string.
// Warning: The string is the sha1 hash of the curren ttime, so it should 
// under no circumstances be used in cryptography or for passwords!
func generateRandomString() string {
	hash := sha1.New()
	io.WriteString(hash, time.Now().String())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func getKeyId(k *openpgp.Entity) string {
	return fmt.Sprintf("%X", k.PrimaryKey.KeyId)[8:]
}

// Return the first Entity from keyring wich matches the given email address.
func getKeysByEmail(keyring openpgp.EntityList, emails []string) openpgp.EntityList {
	var keys openpgp.EntityList

	for _, entity := range keyring {
		for _, identity := range entity.Identities {
			for _, email := range emails {
				if identity.UserId.Email == email {
					keys = append(keys, entity)
					continue // enough if one addr per key matches
				}
			}
		}
	}

	return keys
}
