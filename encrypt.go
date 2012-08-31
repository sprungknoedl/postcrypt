package main

import (
    "os"
    "io"
	"fmt"
    "time"
    "bytes"
    "strings"
    "os/exec"
    "net/mail"
    "crypto/sha1"
    "text/template"
    "code.google.com/p/go.crypto/openpgp"
    "code.google.com/p/go.crypto/openpgp/armor"
)

// data which gets passed to templates
type PGPMimeData struct {
    Message *bytes.Buffer
    Boundary string
}

var cmdEncrypt = &Command{
	Name: "encrypt",
	Run:  runEncrypt,
}

// template for mail header Content-Type.
var contenttype = template.Must(template.New("content type").Parse(
    "multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{{ .Boundary }}\""))

// template for pgp/mime formated mail
var mailbody = template.Must(template.New("mail body").Parse(`
This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)
{{ .Boundary }}
Content-Type: application/pgp-encrypted
Content-Description: PGP/MIME version identification

Version: 1

{{ .Boundary }}
Content-Type: application/octet-stream; name="encrypted.asc"
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename="encrypted.asc"

{{ .Message }}

{{ .Boundary }}
`))

// Encrypts a mail from stdin and forwards it to postfix.
func runEncrypt(cmd *Command, args []string) {
    // buffer for original message
    original := bytes.NewBuffer(nil)
    // buffer for encrypted message body
    cryptobuffer := bytes.NewBuffer(nil)
    // buffer for pgp/mime formated message
    msgbuffer := bytes.NewBuffer(nil)

    // read mail from stdin into buffer
    io.Copy(original, os.Stdin)

    // send original message in case something goes wrong
    defer func() {
        if err := recover(); err != nil {
            fmt.Printf("error: %s\n", err)
            sendMail(original, args)
        }
    }()

    // open gpg keyring file
    keyringFile, err := os.Open(KeyringPath)
    if err != nil {
        panic(err)
    }
    defer keyringFile.Close()

    // read keyring
    keyring, err := openpgp.ReadKeyRing(keyringFile)
    if err != nil {
        panic(err)
    }

    // see if key is known so we can encrypt mail
    if entity := getKeyByEmail(keyring, args); entity != nil {
        to := []*openpgp.Entity{entity}

        // parse mail format (split in header and body mostly)
        msg, err := mail.ReadMessage(original)
        if err != nil {
            panic(err)
        }

        // setup armored output encoding
        armored, err := armor.Encode(cryptobuffer, "PGP MESSAGE", nil)
        if err != nil {
            panic(err)
        }
        defer armored.Close()

        // setup encryption
        crypter, err := openpgp.Encrypt(armored, to, nil, nil, nil)
        if err != nil {
            panic(err)
        }
        defer crypter.Close()

        // preserve content-type in encrypted message
        contenttype := msg.Header.Get("Content-Type")
        if contenttype == "" {
            contenttype = "text/plain"
        }
        fmt.Fprintf(crypter, "Content-Type: %s\n\n", contenttype)

        // encrypt message body
        io.Copy(crypter, msg.Body)
        crypter.Close()
        armored.Close()

        // create new mail with pgp/mime format
        data := &PGPMimeData{
            Message: cryptobuffer,
            Boundary: generateBoundary("------postcrypt"),
        }
        printHeaders(msgbuffer, msg.Header, data)
        mailbody.Execute(msgbuffer, data)

        sendMail(msgbuffer, args)
    } else {
        // could not find key, so leave mail as it was
        sendMail(original, args)
    }
}

func sendMail(r io.Reader, recipients []string) {
        // sendmail command to relay message
        sendmail := exec.Command("sendmail", "-G", "-i", strings.Join(recipients, " "))
        w, err := sendmail.StdinPipe()
        if err != nil {
            fmt.Printf("error: %s\n", err)
            return
        }

        // write mail to sendmail's stdin
        sendmail.Start()
        io.Copy(w, r)

        // close output and wait for sendmail to deliver mail
        w.Close()
        sendmail.Wait()
}

// Prints the mail header and sets Content-Type to PGP/Mime.
func printHeaders(w io.Writer, header mail.Header, data *PGPMimeData) {
    buffer := bytes.NewBuffer(nil)
    contenttype.Execute(buffer, data)
    header["Content-Type"] = []string{buffer.String()}

    for key, values := range header {
        for _, value := range values {
            fmt.Fprintf(w, "%s: %s\n", key, value)
        }
    }
}

// Return the first Entity from keyring wich matches the given email address.
func getKeyByEmail(keyring openpgp.EntityList, emails []string) *openpgp.Entity {
    for _, entity := range keyring {
        for _, ident := range entity.Identities {
            for _, email := range emails {
                if ident.UserId.Email == email {
                    return entity
                }
            }
        }
    }

    return nil
}

// Generates a pseudo-random mime boundary string. A prefix can be supplied to
// customize the boundary with e.g. the program name
func generateBoundary(prefix string) string {
    hash := sha1.New()
    io.WriteString(hash, time.Now().String())
    return fmt.Sprintf("%s-%x", prefix, hash.Sum(nil)[:10])
}
