package main

import (
    "os"
    "io"
    "fmt"
    "bytes"
    //"strings"
    "net/mail"
    "net/smtp"
    "log/syslog"
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

    msgid := generateRandomString()[:8]
    logger, _ := syslog.New(SyslogLevel, "postcrypt")

    // read mail from stdin into buffer
    io.Copy(original, os.Stdin)

    // send original message in case something goes wrong
    defer func() {
        if err := recover(); err != nil {
            logger.Err(fmt.Sprintf("[%s] error: %s\n", msgid, err))
            sendMail(msgid, original, args)
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
        keyid := fmt.Sprintf("%X", entity.PrimaryKey.KeyId)
        logger.Info(fmt.Sprintf("[%s] encrypting message with key %s", msgid, keyid[:8]))

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

        sendMail(msgid, msgbuffer, args)
    } else {
        // could not find key, so leave mail as it was
        sendMail(msgid, original, args)
    }
}

func sendMail(msgid string, r io.Reader, args []string) {
        logger, _ := syslog.New(SyslogLevel, "postcrypt")
        defer func() {
            if err := recover(); err != nil {
                logger.Err(fmt.Sprintf("[%s] error: %s\n", msgid, err))
            }
        }()

        from := args[0]
        to := args[1:]

        // connect to smtp
        c, err := smtp.Dial("127.0.0.1:10029")
        if err != nil {
            panic(err)
        }

        // sender
        if err = c.Mail(from); err != nil {
            panic(err)
        }

        // recipients
        for _, addr := range to {
            if err = c.Rcpt(addr); err != nil {
                panic(err)
            }
        }

        // mail
        w, err := c.Data()
        if err != nil {
            panic(err)
        }
        io.Copy(w, r)

        c.Quit()
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
    hash := generateRandomString()
    return fmt.Sprintf("%s-%x", prefix, hash[:10])
}
