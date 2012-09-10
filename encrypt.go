package main

import (
    "os"
    "io"
    "fmt"
    "bytes"
    "strings"
    "net/mail"
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
    Run:  runEncrypt,

    Name: "encrypt",
    Short: "encrypts mails from stdin with PGP/MIME",
    Long: `
Usage: postcrypt encrypt <sender> <receivers>

Help:
Encrypts mails from stdin with PGP/MIME. The mails will be forwarded to
<sender>. This address is best specified by postfix via the $sender variable.

The mails will be encrypted for each receiver in <receivers> if a key is
known to postcrypt. Receivers without a known key are ignored and may not
be able to read the mails later!

If no receiver has a key associated with them, the mail will be forwarded
as is and no encryption takes place.

To add keys, see 'postcrypt help add-key'.
`,
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

{{ .Boundary }}--
`))

// Encrypts a mail from stdin and forwards it to postfix.
func runEncrypt(cmd *Command, args []string) {
    // buffer for original message
    original := bytes.NewBuffer(nil)
    // buffer for encrypted message body
    cryptobuffer := bytes.NewBuffer(nil)
    // buffer for pgp/mime formated message
    msgbuffer := bytes.NewBuffer(nil)

    sender := args[0]
    recipients := args[1:]

    msgid := generateRandomString()[:8]
    logger, _ := syslog.New(syslog.LOG_INFO, "postcrypt")
    logger.Info(fmt.Sprintf("Encrypting message with id %s", msgid))

    // read mail from stdin into buffer
    io.Copy(original, os.Stdin)

    // send original message in case something goes wrong
    defer func() {
        if err := recover(); err != nil {
            logger.Err(fmt.Sprintf("[%s] Error: %s\n", msgid, err))
            sendMail(original, msgid, sender, recipients)
        }
    }()

    // parse mail format (split in header and body mostly)
    msg, err := mail.ReadMessage(original)
    if err != nil {
        panic(err)
    }

    // preserve content-type in encrypted message
    contenttype := msg.Header.Get("Content-Type")

    // skip message if allready encrypted
    if strings.Contains(contenttype, "multipart/encrypted") {
        logger.Info(fmt.Sprintf("[%s] Message allready encrypted, skipping\n", msgid))
        sendMail(original, msgid, sender, recipients)
        return
    }

    // get path to keyring from configruation
    path, err := Config.GetString("", "keyring")
    if err != nil {
        logger.Err(fmt.Sprintf("[%s] Could not read configuration `keyring`\n", msgid))
        panic(err)
    }

    // open gpg keyring file
    keyringFile, err := os.Open(path)
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
    if entities := getKeysByEmail(keyring, recipients); len(entities) > 0 {
        for _, e := range entities {
            keyid := fmt.Sprintf("%X", e.PrimaryKey.KeyId)
            logger.Info(fmt.Sprintf("[%s] Encrypting mail with key: %s", msgid, keyid[:8]))
        }

        // setup armored output encoding
        armored, err := armor.Encode(cryptobuffer, "PGP MESSAGE", nil)
        if err != nil {
            panic(err)
        }
        defer armored.Close()

        // setup encryption
        crypter, err := openpgp.Encrypt(armored, entities, nil, nil, nil)
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

        sendMail(msgbuffer, msgid, sender, recipients)
    } else {
        // could not find key, so leave mail as it was
        sendMail(original, msgid, sender, recipients)
    }
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

// Generates a pseudo-random mime boundary string. A prefix can be supplied to
// customize the boundary with e.g. the program name
func generateBoundary(prefix string) string {
    hash := generateRandomString()
    return fmt.Sprintf("%s-%x", prefix, hash[:10])
}
