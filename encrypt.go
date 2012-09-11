package main

import (
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"text/template"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/goconf/conf"
)

var cmdEncrypt = &Command{
	Run: runEncrypt,

	Name:  "encrypt",
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
var MailHeaderTpl = template.Must(template.New("content type").Parse(
	"multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"----postfix-{{ .Boundary }}\""))

// template for pgp/mime formated mail
var MailBodyTpl = template.Must(template.New("mail body").Parse(`
This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)
----postfix-{{ .Boundary }}
Content-Type: application/pgp-encrypted
Content-Description: PGP/MIME version identification

Version: 1

----postfix-{{ .Boundary }}
Content-Type: application/octet-stream; name="encrypted.asc"
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename="encrypted.asc"

{{ .Message }}

----postfix-{{ .Boundary }}--
`))

type Envelope struct {
	Mail       *mail.Message
	Sender     string
	Recipients []string
}

type TemplateData struct {
	Message  *bytes.Buffer
	Boundary string
}

func runEncrypt(cmd *Command, args []string) {
	var err error
	var e Envelope
	var c *conf.ConfigFile
	var keys openpgp.EntityList

	log := NewTee("postcrypt")
	id := generateRandomString()[:8]
	log.Info("encrypting message with id " + id)

	if len(args) < 2 {
		return
	}

	c = cmd.Config

	e.Sender = args[0]
	e.Recipients = args[1:]
	e.Mail, err = readMail()
	if err != nil {
		log.Crit(id + " could not parse mail: " + err.Error())
		return
	}

	if !isEncrypted(e) {
		keys = getKeys(c, e)
		if len(keys) > 0 {
			for _, k := range keys {
				log.Info(id + " encrypting with key " + getKeyId(k))
			}

			var encrypted *bytes.Buffer
			encrypted, err = encryptMail(e, keys)
			if err != nil {
				log.Err(id + "error encrypting mail. " + err.Error())
				sendMail(c, e)
			}

			e = packMail(e, encrypted)
		} else {
			log.Info(id + " no keys found, sending unmodified")
		}
	} else {
		log.Info(id + " already encrypted, sending unmodified")
    }

	err = sendMail(c, e)
    if err != nil {
        log.Crit(id + " sending mail failed. " + err.Error())
    }
}

func readMail() (*mail.Message, error) {
	var buffer *bytes.Buffer

	buffer = bytes.NewBuffer(nil)
	io.Copy(buffer, os.Stdin)
	return mail.ReadMessage(buffer)
}

func isEncrypted(e Envelope) bool {
	contenttype := e.Mail.Header.Get("Content-Type")
	return strings.Contains(contenttype, "multipart/encrypted")
}

func getKeys(c *conf.ConfigFile, e Envelope) openpgp.EntityList {
	var path string
	var fh *os.File
	var err error
	var keyring openpgp.EntityList

	path, _ = c.GetString("", "keyring")

	fh, err = os.Open(path)
	if err != nil {
		panic(err)
	}

	keyring, err = openpgp.ReadKeyRing(fh)
	if err != nil {
		panic(err)
	}

	return getKeysByEmail(keyring, e.Recipients)
}

func encryptMail(e Envelope, keys openpgp.EntityList) (*bytes.Buffer, error) {
	var err error
	var contenttype string
	var buffer *bytes.Buffer
	var armored io.WriteCloser
	var crypter io.WriteCloser

	buffer = bytes.NewBuffer(nil)

	armored, err = armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		return buffer, err
	}

	crypter, err = openpgp.Encrypt(armored, keys, nil, nil, nil)
	if err != nil {
		return buffer, err
	}

	contenttype = e.Mail.Header.Get("Content-Type")
	if contenttype == "" {
		contenttype = "text/plain"
	}
	fmt.Fprintf(crypter, "Content-Type: %s\n\n", contenttype)

	io.Copy(crypter, e.Mail.Body)
	crypter.Close()
	armored.Close()

	return buffer, nil
}

func packMail(e Envelope, encrypted *bytes.Buffer) Envelope {
	var data *TemplateData
	var body *bytes.Buffer
	var contenttype *bytes.Buffer

	body = bytes.NewBuffer(nil)
	contenttype = bytes.NewBuffer(nil)

	data = &TemplateData{
		Message:  encrypted,
		Boundary: generateRandomString()[:10],
	}

	MailBodyTpl.Execute(body, data)
	MailHeaderTpl.Execute(contenttype, data)

	e.Mail.Header["Content-Type"] = []string{contenttype.String()}
	e.Mail.Body = body
	return e
}

func serializeMail(e Envelope) *bytes.Buffer {
	var buffer *bytes.Buffer
	buffer = bytes.NewBuffer(nil)

	// header
	for key, values := range e.Mail.Header {
		for _, value := range values {
			fmt.Fprintf(buffer, "%s: %s\n", key, value)
		}
	}

	// body
	fmt.Fprintf(buffer, "%s", e.Mail.Body)

	return buffer
}

func sendMail(c *conf.ConfigFile, e Envelope) error {
	var addr string
	var err error
	var conn *smtp.Client

	addr, _ = c.GetString("", "smtp")

	conn, err = smtp.Dial(addr)
	if err != nil {
        return err
	}

	if err = conn.Mail(e.Sender); err != nil {
        return err
	}

	for _, addr := range e.Recipients {
		if err = conn.Rcpt(addr); err != nil {
            return err
		}
	}

	w, err := conn.Data()
	if err != nil {
        return err
	}

	io.Copy(w, serializeMail(e))
	conn.Quit()
    return nil
}
