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
	"multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"----postcrypt-{{ .Boundary }}\""))

// template for pgp/mime formated mail
var MailBodyTpl = template.Must(template.New("mail body").Parse(`
This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)
----postcrypt-{{ .Boundary }}
Content-Type: application/pgp-encrypted
Content-Description: PGP/MIME version identification

Version: 1

----postcrypt-{{ .Boundary }}
Content-Type: application/octet-stream; name="encrypted.asc"
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename="encrypted.asc"

{{ .Message }}

----postcrypt-{{ .Boundary }}--
`))

type Envelope struct {
	Id         string
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
	var keys openpgp.EntityList
	var msg *mail.Message
	var sender string
	var recipients []string
	var log *Tee

	// generate 'unique' id for message
	e.Id = generateRandomString()[:8]

	log = NewTee("postcrypt")
	log.Info("encrypting message with id " + e.Id)

	if len(args) < 2 {
		return
	}

	sender = args[0]
	recipients = args[1:]
	msg, err = readMail()
	if err != nil {
		log.Crit(e.Id + " could not parse mail: " + err.Error())
		return
	}

	if !isEncrypted(e) {
		for _, rcpt := range recipients {
			e.Sender = sender
			e.Recipients = []string{rcpt}
			e.Mail = msg

			keys = getKeys(cmd.Config, e)
			if len(keys) > 0 {
				for _, k := range keys {
					log.Info(e.Id + " encrypting with key " + getKeyId(k) + " for " + rcpt)
				}

				var encrypted *bytes.Buffer
				encrypted, err = encryptMail(e, keys)
				if err != nil {
					log.Err(e.Id + "error encrypting mail. " + err.Error())
					sendMail(cmd.Config, e)
				}

				e = packMail(e, encrypted)
			} else {
				log.Info(e.Id + " no keys found, sending unmodified")
			}

			err = sendMail(cmd.Config, e)
			if err != nil {
				log.Crit(e.Id + " sending mail failed. " + err.Error())
			}
		}
	} else {
		log.Info(e.Id + " already encrypted, sending unmodified")
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
	var ids []string
	var path string
	var fh *os.File
	var err error
	var k openpgp.EntityList

	path, _ = c.GetString("main", "keyring")

	fh, err = os.Open(path)
	if err != nil {
		panic(err)
	}

	k, err = openpgp.ReadKeyRing(fh)
	if err != nil {
		panic(err)
	}

	ids = getIdsByEmails(c, k, e.Recipients)
	return getKeysByIds(k, ids)
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

	fmt.Fprintln(buffer, "")

	// body
	io.Copy(buffer, e.Mail.Body)
	//fmt.Fprintf(buffer, "%s", e.Mail.Body.String())

	return buffer
}

func sendMail(c *conf.ConfigFile, e Envelope) error {
	var addr string
	var err error
	var conn *smtp.Client

	addr, _ = c.GetString("main", "smtp")

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
