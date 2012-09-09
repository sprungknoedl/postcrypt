package main

import (
    "io"
    "fmt"
    "net/smtp"
    "log/syslog"
)

func sendMail(r io.Reader, msgid string, from string, recipients []string) {
        logger, _ := syslog.New(syslog.LOG_INFO, "postcrypt")

        // get address of smtp service to send mail to
        addr, err := Config.GetString("", "smtp")
        if err != nil {
            logger.Err(fmt.Sprintf("[%s] Could not read configuration `smtp`\n", msgid))
            panic(err)
        }

        // connect to smtp
        c, err := smtp.Dial(addr)
        if err != nil {
            panic(err)
        }

        // sender
        if err = c.Mail(from); err != nil {
            panic(err)
        }

        // recipients
        for _, addr := range recipients {
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

        logger.Info(fmt.Sprintf("[%s] Delivered mail to sendmail (%s)", msgid, addr))
        c.Quit()
}

