postcrypt
=========

postcrypt is a content-filter for Postfix that encrypts mails with PGP before being sent to the next hop.

Build
=====
Building postcrypt requires a working go environment. If you have allready one, just execute:
    
    go get github.com/sprungknoedl/postcrypt

This will install postcrypt into your `$GOPATH/bin` directory.

Installation
============
1. Ensure GPG is installed and configured.
2. Configure /etc/postcrypt.conf according to postcrypt.conf.template
3. Create dedicated user to run postcrypt
  * postcrypt needs a sh-compatible shell (no /sbin/nologin).
  * This will hopefully unnecessary in future versions.
4. Add the following to the end of your postfix's `master.cf`:

        postcrypt    unix  -       n       n       -       10      pipe
                flags=Rq user=postcrypt null_sender=
                argv=/usr/bin/postcrypt encrypt ${sender} ${recipient}

        127.0.0.1:10029 inet    n       -       n       -       10      smtpd
                -o content_filter=
                -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
                -o smtpd_helo_restrictions=
                -o smtpd_client_restrictions=
                -o smtpd_sender_restrictions=
                -o smtpd_recipient_restrictions=permit_mynetworks,reject
                -o mynetworks=127.0.0.0/8
                -o smtpd_authorized_xforward_hosts=127.0.0.0/8

5. Add the following to your postfix's `main.cf`:

        content_filter = postcrypt

6. Restart postfix.

Adding keys to postcrypt
========================
postcrypt will only encrypt mails where it knows the key of the receiver. To learn postcrypt the key, find the PGP keyid with your gpg tool of liking and execute:

    postcrypt add-key KEYID

With `postcrypt list-keys` you can view the list of known keys and recipients.
