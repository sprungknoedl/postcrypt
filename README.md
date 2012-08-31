postcrypt
=========

postcrypt is a content-filter for Postfix that encrypts mails with PGP before being sent to the next hop.

Installation
============
master.cf
    postcrypt    unix  -       n       n       -       10      pipe
            flags=Rq user=_postcrypt null_sender=
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
