package main

import (
    "os"
    "fmt"
    "flag"
    "text/template"

    "code.google.com/p/goconf/conf"
)


//
// --- type definitions ---
//
type Command struct {
    Name string
    Run  func(cmd *Command, args []string)
    Short string
    Long string
}


//
// --- global variables ---
//

// holds list of available subcommands
var commands = []*Command{
    cmdEncrypt,
    cmdAddKey,
    cmdListKeys,
}

// holds parsed configuration
var Config *conf.ConfigFile


// commandline flags
var cfgPath = flag.String("config", "/etc/postcrypt.conf", "specify an alternative configuration file")


//
// --- functions ---
//

// prints usage information and list of available subcommands
func usage() {
    tmpl := template.Must(template.New("usage").Parse(
`postcrypt is a tool to encrypt mails with PGP before relaying.

Usage:

    postcrypt [options] command [arguments]

The commands are:
{{range .}}
    {{ .Name | printf "%-11s"}} {{.Short}}{{end}}

Use "postcrypt help [command]" for more information about a command.

The options are:

    {{ "-config" | printf "%-11s"}} specify an alternative configuration file

`))

    if err := tmpl.Execute(os.Stdout, commands); err != nil {
        panic(err)
    }
}

// prints detailed help information about a command
func help(args []string) {
    if len(args) < 1 {
        usage()
        return
    }

    for _, cmd := range commands {
        if cmd.Name == args[0] {
            fmt.Printf(cmd.Long)
            return
        }
    }

    fmt.Printf("Unknown help topic %#q. Run 'go help'.\n", args[0])
}

func validateConfig(c *conf.ConfigFile) error {
    if _, err := c.GetString("", "smtp"); err != nil {
        return err
    }

    if _, err := c.GetString("", "keyring"); err != nil {
        return err
    }

    return nil
}

func main() {
    var err error
    var args []string

    flag.Parse()
    args = flag.Args()

    // no subcommand given, so print usage
    if len(args) < 1 {
        usage()
        return
    }

    // subcommand is help, so help them
    // cannot make help a *Command because it would
    // result in an `initialization loop` if help
    // would iterate over *Command[] array
    if args[0] == "help" {
        help(args[1:])
        return
    }

    // try to read configuration
    Config, err = conf.ReadConfigFile(*cfgPath)
    if err != nil {
        fmt.Printf("error: could not read configuration. %s\n", err)
        return
    }

    // validate configuration file, see if all necessary options
    // are present
    err = validateConfig(Config)
    if err != nil {
        fmt.Printf("error: configuration not valid. %s\n", err)
        return
    }


    // execute command
    for _, cmd := range commands {
        if cmd.Name == args[0] && cmd.Run != nil {
            cmd.Run(cmd, args[1:])
            return
        }
    }

    // command not found
    fmt.Printf("Unknown subcommand %#q. Run 'go help'.\n", args[0])
}
