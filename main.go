package main

import (
	"flag"
	"fmt"
	"os"
	"text/template"

	"code.google.com/p/goconf/conf"
)

//
// --- type definitions ---
//
type Command struct {
	Name   string
	Run    func(cmd *Command, args []string)
	Short  string
	Long   string
	Config *conf.ConfigFile
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

//
// --- functions ---
//

// prints usage information and list of available subcommands
func usage() {
	tmpl, _ := template.New("usage").Parse(
		`postcrypt is a tool to encrypt mails with PGP before relaying.

Usage:

    postcrypt [options] command [arguments]

The commands are:
{{range .}}
    {{ .Name | printf "%-11s"}} {{.Short}}{{end}}

Use "postcrypt help [command]" for more information about a command.

The options are:

`)

	tmpl.Execute(os.Stdout, commands)
	flag.PrintDefaults()
}

// prints detailed help information about a command
func help(args []string) {
	log := NewTee("postcrypt")

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

	log.Err("unknown help topic `" + args[0] + "`. run 'go help'.")
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

// commandline flags
var cfgPath = flag.String("config", "/etc/postcrypt.conf", "specify an alternative configuration file")

func main() {
	var err error
	var args []string
    var config *conf.ConfigFile

	log := NewTee("postcrypt")

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
	config, err = conf.ReadConfigFile(*cfgPath)
	if err != nil {
		log.Crit("could not read configuration. " + err.Error())
		return
	}

	// validate configuration file, see if all necessary options
	// are present
	err = validateConfig(config)
	if err != nil {
		log.Crit("configuration not valid. " + err.Error())
		return
	}

	// execute command
	for _, cmd := range commands {
		if cmd.Name == args[0] && cmd.Run != nil {
            cmd.Config = config
			cmd.Run(cmd, args[1:])
			return
		}
	}

	// command not found
	log.Err("unknown subcommand `" + args[0] + "`. run 'go help'.")
}
