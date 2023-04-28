package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

var (
	ConfigIsStrict = false
)

// CLI
func main() {
	app := cli.App{
		Name:     "Chimata",
		HelpName: "Chimata-client",
		Version:  "0.99.indev",
		Usage:    "CLI Interface of Project Chimata/Client. Please note that the project is designed to run in `go test`",
	}

	//CryptoInit()

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

	//debug.NoImpl()
}
