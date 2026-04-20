package main

import "os"

func main() {
	os.Exit(newCommand(os.Stdout, os.Stderr).run(os.Args[1:]))
}
