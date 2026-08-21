package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("all arguments:", os.Args)

	if len(os.Args) < 2 {
		fmt.Println("usage: toy-container PROGRAM [ARGUMENT...]")
		os.Exit(2)
	}

	program := os.Args[1]
	arguments := os.Args[2:]

	fmt.Println("program:", program)
	fmt.Println("program arguments:", arguments)

	command := exec.Command(program, arguments...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr

	if err := command.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "child failed:", err)
		os.Exit(1)
	}
}
