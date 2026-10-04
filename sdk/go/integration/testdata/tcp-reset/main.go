// A real guest socket reset, controlled through exec stdin after the host filled TCP credit.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func main() {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	check(err)
	defer listener.Close()
	_, err = fmt.Fprintln(os.Stdout, listener.Addr())
	check(err)
	peer, err := listener.AcceptTCP()
	check(err)
	commands := bufio.NewScanner(os.Stdin)
	if !commands.Scan() || commands.Text() != "reset" {
		panic(fmt.Sprintf("expected reset command, got %q: %v", commands.Text(), commands.Err()))
	}
	check(peer.SetLinger(0))
	check(peer.Close())
	_, err = fmt.Fprintln(os.Stdout, "reset")
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
