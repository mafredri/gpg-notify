package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"

	"github.com/mafredri/gpg-notify/agent"

	"github.com/pkg/errors"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			cancel()
		}
	}()

	if err := run(ctx); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func socketReader(c net.Conn) {
	defer c.Close()

	agent := agent.New()
	s := bufio.NewScanner(c)
	for s.Scan() {
		err := agent.LogUpdate(s.Bytes())
		if err != nil {
			fmt.Println(err)
		}
	}
	if err := s.Err(); err != nil {
		log.Println(err)
	}
}

func run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	homedir := os.Getenv("GNUPGHOME")
	if homedir == "" {
		homedir = path.Join(os.Getenv("HOME"), ".gnupg")
	}

	agentSock, err := configLogFile(path.Join(homedir, "gpg-agent.conf"))
	if err != nil {
		return err
	}

	if !strings.HasPrefix(agentSock, "socket://") {
		return errors.New(fmt.Sprintf("missing gpg-agent config: log-file socket://%s/%s", homedir, "S.gpg-agent.log"))
	}
	agentSock = strings.Replace(agentSock, "socket://", "", 1)

	log.Println(agentSock)

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", agentSock)
	if err != nil {
		return errors.Wrap(err, "listen error")
	}
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		}
	}()
	defer l.Close()

	for {
		fd, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return errors.Wrap(err, "accept error")
		}

		go socketReader(fd)
	}
}

func configLogFile(path string) (name string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return name, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		l := s.Text()
		if strings.HasPrefix(l, "log-file") {
			name = strings.Join(strings.Split(l, " ")[1:], " ")
			return name, nil
		}
	}
	if s.Err() != nil {
		return name, err
	}

	return name, errors.New("log file not found")
}
