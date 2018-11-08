// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package lsof

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Process defines a process using an open file. Properties here are strings
// for compatibility with different platforms.
type Process struct {
	PID             string
	ParentPID       string
	Command         string
	UserID          string
	FileDescriptors []FileDescriptor
}

// FD returns the file descriptor n, or an empty file descriptor.
func (p Process) FD(n string) FileDescriptor {
	for _, fd := range p.FileDescriptors {
		if fd.FD == n {
			return fd
		}
	}
	return FileDescriptor{}
}

func (p Processes) ProcessConnectedToDevice(dev string) Process {
	find := fmt.Sprintf("->%s", dev)
	for _, pp := range p {
		for _, fd := range pp.FileDescriptors {
			if fd.Name == find {
				return pp
			}
		}
	}
	return Process{}
}

// Processes is a slice of Process.
type Processes []Process

// PID returns process with pid n or an empty process.
func (p Processes) PID(n string) Process {
	for _, pp := range p {
		if pp.PID == n {
			return pp
		}
	}
	return Process{}
}

// FileDescriptor defines a file in use by a process
type FileDescriptor struct {
	FD     string
	Device string
	Name   string
}

// UnixSockets returns processes connected to UNIX sockets.
func UnixSockets() (Processes, error) {
	return run([]string{"-U", "-F", "pRcufdn"})
}

func (p *Process) fillField(s string) error {
	if s == "" {
		return fmt.Errorf("Empty field")
	}
	// See Output for Other Programs at http://linux.die.net/man/8/lsof
	key := s[0]
	value := s[1:]
	switch key {
	case 'p':
		p.PID = value
	case 'R':
		p.ParentPID = value
	case 'c':
		p.Command = value
	case 'u':
		p.UserID = value
	default:
		// Skip unhandled field.
	}
	return nil
}

func parseInt(p *int, v string) error {
	i, err := strconv.Atoi(v)
	if err != nil {
		return err
	}
	*p = i
	return nil
}

func (f *FileDescriptor) fillField(s string) error {
	// See Output for Other Programs at http://linux.die.net/man/8/lsof
	key := s[0]
	value := s[1:]
	switch key {
	case 'f':
		f.FD = value
	case 'n':
		f.Name = value
	case 'd':
		f.Device = value
	default:
		// Skip unhandled field.
	}

	return nil
}

func (p *Process) parseFileLines(lines []string) error {
	file := FileDescriptor{}
	for _, line := range lines {
		if strings.HasPrefix(line, "f") && file.FD != "" {
			// New file.
			p.FileDescriptors = append(p.FileDescriptors, file)
			file = FileDescriptor{}
		}
		err := file.fillField(line)
		if err != nil {
			return err
		}
	}
	if file.FD != "" {
		p.FileDescriptors = append(p.FileDescriptors, file)
	}
	return nil
}

func parseProcessLines(lines []string) (Process, error) {
	p := Process{}
	for index, line := range lines {
		if strings.HasPrefix(line, "f") {
			err := p.parseFileLines(lines[index:])
			if err != nil {
				return p, err
			}
			break
		} else {
			p.fillField(line)
		}
	}
	return p, nil
}

func parseAppendProcessLines(processes []Process, linesChunk []string) ([]Process, []string, error) {
	if len(linesChunk) == 0 {
		return processes, linesChunk, nil
	}
	process, err := parseProcessLines(linesChunk)
	if err != nil {
		return processes, linesChunk, err
	}
	processesAfter := append(processes, process)
	linesChunkAfter := []string{}
	return processesAfter, linesChunkAfter, nil
}

func parse(s string) ([]Process, error) {
	lines := strings.Split(s, "\n")
	linesChunk := []string{}
	processes := []Process{}
	var err error
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// End of process, let's parse those lines.
		if strings.HasPrefix(line, "p") && len(linesChunk) > 0 {
			processes, linesChunk, err = parseAppendProcessLines(processes, linesChunk)
			if err != nil {
				return nil, err
			}
		}
		linesChunk = append(linesChunk, line)
	}
	processes, _, err = parseAppendProcessLines(processes, linesChunk)
	if err != nil {
		return nil, err
	}
	return processes, nil
}

// execError is an error running lsof.
type execError struct {
	command string
	args    []string
	output  string
	err     error
}

func (e execError) Cause() error {
	return e.err
}

func (e execError) Error() string {
	return fmt.Sprintf("lsof: error running %s %s: %s (%s)", e.command, e.args, e.err, e.output)
}

func run(args []string) ([]Process, error) {
	command := "/usr/sbin/lsof"
	args = append([]string{"-w"}, args...)
	output, err := exec.Command(command, args...).Output()
	if err != nil {
		return nil, execError{command: command, args: args, output: string(output), err: err}
	}
	return parse(string(output))
}
