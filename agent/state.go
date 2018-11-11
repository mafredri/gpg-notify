package agent

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/mafredri/gpg-notify/lsof"

	"github.com/deckarep/gosx-notifier"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/process"
)

type sshState struct {
	pid     string
	debugfd string
	sign    bool
}

// State represents the gpg-agent state.
type State struct {
	pid         string
	sshfd       map[string]*sshState
	lastSSHFD   string
	lastDebugFD string

	buf *messageBuffer
}

// New returns a new, empty, State.
func New() *State {
	s := &State{
		sshfd: make(map[string]*sshState),

		buf: newMessageBuffer(),
	}
	go s.watch()
	return s
}

func (s *State) Close() error {
	close(s.buf.c)
	return nil
}

func (s *State) watch() {
	for m := range s.buf.get() {
		s.buf.load()

		err := s.LogUpdate(m)
		if err != nil {
			fmt.Println(err)
		}
	}
}

var (
	agentRe    = regexp.MustCompile("^gpg-agent\\[(?P<pid>[0-9]+)\\]: (?P<message>.+)$")
	scdaemonRe = regexp.MustCompile("^scdaemon\\[(?P<pid>[0-9]+)\\]: (?P<message>.+)$")

	debugRe                = regexp.MustCompile("^DBG: chan_(?P<chan>[0-9]+) (?P<chan_dir>-?[<>]-?) (?P<command>.+)$")
	sshHandlerRe           = regexp.MustCompile("^ssh handler [^ ]+ for fd (?P<fd>[0-9]+) (?P<action>.+)$")
	sshRequestRe           = regexp.MustCompile("^ssh request handler for (?P<action>[a-z_]+) \\([0-9]+\\) (?P<status>.+)$")
	sshSignRequestFailedRe = regexp.MustCompile("^ssh sign request failed: (.+)$")
)

type messageType int

const (
	debugMessage messageType = iota + 1

	gpgRemoteProcessConnected
	gpgRemoteProcessDisconnected
	gpgPinentryConnected
	gpgPinentryDisconnected
	gpgPinentryOwner
	gpgPrivateKeySign
	gpgPrivateKeyDecrypt
	gpgPrivateKeyAuth

	sshHandlerStarted
	sshHandlerClosed
	sshRequestIdentitiesStarted
	sshRequestIdentitiesReady
	sshSignRequestStarted
	sshSignRequestReady
	sshAddIdentityStarted
	sshAddIdentityReady
	sshSignRequestFailed

	ignoredMessage
	unhandledMessage
)

func (s *State) Add(logline []byte) {
	s.buf.store(logline)
}

// LogUpdate parses the log line and updates State.
func (s *State) LogUpdate(line []byte) error {
	var from, message string

	switch {
	case agentRe.Match(line):
		from = "gpg-agent"
		match := agentRe.FindAllStringSubmatch(string(line), -1)[0]
		pid := match[1]
		if pid != s.pid {
			if s.pid != "" {
				fmt.Printf("gpg-agent with pid %s replaced by %s\n", s.pid, pid)
			}
			s.pid = pid
		}
		message = match[2]

	case scdaemonRe.Match(line):
		from = "scdaemon"
		match := scdaemonRe.FindAllStringSubmatch(string(line), -1)[0]
		// pid := match[1]
		// if pid != s.pid {
		// 	if s.pid != "" {
		// 		fmt.Printf("scdaemon with pid %s replaced by %s\n", s.pid, pid)
		// 	}
		// 	s.pid = pid
		// }
		message = match[2]

		if s.scdaemonDebugState(message) == ignoredMessage {
			return nil
		}

	default:
		return errors.Errorf("bad log line: %q", line)
	}

	state, payload := s.logState(message)
	if state == debugMessage {
		v := debugRe.FindAllStringSubmatch(message, -1)[0]
		chfd, chdir, command := v[1], v[2], v[3]

		state, payload = s.debugState(chfd, chdir, command)
		s.lastDebugFD = chfd
	}

	switch state {
	case gpgRemoteProcessConnected:
		// rp, err := findProcessByFD(s.pid, s.lastDebugFD)
		// if err != nil {
		// 	fmt.Println("okPleasedToMeetYou", err)
		// 	return nil
		// }
		// pp := findParentByPID(rp.ParentPID)
		// fmt.Println(rp.PID, rp.Command, "requesting stuff... by:", rp.ParentPID, pp.Name, pp.Cmdline)

	case gpgRemoteProcessDisconnected:
	case gpgPinentryConnected:
	case gpgPinentryDisconnected:
	case gpgPinentryOwner:
	case gpgPrivateKeySign:
		n := gosxnotifier.NewNotification("Sign Request!")
		n.AppIcon = "resources/gpg.png"
		n.ContentImage = "resources/git.png"
		n.Sound = gosxnotifier.Pop
		return n.Push()

	case gpgPrivateKeyDecrypt:
		n := gosxnotifier.NewNotification("Decrypt Request!")
		n.AppIcon = "resources/gpg.png"
		n.Sound = gosxnotifier.Pop
		return n.Push()

	case gpgPrivateKeyAuth:
		ssh, ok := s.sshfd[s.lastSSHFD]
		if ok && ssh.sign {
			n := gosxnotifier.NewNotification("SSH Auth Request!")
			n.AppIcon = "resources/gpg.png"
			n.ContentImage = "resources/yubikey.png"
			n.Sound = gosxnotifier.Pop
			return n.Push()
		}

	case sshHandlerStarted:
		s.lastSSHFD = payload
		ssh := &sshState{}
		s.sshfd[s.lastSSHFD] = ssh

		// rp, err := findProcessByFD(s.pid, s.lastSSHFD)
		// if err != nil {
		// 	fmt.Println("sshHandlerStarted", err)
		// 	return nil
		// }
		// pp := findParentByPID(rp.ParentPID)
		// fmt.Println(rp.PID, rp.Command, "requesting stuff...", pp.PID, pp.Name, pp.Cmdline)

	case sshHandlerClosed:
		delete(s.sshfd, payload)
		s.lastSSHFD = ""
	case sshRequestIdentitiesStarted:
	case sshRequestIdentitiesReady:
	case sshSignRequestStarted:
		ssh, ok := s.sshfd[s.lastSSHFD]
		if ok {
			ssh.sign = true
		}
	case sshSignRequestReady:
		ssh, ok := s.sshfd[s.lastSSHFD]
		if ok {
			ssh.sign = false
		}
	case sshAddIdentityStarted:
	case sshAddIdentityReady:
	case sshSignRequestFailed:
	case ignoredMessage:
		// Ignore.
	case unhandledMessage:
		log.Printf("%s: %q [unhandled]\n", from, message)
	default:
		panic("not reachable")
	}

	return nil
}

func (s *State) logState(message string) (messageType, string) {
	switch {
	case debugRe.MatchString(message):
		return debugMessage, ""

	case sshHandlerRe.MatchString(message):
		v := sshHandlerRe.FindAllStringSubmatch(message, -1)[0]
		fd, action := v[1], v[2]

		switch action {
		case "started":
			return sshHandlerStarted, fd
		case "terminated":
			return sshHandlerClosed, fd
		default:
			panic("unknown handler " + action + " for fd " + fd)
		}

	case sshRequestRe.MatchString(message):
		v := sshRequestRe.FindAllStringSubmatch(message, -1)[0]
		action, status := v[1], v[2]
		started := status == "started"
		ready := status == "ready"

		switch {
		case started && action == "request_identities":
			return sshRequestIdentitiesStarted, ""
		case ready && action == "request_identities":
			return sshRequestIdentitiesReady, ""
		case started && action == "sign_request":
			return sshSignRequestStarted, ""
		case ready && action == "sign_request":
			return sshSignRequestReady, ""
		case started && action == "add_identity":
			return sshAddIdentityStarted, ""
		case ready && action == "add_identity":
			return sshAddIdentityReady, ""
		default:
			panic("unknown request " + action + " " + status)
		}
	case sshSignRequestFailedRe.MatchString(message):
		return sshSignRequestFailed, ""

	case strings.Contains(message, "DBG: agent_cache_housekeeping"):
		return ignoredMessage, ""

	default:
		return unhandledMessage, ""
	}
}

func (s *State) debugState(chfd, chdir, command string) (messageType, string) {
	send := chdir == "->"
	recv := chdir == "<-"

	switch {
	case send && strings.HasPrefix(command, "OK Pleased to meet you"):
		return gpgRemoteProcessConnected, ""
	case send && strings.HasPrefix(command, "OK closing connection"):
		return gpgRemoteProcessDisconnected, ""

	// Recv here, since gpg-agent talks to Pinentry.
	case recv && strings.HasPrefix(command, "OK Pleased to meet you"):
		return gpgPinentryConnected, ""
	case send && command == "BYE":
		return gpgPinentryDisconnected, ""

	case send && strings.HasPrefix(command, "OPTION owner"):
		owner := strings.Join(strings.Split(command, "=")[1:], "=")
		return gpgPinentryOwner, owner
	case strings.HasPrefix(command, "OPTION"):
		return ignoredMessage, ""

	case send && strings.HasPrefix(command, "PKSIGN"):
		return gpgPrivateKeySign, ""
	case send && strings.HasPrefix(command, "PKDECRYPT"):
		return gpgPrivateKeyDecrypt, ""
	case send && strings.HasPrefix(command, "PKAUTH"):
		return gpgPrivateKeyAuth, ""

	case send && command == "SERIALNO":
		// If SSH just moments ago: request_identities started. SSH <-> FD.
		// First message proving SCdaemon.
		return unhandledMessage, ""

	case send && command == "RESTART":
		// E.g. ssh sign_request ready?
		// SmartCard reset?
		return unhandledMessage, ""

	case command == "OK":
		return ignoredMessage, "" // send / recv.

	case !send && !recv:
		panic("unknown chdir " + chdir)

	default:
		return unhandledMessage, ""
	}
}

func (s *State) scdaemonDebugState(msg string) messageType {
	switch {
	case msg == "check_pcsc_pinpad: command=20, r=27265":
		// Asking for pin.....
		return unhandledMessage

	case msg == "send apdu: c=00 i=2A p1=80 p2=86 lc=513 le=256 em=-254":
		// Decrypt waiting... (GPG, YK touch)
	case msg == "send apdu: c=00 i=2A p1=9E p2=9A lc=83 le=256 em=0":
		// Sign Waiting... (GPG, YK touch)
	case msg == "send apdu: c=00 i=88 p1=00 p2=00 lc=35 le=256 em=0":
		// Auth Waiting... (SSH, YK touch)

	case strings.Contains(msg, "response:"):
		// Response to an apdu.
		// response: sw=???? datalen=???

	case containsOneOf(msg,
		"pcsc_get_status_change:",
		"ccid open error: skip",
		"PCSC_data:",
		"dump:",
		"PCSC_data:",
	):
		return ignoredMessage

	default:
		return unhandledMessage
	}

	return unhandledMessage
}

func containsOneOf(s string, substr ...string) bool {
	for _, ss := range substr {
		if strings.Contains(s, ss) {
			return true
		}
	}
	return false
}

func findProcessByFD(agentPID string, fd string) (p lsof.Process, err error) {
	sl, err := lsof.UnixSockets()
	if err != nil {
		return p, err
	}
	agent := sl.PID(agentPID)
	dev := agent.FD(fd).Device
	if dev == "" {
		return p, errors.New("no device for FD " + fd)
	}

	rp := sl.ProcessConnectedToDevice(dev)
	if rp.PID == "" {
		return p, errors.New("no remote process for FD " + fd)
	}

	return rp, nil
}

type emptyProcess struct{}

func (p *emptyProcess) Pid() int           { return 0 }
func (p *emptyProcess) PPid() int          { return 0 }
func (p *emptyProcess) Executable() string { return "" }

func findProcessByPID(pid string) (*process.Process, error) {
	p, err := strconv.Atoi(pid)
	if err != nil {
		return nil, err
	}
	pp, err := process.NewProcess(int32(p))
	if err != nil {
		return nil, err
	}
	return pp, nil
}

// Process represents a process.
type Process struct {
	ParentPid string
	PID       string
	Name      string
	Cmdline   string
}

func findParentByPID(pid string) Process {
	p := Process{}
	pp, err := findProcessByPID(pid)
	if err != nil {
		fmt.Println("could not fetch parent pid", pid+":", err)
	} else {
		p.PID = pid
		p.Name, _ = pp.Name()
		p.Cmdline, _ = pp.Cmdline()
		ppid, _ := pp.Ppid()
		p.ParentPid = strconv.Itoa(int(ppid))
	}
	return p
}
