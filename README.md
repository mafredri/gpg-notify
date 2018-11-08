# gpg-notify

This command line tool (future daemon) watches `gpg-agent` logs and notifies you when a smartcard action is required or what process requested pinentry.

## Status

Super early WIP.

## Installing

```console
$ go get -u github.com/mafredri/gpg-notify
```

## Running

1. Make sure to Enable log file monitoring
2. Run `gpg-notify`
    - Actually `cd $GOPATH/src/github.com/mafredri/gpg-notify && gpg-notify` for now (because images...)
3. Make sure gpg-agent is restarted if it's already running
    - `gpgconf --kill gpg-agent`

## Enable log file monitoring

Modify `~/.gnupg/gpg-agent.conf`:

```
log-file socket:///Users/myuser/.gnupg/S.gpg-agent.log
debug-pinentry
debug 1024
```

## TODO

- Better state handling
- Display more detailed information about the process that invoked pinentry or smartcard
- Daemonize this tool
- Move out notifications into separate project?
- Attribute icons
