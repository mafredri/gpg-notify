# Notes

- assuan protocol communication is logged as `DBG: chan_X -> COMMAND` (or `<-`, depending on direction)
- Normally `gpg-agent` and `scdaemon` communicate via stdout/stdin, however, when multiple requests are pending `gpg-agent` will open a new socket connection for each
    - This is relevant when we try to detect which `gpg-agent` channel is communicating with which `scdaemon` channel
- When talking to pinentry, `gpg-agent` already sends owner (pid), so this detection can be kept relatively simple
    - Used for informing user what process (or chain of processes) requested pinentry
- We can detect when `gpg` talks to `gpg-agent` since it initiates communication via `"OK Pleased to meet you"`
    - How reliable is this?
    - Maybe we generalize it for any process?
- To figure out what process truly accessed a smart card, we need to (chronological order):
    1. Check what process connected to `gpg-agent` via `lsof` (file descriptors *seem to* map to chan)
    2. Connect the `gpg-agent` chan (X) with `scdaemon` chan (Y) (again, `lsof`)
    3. Agent requests `PK{AUTH,SIGN,DECRYPT}` on chan X
    4. `scdaemon` issues `send apdu: ...` on chan Y
    5. Backtrack: Y -> X -> PID (-> Parent PID)
