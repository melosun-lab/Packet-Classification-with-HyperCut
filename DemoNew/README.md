HyperCuts Version

1. In your shell, run:
   ```bash
   make
   ```

2. We want to send traffic from `h1` to `h2`. If we
capture packets at `h2`.

3. You should now see a Mininet command prompt. Open two terminals
for `h1` and `h2`, respectively:
   ```bash
   mininet> xterm h1 h2
   ```
4. In `h2`'s XTerm, start the server that captures packets:
   ```bash
   ./receive.py
   ```
5. In `h1`'s XTerm, send one packet per second to `h2` using send.py
say for 30 seconds.
   To send UDP:
   ```bash
   ./send.py --p UDP --src 10 --des 0 --m message+1 --sp 3 --dp 2
   ```
   To send TCP:
   ```bash
   ./send.py --p TCP --src 12 --des 14 --m message+3 --sp 2 --dp 1
   ```
   The message should be received in `h2`'s xterm,
6. At `h2`, the `ipv4.tos` field indicates the id of matched rule
7. type `exit` to close each XTerm window

`make` may leave a Mininet instance
running in the background.  Use the following command to clean up
these instances:

```bash
make stop
```
