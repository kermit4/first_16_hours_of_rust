THIS IS JUST A DEMO OF MY RUST SKILL LEVEL, IT IS NOT ACTUALLY VERY USEFUL

Actually at 14 hours of Rust now.  The number of lines in the file worklog.txt shows the time spent at that point in the git history.

If run with no args, it will listen for uploads.

With args it will send a file.  (It does not exit when it's done, and it may stall as there is no timer yet.)

i.e.
```
./udp_uploader &
./udp_uploader /etc/passwd 127.0.0.1:34254
```

should result in a file called "f000.." with the same content

## DONE:
	* retransmission
	* transmission window scaling
## TODO:
	* reduce code duplication and break up long receive() function
