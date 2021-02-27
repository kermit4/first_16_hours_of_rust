THIS IS JUST A DEMO OF MY RUST SKILL LEVEL AND LEARNING SPEED, IT IS NOT ACTUALLY VERY USEFUL

I'm attempting to use more Rust features than necessary, as it already works as-is.

I'm actually at 15 hours of Rust now.  The number of lines in the file worklog.txt shows the time spent at that point in the git history.

If run with no args, it will listen for uploads.

With args it will send a file.  

i.e.
```
./udp_uploader &
./udp_uploader /etc/passwd 127.0.0.1:34254
```

should result in a file of the same content named by its sha256
