## Key learning while building this tool.
- I've witnessed, how go-lang managing multiple goroutines in one single thread.

- I have been in a situation of using multiple mutex lock in the program. on the second iteration, I've removed all the locks, then witnessed, how mutex lock slowing down the performance of the system.
So, always keep in mind, concurrent access of shared variable comes with a price, so if you building any high-performance system,
avoid locks as much as possible. 

- In socket, sending and receiving data run on the separate thread, but it still depends on how you implement. for example, rust spawns seperate thread for each connection, but in go-lang, it using n:m ratio, i.e separate goroutine for each connection, wherein multiple goroutines can be in single thread. 

- Test every step you take, otherwise, you'll end up in introducing `print` statement in between.

## don't why kernel works like this, but I'm noting these findings for the people who willing to work on ebpf.

- `sys_exit_clone` - is called twice, one for the parent pid and for the spawned child pid.
