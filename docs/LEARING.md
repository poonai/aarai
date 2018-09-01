## Key learing while building this tool.
- I've witnessed, how go managing multiple go routines in one single thread.

- Initial iteration,I have been in situation of using mulptile mutex lock in the program. on the second iteration, I've removed all the locks, then witnessed, how mutex lock slowing down the performance of the system.
So, always keep in mind, concurrent access of shared variable comes with a price, so if you building any high performance system,
avoid locks as much as possible. 

- In socket, sending and reciving data run on the seperate thread, but it still depends on how you implement. for example: rust spawns thread for each connection, but in go-lang, it using n:m ratio, i.e seperate go routine for each connection, where in multiple go routine can be in single thread. 

## os related learning
- process have unique pid, thread also a kind of process but it has the process id as same as parent, it diffrentiated by tid(thread id) since it shraing the memory with the parent process.

## don't why kernal works like this, but I'm noting this findings for further research for the people who willing to work on ebpf.

- `sys_exit_clone` - is called twice, one for the parent pid and for the spawned child pid.
