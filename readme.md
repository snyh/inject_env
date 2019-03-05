# inject environment

本工具可以使用ptrace动态注入任意环境变量到指定的进程。

初衷是在考虑DDE代理模块时，http_proxy这类代理环境变量无法实时生效，必须注销后才能应用。
原因也很简单，environment这类值默认是在fork/execs时通过继承parent process来获得的。
而DDE下绝大部分进程都是继承自startdde的。 

缓解的方式是通过`dbus-update-activation-environment`这类约定机制来通知环境变量的变动，但
这种方式仅限于少量遵循“协议”的进程。类似游览器、终端等在创建完成后就不再会理会parent process
的环境变量变化。
通过这个方式虽然可以不用注销整个会话了，但还是得重启应用程序才能生效。


另外添加两个相关的小tip：
1. 在查看`/proc/$pid/environ`时，使用`strings`而非`cat`避免换行的问题。
2. `/proc/$pid/environ`只是进程被创建时的值，并不代表实际值。遇到相关bug时一定要指定这个。

# 使用方式

```
snyh-PC% ./inject_env -h
Usage: ./inject_env -p <pid> $key $value
```
指定进程号以及key和value就行了。若权限有问题加上sudo执行。

注意：仅供测试学习使用，生产环境中不要用。

# 原理

原始代码参考: https://github.com/eklitzke/ptrace-call-userspace

大体代码原理是

通过 《动态修改进程代码段（一）》和 《动态修改进程代码段（二）》介绍的原理使用ptrace修改PC的内容来调用我们期望的函数，
并通过修改参数寄存器的方式来传递我们期望的参数。
从而构造了一个基本工具: 执行任意函数的工具(只能执行目标进程已经存在的函数)。
这一步涉及到的几个关键点是
1. 使用`PTRACE_GETREGS`来获取包括PC在内的寄存器值。
2. 使用`PTRACE_SETREGS`来修改PC到指定的任意函数入口，以及修改参数寄存器的内容。
3. 利用PIC的特性，通过计算当前进程的`libc.so`被加载的地址以及`setenv`的地址差，配合目标进程的libc.so被加载的地址从而得到目前进程
   的`setenv`地址。 但要注意，这里假设目前进程有`libc.so`以及版本一致。 有些进程是不满足这个假设的，但如果目标进程没有使用libc.so
   那环境变量这个概念本身也没有准确的定义。

然后利用这个基本工具，就可以调用目标进程内的`setenv`和`unsetenv`函数了。
但这里会遇到一个问题，`setenv`的两个参数都是`char *`，简单的通过`PTRACE_SETREGS`是没法设置的。因此还得再在目标进程里构造
一块内存来存放环境变量的值，然后把这块内存的地址设置到参数寄存器。
这一步涉及到的几个关键点是
1. 使用`PTRACE_POKEx`来修改PC值为`syscall`指令，配合找参数寄存器，来调用`addr=mmap(0, len, prot, flag, -1, 0)`，
2. 然后读取"返回寄存器"的值来获得`addr`的内容，再继续通过`PTRACE_POKEx`来设置`addr`指向的内存内容为期望的环境变量值。
3. 根据`addr`的计算出`key`和`value`的偏移地址，然后传递给`setenv`即可
   
实际上ptrace的接口主要分为
1. 寄存器的读取、修改，主要是`GETREGS`、`SETREGS`，部分平台实现了更高级的`PEEKUSER`、`REGSET`的接口。通过这个可以知道目标进程正在执行的
   函数地址，堆栈地址等等信息。
2. 内存的读取、修改，主要是`POKEx`、`PEEK`，用来读取或设置内存的内容。从而可以配合`SP`值来获取整个call stack，函数内容，全局变量等等内容。
3. `PTRACE_SYSCALL`、`PTRACE_SIGNLESTEP`、`PTRACE_CONT`用来暂停或继续目标进程。

利用这3类接口，配合目标平台的ABI即可"低效"的完成多种多样的功能。
