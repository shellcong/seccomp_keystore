# seccomp_keystore

DESCRIPTION

The SeccompKeystore project is an effort to secure the keystore daemon by the seccomp capability system with a few instrumentation. The performance overhead is about 400-500 microseconds for each request. The main contribution of this project is preventing the following attack once an vulnerability in keystore daemon can be exploited.

+++Attack+++: Let us see the following two apps:

App A (uid:10053) sends a request to keystore for generating a key pair (alias: a), which is stored in the path "/data/misc/keystore/user_0/10053_USRCERT_a" and "/data/misc/keystore/user_0/10053_USRPKEY_a".

App B (uid:10054) sends a request to keystore for generating a key pair (alias: b), which is stored in the path "/data/misc/keystore/user_0/10054_USRCERT_b" and "/data/misc/keystore/user_0/10054_USRPKEY_b".

(the permission of these keys are "-rw------- keystore keystore" )

If app A is a malicious app and an arbitrary code execution vulnerability exists in keystore, app A can firstly construct a malicious requests for keystore to trigger this vulnerability, and then get 10054_USRCERT_b key.

This attack breaks the Android data isolation mechanism. In Android, each app can send and store its data in keystore. Even through keystore tries to isolate these data, but it can still fail if keystore itself is vulnerable.

OVERVIEW

Our goal is to strengthen the data isolation for apps in keystore daemon. The general design is forking a new keystore process for each request from the keystore binder, and applying seccomp into the forked child process to restrict system calls.

Workflow of our instrumented seccomp keystore:

1) When a new request message arrives at the keystore BnBinder, keystore forks itself. The child process will go to the original flow of keystore to parse and handle this request. Before the running of the child process, enable the seccomp to stop the "open" system call by seccomp filter in the child process.

2) Hook "open" in child process by LD_PRELOAD. Once an "open" is hooked, our hook library request the parent process for doing "open". So, the parent process must check the filename and flags. If the filename starts with the UID of current app, the parent process does "open" and sends the file descriptor back to the child process by socket.

3) After the child process finishes this request message and gets the return value, it sends the return value to the parent process and then exit.

4) The parent process sends the return value back by Binder.

According to our design, the real keystore working process is the child process and it cannot call any libc "open" functions or direct "open" system call because of the seccomp restriction. All "open" are done in our dispatcher ( parent process) and the filename can be checked according to the UID of requested app. So, this new keystore design with seccomp can prevent the attack described above.

INSTALLATION

1) Modify the init.rc. Add line "setenv LD_PRELOAD /system/lib/libhook.so" in service keystore. 2) replace "/system/bin/keystore", "/system/lib/libkeystore_binder.so" and "/system/lib/libhook.so" with our instrumented version.

HOW TO CONTRIBUTE

My experiment is set on Android-x86-4.4 (http://www.android-x86.org) with 3.18.0 kernel. I have not tested it on other versions or ARM platform. Please give me feedback if you test on other versions or platforms.

You should compile a libseccomp.so together with Android source codes.
