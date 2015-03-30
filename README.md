# seccomp_keystore


===========
1. OVERVIEW

In recent years, a lot of vulnerabilities in Android native daemons have been revealed in AOSP, not to mention OEM customized daemons. A stack buffer overflow vulnerability (CVE-2014-3100) was found in keystore daemon before 4.4 version last year. This vulnerability could be exploited for the arbitrary code execution after bypass the DEP, ASLR and stack cookie. Due to the serious fragmentation problem of Android, there are still many old devices under the threat of this vulnerability now, and more vulnerabilities in Android native daemons will be revealed in the future, especially for OEM daemons. Currently, we are only focusing on the keystore daemon, and will expand it to other vulnerable daemons in the future. 

The threat model: One vulnerability exists in keystore and attackers can exploit this vulnerability to execute arbitrary codes after bypassing the DEP, ASLR and stack cookie protection. Let's see this legitimate app (uid:10053), which sends a request to keystore for generating a key pair (alias: a). The keys are stored in the path "/data/misc/keystore/user_0/10053_USRCERT_a" and "/data/misc/keystore/user_0/10053_USRPKEY_a" (the permission are "-rw------- keystore keystore" ).  Now, attackers can easily write a malicious app, which can send a malformed or overflowed request message to keystore to trigger that vulnerability and execute malicious codes. Then, the malicious app can read the 10053_USRCERT_a key file. In fact, this malicious app is not allowed to read this key file according to the current data isolation mechanism in keystore daemon. But, this mechanism will be nothing once attackers can trigger keystore's  vulnerabilities. 

Even though SEAndroid is applied into Android after version 4.4, the above attack can still not be prevented by SEAndroid. In SEAndroid,  each file and process are labeled, and the file operation is restricted by policies. Obviously, the keystore process is allowed to create/read/write all key files in the "/data/misc/keystore/" directory for each app in SEAndroid policies, even when keystore process has been compromised. The SEAndroid cannot dynamically adjust policies to restrict file operations on different files according to different requested apps. So, this attack can bypass the defense of SEAndroid. 

We propose a new design for keystore daemon, whose capabilities will be restricted strictly by the seccomp mode. For each service request for keystore daemon, we fork a new keystore process. Before the new keystore process executes, the seccomp is enabled to prohibit the "open" system call. So, the new keystore process can only read and write already-opened file descriptors, which are created in the dispatcher process. The dispatcher checks the requesting app when it opens key files. In this defense, even if keystore can be exploited, it can not read or write other apps' data for the current app. 


========
2. DESIGN

Our goal is to strengthen the data isolation protection in keystore daemon. Our general idea is forking a new keystore process to handle each service request from the keystore binder, and applying seccomp into the forked child process to restrict system calls. 

1)  When a new service request arrives at the keystore BnBinder, keystore forks itself. The child process will go to the original flow of keystore to parse and handle this request. Before the running of the child process, seccomp is enabled to prohibit the "open" system call in the child process.

2) Hook "open" in child process by LD_PRELOAD. Once an "open" is hooked, our hook library request the parent process (dispatcher) for doing "open". The dispatcher can check the filename and flags. If the filename starts with the UID of requesting app, the dispatcher finishes "open" and sends the file descriptor back to the child process by socket.  

3) After the child process finishes handling the service request and obtains the return value, it sends the return value to the dispatcher and then exit.

4) The dispatcher sends the return value back by Binder.

According to our design, the real keystore working process is the child process and it cannot call any libc "open" functions or direct "open" system call because of  the seccomp restriction. The "open" is really done in the dispatcher and the filename can be checked according to the UID of requesting app. So, this new keystore design with seccomp can prevent this new attack.


============
3. INSTALLATION
 1) Modify the init.rc. Add line "setenv LD_PRELOAD /system/lib/libhook.so"  in service keystore. 
 2) replace "/system/bin/keystore", "/system/lib/libkeystore_binder.so" and "/system/lib/libhook.so" with our instrumented version. 

You should compile a libseccomp.so together with Android source codes

My experiment is set on Android-x86-4.4 (http://www.android-x86.org) with 3.18.0 kernel. I have not tested it on other versions or ARM platform. Please give me feedback if you test on other versions or platforms.  


===========
4. TEST 
We tested the overhead performance after the instrumentation by writing a demo app ( /keystore/test/demo.apk.tar.gz). In this demo app, we invoke some keystore sdk APIs to send different requests to keystore daemon. After comparing results of the original and our new keystore, the average overhead for each request is about 400-500 microseconds. 


============
5. SUMMARY
An vulnerability can destroy the data isolation protection of keystore daemon. We apply the seccomp mode to restrict the capability of keystore daemon to achieve a strong data isolation protection. 

