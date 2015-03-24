#include <sys/types.h>
#include <sys/syscall.h>
#include <cutils/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifdef __cplusplus
extern "C" {
#endif



int seccomp_recvFD(int socket_fd)
{
    int  data;
    struct msghdr msgh;
    struct iovec iov;
    struct cmsghdr* cmhp;
    char control[CMSG_SPACE(sizeof(int))];

    msgh.msg_control = control;
    msgh.msg_controllen = sizeof(control);

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    int ret = recvmsg(socket_fd, &msgh, 0);
    if (ret == -1)
        return -1;

    cmhp = CMSG_FIRSTHDR(&msgh);
    if (cmhp == NULL || cmhp->cmsg_len != CMSG_LEN(sizeof(int)))
        return -1;
    if (cmhp->cmsg_level != SOL_SOCKET)
        return -1;
    if (cmhp->cmsg_type != SCM_RIGHTS)
        return -1;

    int fd;
    fd = *((int *) CMSG_DATA(cmhp));

    return fd;
}



int seccomp_client(const char* filename, int flag, mode_t mode=0)
{

    struct sockaddr_un address;
    int socket_fd;

    struct OpenFile{
        char filename[250];
        int flag;
        mode_t mode;
    };


    struct OpenFile myFile;
    memset(&myFile, 0, sizeof(struct OpenFile));
    strcpy(myFile.filename, filename);
    myFile.flag = flag;
    myFile.mode = mode;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        ALOGE("keystore seccomp_client() socket() failed\n");
        return -1;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./socket");

    int i = 0;

    // if return -8 : this open is not invoked by the request from binder, but from the init code in keystore
    while (connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
        ALOGE("keystore seccomp_client() connect() failed\n");
        //close(socket_fd);
        //return -1;
        sleep(0.000001);
        if(i > 3){
            close(socket_fd);
            return -8;
        }
        i++;
    }

    write(socket_fd, (char *)&myFile, sizeof(struct OpenFile));
    int fd = seccomp_recvFD(socket_fd);

    close(socket_fd);
    return fd;
}


int open(const char *pathname, int flags, ...)
{
    ALOGE("keystore open hook pathname %s %d", pathname, flags);

    mode_t  mode = 0;
    flags |= O_LARGEFILE;

    if (flags & O_CREAT)
    {
        va_list  args;

        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

    int fd;
	
    fd = seccomp_client(pathname, flags, mode);
    if(fd == -8) 
        return syscall(SYS_open, pathname, flags, mode);
    else
        return fd;
}


#ifdef __cplusplus
}
#endif
