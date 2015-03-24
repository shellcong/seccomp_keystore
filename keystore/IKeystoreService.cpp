/*
**
** Copyright 2008, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdint.h>
#include <sys/types.h>

#define LOG_TAG "KeystoreService"
#include <utils/Log.h>

#include <binder/Parcel.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <keystore/IKeystoreService.h>

#include <seccomp.h>
#include <sys/prctl.h>

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <utils/String8.h>
#include <utils/UniquePtr.h>
#include <utils/Vector.h>
#include <cutils/log.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timeb.h>

namespace android {

KeystoreArg::KeystoreArg(const void* data, size_t len)
    : mData(data), mSize(len) {
}

KeystoreArg::~KeystoreArg() {
}

const void *KeystoreArg::data() const {
    return mData;
}

size_t KeystoreArg::size() const {
    return mSize;
}

class BpKeystoreService: public BpInterface<IKeystoreService>
{
public:
    BpKeystoreService(const sp<IBinder>& impl)
        : BpInterface<IKeystoreService>(impl)
    {
    }

    // test ping
    virtual int32_t test()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        status_t status = remote()->transact(BnKeystoreService::TEST, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("test() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("test() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t get(const String16& name, uint8_t** item, size_t* itemLength)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        status_t status = remote()->transact(BnKeystoreService::GET, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("get() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        ssize_t len = reply.readInt32();
        if (len >= 0 && (size_t) len <= reply.dataAvail()) {
            size_t ulen = (size_t) len;
            const void* buf = reply.readInplace(ulen);
            *item = (uint8_t*) malloc(ulen);
            if (*item != NULL) {
                memcpy(*item, buf, ulen);
                *itemLength = ulen;
            } else {
                ALOGE("out of memory allocating output array in get");
                *itemLength = 0;
            }
        } else {
            *itemLength = 0;
        }
        if (err < 0) {
            ALOGD("get() caught exception %d\n", err);
            return -1;
        }
        return 0;
    }

    virtual int32_t insert(const String16& name, const uint8_t* item, size_t itemLength, int uid,
            int32_t flags)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(itemLength);
        void* buf = data.writeInplace(itemLength);
        memcpy(buf, item, itemLength);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::INSERT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t del(const String16& name, int uid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::DEL, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("del() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("del() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t exist(const String16& name, int uid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::EXIST, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("exist() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("exist() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t saw(const String16& name, int uid, Vector<String16>* matches)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::SAW, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("saw() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t numMatches = reply.readInt32();
        for (int32_t i = 0; i < numMatches; i++) {
            matches->push(reply.readString16());
        }
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("saw() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t reset()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        status_t status = remote()->transact(BnKeystoreService::RESET, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("reset() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("reset() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t password(const String16& password)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(password);
        status_t status = remote()->transact(BnKeystoreService::PASSWORD, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("password() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("password() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t lock()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        status_t status = remote()->transact(BnKeystoreService::LOCK, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("lock() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("lock() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t unlock(const String16& password)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(password);
        status_t status = remote()->transact(BnKeystoreService::UNLOCK, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("unlock() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("unlock() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t zero()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        status_t status = remote()->transact(BnKeystoreService::ZERO, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("zero() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("zero() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t generate(const String16& name, int32_t uid, int32_t keyType, int32_t keySize,
            int32_t flags, Vector<sp<KeystoreArg> >* args)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        data.writeInt32(keyType);
        data.writeInt32(keySize);
        data.writeInt32(flags);
        data.writeInt32(args->size());
        for (Vector<sp<KeystoreArg> >::iterator it = args->begin(); it != args->end(); ++it) {
            sp<KeystoreArg> item = *it;
            size_t keyLength = item->size();
            data.writeInt32(keyLength);
            void* buf = data.writeInplace(keyLength);
            memcpy(buf, item->data(), keyLength);
        }
        status_t status = remote()->transact(BnKeystoreService::GENERATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("generate() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("generate() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t import(const String16& name, const uint8_t* key, size_t keyLength, int uid,
            int flags)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(keyLength);
        void* buf = data.writeInplace(keyLength);
        memcpy(buf, key, keyLength);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::IMPORT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t sign(const String16& name, const uint8_t* in, size_t inLength, uint8_t** out,
            size_t* outLength)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(inLength);
        void* buf = data.writeInplace(inLength);
        memcpy(buf, in, inLength);
        status_t status = remote()->transact(BnKeystoreService::SIGN, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        ssize_t len = reply.readInt32();
        if (len >= 0 && (size_t) len <= reply.dataAvail()) {
            size_t ulen = (size_t) len;
            const void* outBuf = reply.readInplace(ulen);
            *out = (uint8_t*) malloc(ulen);
            if (*out != NULL) {
                memcpy((void*) *out, outBuf, ulen);
                *outLength = ulen;
            } else {
                ALOGE("out of memory allocating output array in sign");
                *outLength = 0;
            }
        } else {
            *outLength = 0;
        }
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return -1;
        }
        return 0;
    }

    virtual int32_t verify(const String16& name, const uint8_t* in, size_t inLength,
            const uint8_t* signature, size_t signatureLength)
    {
        Parcel data, reply;
        void* buf;

        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(inLength);
        buf = data.writeInplace(inLength);
        memcpy(buf, in, inLength);
        data.writeInt32(signatureLength);
        buf = data.writeInplace(signatureLength);
        memcpy(buf, signature, signatureLength);
        status_t status = remote()->transact(BnKeystoreService::VERIFY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("verify() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("verify() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t get_pubkey(const String16& name, uint8_t** pubkey, size_t* pubkeyLength)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        status_t status = remote()->transact(BnKeystoreService::GET_PUBKEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("get_pubkey() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        ssize_t len = reply.readInt32();
        if (len >= 0 && (size_t) len <= reply.dataAvail()) {
            size_t ulen = (size_t) len;
            const void* buf = reply.readInplace(ulen);
            *pubkey = (uint8_t*) malloc(ulen);
            if (*pubkey != NULL) {
                memcpy(*pubkey, buf, ulen);
                *pubkeyLength = ulen;
            } else {
                ALOGE("out of memory allocating output array in get_pubkey");
                *pubkeyLength = 0;
            }
        } else {
            *pubkeyLength = 0;
        }
        if (err < 0) {
            ALOGD("get_pubkey() caught exception %d\n", err);
            return -1;
        }
        return 0;
     }

    virtual int32_t del_key(const String16& name, int uid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::DEL_KEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("del_key() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("del_key() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t grant(const String16& name, int32_t granteeUid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(granteeUid);
        status_t status = remote()->transact(BnKeystoreService::GRANT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("grant() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("grant() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t ungrant(const String16& name, int32_t granteeUid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(granteeUid);
        status_t status = remote()->transact(BnKeystoreService::UNGRANT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("ungrant() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("ungrant() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    int64_t getmtime(const String16& name)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        status_t status = remote()->transact(BnKeystoreService::GETMTIME, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("getmtime() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int64_t ret = reply.readInt64();
        if (err < 0) {
            ALOGD("getmtime() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t duplicate(const String16& srcKey, int32_t srcUid, const String16& destKey,
            int32_t destUid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(srcKey);
        data.writeInt32(srcUid);
        data.writeString16(destKey);
        data.writeInt32(destUid);
        status_t status = remote()->transact(BnKeystoreService::DUPLICATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("duplicate() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("duplicate() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t is_hardware_backed(const String16& keyType)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(keyType);
        status_t status = remote()->transact(BnKeystoreService::IS_HARDWARE_BACKED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("is_hardware_backed() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("is_hardware_backed() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t clear_uid(int64_t uid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt64(uid);
        status_t status = remote()->transact(BnKeystoreService::CLEAR_UID, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("clear_uid() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("clear_uid() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }
};

IMPLEMENT_META_INTERFACE(KeystoreService, "android.security.keystore");

// ----------------------------------------------------------------------

struct appuid{
int uid;
String8 keynames[100];
} uid2keyname[100];



size_t encode_key_length(const android::String8& keyName) {
    const uint8_t* in = reinterpret_cast<const uint8_t*>(keyName.string());
    size_t length = keyName.length();
    for (int i = length; i > 0; --i, ++in) {
        if (*in < '0' || *in > '~') {
            ++length;
        }
    }
    return length;
}

int encode_key(char* out, const android::String8& keyName) {
    const uint8_t* in = reinterpret_cast<const uint8_t*>(keyName.string());
    size_t length = keyName.length();
    for (int i = length; i > 0; --i, ++in, ++out) {
        if (*in < '0' || *in > '~') {
            *out = '+' + (*in >> 6);
            *++out = '0' + (*in & 0x3F);
            ++length;
        } else {
            *out = *in;
        }
    }
    *out = '\0';
    return length;
}


String8  check(int uid, String16 alias)
{

	struct appuid app;
	size_t i;	
	for (i = 0; i < sizeof(uid2keyname)/sizeof(uid2keyname[0]); i++){
		app = uid2keyname[i];
		if (app.uid == uid) 
			return app.keynames[0];	
		
		if (app.uid == 0)
			break;
	} 

	String8 alias2(alias);

	char encoded[encode_key_length(alias2) + 1];   // add 1 for null char
    encode_key(encoded, alias2);

	String8 usrpkey = android::String8::format("%d_%s", uid, encoded);

	ALOGE("CONGZHENG:   KEY  %s", usrpkey.string());

	uid2keyname[0] = appuid();
	uid2keyname[0].uid = uid;
	uid2keyname[0].keynames[0] = usrpkey;	 
	return usrpkey;
}




int seccomp_sendFD(int socket_fd, int send_fd)
{
    int ret;
    struct msghdr msg;
    struct cmsghdr *p_cmsg;
    struct iovec vec;
    char cmsgbuf[CMSG_SPACE(sizeof(send_fd))];
    int *p_fds;
    char sendchar = 0;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    p_cmsg = CMSG_FIRSTHDR(&msg);
    p_cmsg->cmsg_level = SOL_SOCKET;
    p_cmsg->cmsg_type = SCM_RIGHTS;
    p_cmsg->cmsg_len = CMSG_LEN(sizeof(send_fd));
    p_fds = (int *)CMSG_DATA(p_cmsg);
    *p_fds = send_fd;
     
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
     
    vec.iov_base = &sendchar;
    vec.iov_len = sizeof(sendchar);
    ret = sendmsg(socket_fd, &msg, 0);
    if (ret != 1)
		return -1;
	
	return ret;
}


int seccomp_server()
{
	struct sockaddr_un address;
	int socket_fd, connection_fd;

	struct OpenFile{
		char filename[250];
		int flag;
		mode_t mode;
	};
	
	unlink("./socket");
	memset(&address, 0, sizeof(struct sockaddr_un));

	struct OpenFile myFile;
	memset(&myFile, 0, sizeof(struct OpenFile));

	socklen_t address_length;

	socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(socket_fd < 0){
		ALOGE("keystore seccomp_server() socket() failed\n");
		return -1;
	}
	
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, "./socket");
	address_length = sizeof((struct sockaddr *)&address); 

	if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
		ALOGE("keystore seccomp_server() bind() failed\n");
		return -1;
	}

	if(listen(socket_fd, 5) == -1) {
		ALOGE("keystore seccomp_server() listen() failed\n");
		return -1;
	}

	// continue to recv the socket request until getting the filename "CONGZHENG"
	while(true) {

		if ((connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length)) == -1){
			ALOGE("keystore seccomp_server() accept() failed\n");
			return -1;
		}

		read(connection_fd, (char *)&myFile, sizeof(struct OpenFile));
	
		// now, we get the filename, flag and mode from the child process
		if (strcmp(myFile.filename, "CONGZHENG") == 0) {
			close(connection_fd);
			break;	
		}

		int fd;
		if(myFile.mode == 0)
			fd = TEMP_FAILURE_RETRY(syscall(SYS_open, myFile.filename, myFile.flag));
		else
			fd = TEMP_FAILURE_RETRY(syscall(SYS_open, myFile.filename, myFile.flag, myFile.mode));

		int ret = seccomp_sendFD(connection_fd, fd);

		if(ret == -1 )
			ALOGE("keystore seccomp_sendFD() failed\n");

		close(connection_fd);		
	}

	close(socket_fd);
	return 0;
}



int seccomp_disconnect()
{

    struct sockaddr_un address;
    int socket_fd;

    struct OpenFile{
        char filename[250];
        int flag;
        mode_t mode;
    };

	const char * filename = "CONGZHENG";
    struct OpenFile myFile;
    memset(&myFile, 0, sizeof(struct OpenFile));
    strcpy(myFile.filename, filename);
    myFile.flag = 0;
    myFile.mode = 0;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        ALOGE("keystore seccomp_disconnect() socket() failed\n");
        return -1;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./socket");

    int i = 0;
    while (connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
        ALOGE("keystore seccomp_disconnect() connect() failed\n");
        sleep(0.001);
        if(i > 3){
            close(socket_fd);
            return -1;
        }
        i++;
    }

    write(socket_fd, (char *)&myFile, sizeof(struct OpenFile));

    close(socket_fd);
	return 0; 
}

int seccomp_sendRet0(uint8_t * out, size_t outSize, int32_t ret)
{
    struct sockaddr_un address;
    int socket_fd;

    struct RET{
       	uint8_t out[1000];
        size_t outSize;
        int32_t ret;
    };

    struct RET myRet;

    memset(myRet.out, 0, sizeof(myRet.out));
    memcpy(myRet.out, out , outSize);
	myRet.outSize = outSize;
    myRet.ret = ret;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        ALOGE("keystore seccomp_sendRet socket() failed\n");
        return -1;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");

    while(connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
		sleep(0.001);
    }

    write(socket_fd, (char *)&myRet, sizeof(struct RET));

    close(socket_fd);
    return 1;
}



int seccomp_sendRet1(unsigned char * out, size_t outSize, int32_t ret)
{
	struct sockaddr_un address;
	int socket_fd;

	struct RET{
		unsigned char out[1000];
       	size_t outSize;
		int32_t ret;
	};

	struct RET myRet;
	
	memset(&myRet.out, 0, sizeof(outSize));	
	memcpy(myRet.out, out , outSize);
	myRet.outSize = outSize;
	myRet.ret = ret;

	socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        ALOGE("keystore seccomp_sendRet socket() failed\n");
        return -1;
    }

	memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
	strcpy(address.sun_path, "./demo_socket3");

    while (connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
		sleep(0.001);
    }
    
	write(socket_fd, (char *)&myRet, sizeof(myRet));

	close(socket_fd);
	return 1;
}


int seccomp_sendRet2(int32_t ret)
{
    struct sockaddr_un address;
    int socket_fd;

    struct RET{
        int32_t ret;
    };

    struct RET myRet;

    myRet.ret = ret;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        ALOGE("keystore seccomp_sendRet socket() failed\n");
        return -1;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");

    while (connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
		sleep(0.001);
    }

    write(socket_fd, (char *)&myRet, sizeof(myRet));

    close(socket_fd);
    return 1;
}

int seccomp_sendRet3(Vector<String16> matches, int32_t ret)
{
	struct sockaddr_un address;
    int socket_fd;

	struct RET{
		Vector<String16> matches;
		int32_t ret;
	};

	struct RET myRet;

	Vector<String16>::const_iterator it = matches.begin();
	for(; it != matches.end(); it++) {
		myRet.matches.push(*it);
	}	
	
	myRet.ret = ret;	

	socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        ALOGE("keystore seccomp_sendRet socket() failed\n");
        return -1;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");

    while (connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
		sleep(0.001);
    }

    write(socket_fd, (char *)&myRet, sizeof(myRet));

    close(socket_fd);
    return 1;
	
} 

int seccomp_sendRet4(int64_t ret)
{
    struct sockaddr_un address;
    int socket_fd;

    struct RET{
        int64_t ret;
    };

    struct RET myRet;
    myRet.ret = ret;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        ALOGE("keystore seccomp_sendRet socket() failed\n");
        return -1;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");

    while (connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
		sleep(0.001);
    }

    write(socket_fd, (char *)&myRet, sizeof(myRet));

    close(socket_fd);
    return 1;
}



int seccomp_recvRet0(uint8_t** out, size_t * outSize, int32_t * ret)
{
    struct sockaddr_un address;
    int socket_fd, connection_fd;

    struct RET{
        uint8_t out[1000];
        size_t outSize;
        int32_t ret;
    };

    struct RET myRet;
    memset(myRet.out, 0, sizeof(myRet.out));
    socklen_t address_length;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0){
        ALOGE("keystore seccomp_recvRet socket() failed\n");
        return -1;
    }

    unlink("./demo_socket3");
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");
	address_length = sizeof((struct sockaddr *)&address);


    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
        ALOGE("keystore seccomp_recvRet bind() failed\n");
        return -1;
    }

    if(listen(socket_fd, 5) != 0) {
        ALOGE("keystore recvRet listen() failed\n");
        return -1;
    }

    if((connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length)) > -1){
        read(connection_fd, (char *)&myRet, sizeof(struct RET));
        close(connection_fd);
    }

    close(socket_fd);

    uint8_t * p = (uint8_t *) malloc( myRet.outSize * sizeof(uint8_t));
    memcpy(p, myRet.out, myRet.outSize );
    *out = p;
    *outSize = myRet.outSize;
    *ret = myRet.ret;

    return 1;
}


int seccomp_recvRet1(unsigned char ** out, size_t * outSize, int32_t * ret)
{
	struct sockaddr_un address;
    int socket_fd, connection_fd;

	struct RET{
		unsigned char out[1000];
		size_t outSize;
		int32_t ret;
	};

	struct RET myRet;
	memset(myRet.out, 0, sizeof(myRet.out));

    socklen_t address_length;

   	socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0){
        ALOGE("keystore seccomp_recvRet socket() failed\n");
        return -1;
    }

	unlink("./demo_socket3");
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");
	address_length = sizeof((struct sockaddr *)&address);

    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
        ALOGE("keystore seccomp_recvRet bind() failed\n");
        return -1;
    }

    if(listen(socket_fd, 5) != 0) {
        ALOGE("keystore recvRet listen() failed\n");
        return -1;
    }

    if((connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length))> -1){
        read(connection_fd, (char *)&myRet, sizeof(struct RET));
        close(connection_fd);
    }

	close(socket_fd);

	unsigned char * p = (unsigned char *) malloc( myRet.outSize * sizeof(unsigned char));	
	memcpy(p, myRet.out, myRet.outSize );
	*out = p;
	*outSize = myRet.outSize;
	*ret = myRet.ret;	
	
	return 1;	
}



int seccomp_recvRet2(int32_t* ret)
{

    struct sockaddr_un address;
    int socket_fd, connection_fd;

    struct RET{
        int32_t ret;
    };

    struct RET myRet;

    socklen_t address_length;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0){
        ALOGE("keystore seccomp_recvRet socket() failed\n");
        return -1;
    }

    unlink("./demo_socket3");
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");
	address_length = sizeof((struct sockaddr *)&address);

    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
        ALOGE("keystore seccomp_recvRet bind() failed\n");
        return -1;
    }

    if(listen(socket_fd, 5) != 0) {
        ALOGE("keystore recvRet listen() failed\n");
        return -1;
    }

    connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length);

    if(connection_fd > -1){
        read(connection_fd, (char *)&myRet, sizeof(struct RET));
        close(connection_fd);
    }

    close(socket_fd);

    *ret = myRet.ret;

    return 1;
}


int seccomp_recvRet3(Vector<String16>* matches, int32_t* ret)
{
    struct sockaddr_un address;
    int socket_fd, connection_fd;

	struct RET{
        Vector<String16> matches;
        int32_t ret;
    };

    struct RET myRet;

	socklen_t address_length;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0){
        ALOGE("keystore seccomp_recvRet socket() failed\n");
        return -1;
    }

    unlink("./demo_socket3");
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");

    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
        ALOGE("keystore seccomp_recvRet bind() failed\n");
        return -1;
    }

    if(listen(socket_fd, 5) != 0) {
        ALOGE("keystore recvRet listen() failed\n");
        return -1;
    }

    if((connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length)) > -1){
        read(connection_fd, (char *)&myRet, sizeof(struct RET));
        close(connection_fd);
    }

   close(socket_fd);

   Vector<String16>::const_iterator it = myRet.matches.begin();
    for(; it != myRet.matches.end(); it++) {
       	(*matches).push(*it);
    }

    *ret = myRet.ret;
	
	return 1;
}


int seccomp_recvRet4(int64_t* ret)
{
    struct sockaddr_un address;
    int socket_fd, connection_fd;

    struct RET{
        int64_t ret;
    };

    struct RET myRet;

    socklen_t address_length;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0){
        ALOGE("keystore seccomp_recvRet socket() failed\n");
        return -1;
    }

    unlink("./demo_socket3");
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket3");
	address_length = sizeof((struct sockaddr *)&address);

    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
        ALOGE("keystore seccomp_recvRet bind() failed\n");
        return -1;
    }

    if(listen(socket_fd, 5) != 0) {
        ALOGE("keystore recvRet listen() failed\n");
        return -1;
    }

    if((connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length)) > -1){
        read(connection_fd, (char *)&myRet, sizeof(struct RET));
        close(connection_fd);
    }

    close(socket_fd);

    *ret = myRet.ret;

    return 1;
}



int32_t BnKeystoreService::seccomp_TEST()
{
	int32_t ret = -1;
	pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
        
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		


		int32_t retcode = test();
        ALOGE("%d", retcode);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
		if (retcode2 == -1)
			ALOGE("keystore sendRet failed");
        // exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int32_t retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
	return ret;
}



int32_t BnKeystoreService::seccomp_GET(const String16& name, uint8_t** out, size_t* outSize)
{
	int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = get(name, out, outSize);
        ALOGE("%d", retcode);
		
		seccomp_disconnect();

        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet0(*out, *outSize, retcode);
	        
		if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet0(out, outSize, &ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
	return ret;
} 


int32_t BnKeystoreService::seccomp_INSERT(const String16& name, const uint8_t* in, size_t inSize, int uid, int32_t flags)
{
    int32_t ret = -1;

    uint8_t* mydata = (uint8_t *) malloc ( sizeof(uint8_t) * inSize);
    memcpy(mydata, in, inSize);

    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
	
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = insert(name, mydata, inSize, uid, flags);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);

		if (retcode2 == -1)
			ALOGE("keystore send ret failed");	
        // exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}


int32_t BnKeystoreService::seccomp_DEL(const String16& name, int uid)
{

	int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

        int32_t retcode = del(name, uid);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        
		if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET successfully");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

int32_t BnKeystoreService::seccomp_EXIST(const String16& name, int uid)
{
   int32_t ret = -1;
	struct timeval a1, a2, a3, a4, a5, a6, a7, a8;
	struct timeval b1, b2;
	gettimeofday(&a1, NULL);
    pid_t pid = fork();
	gettimeofday(&a2, NULL);

	ALOGE("time EXIST1: %lu", a2.tv_usec - a1.tv_usec);
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		gettimeofday(&b1, NULL);
		int32_t retcode = exist(name, uid);
		gettimeofday(&b2, NULL);
		ALOGE("time EXIST child : %lu", b2.tv_usec - b1.tv_usec);

		seccomp_disconnect();		

        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
		gettimeofday(&a3, NULL);
        // wait for client to request the file descriptor
        int retcode = seccomp_server();
		gettimeofday(&a4, NULL);
		ALOGE("time EXIST2: %lu", a4.tv_usec - a3.tv_usec);		

		gettimeofday(&a5, NULL);
        // get the return value
        retcode = seccomp_recvRet2(&ret);

		gettimeofday(&a6, NULL);
		ALOGE("time EXIST3: %lu", a6.tv_usec - a5.tv_usec);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");
        
		// wait the return of child process
        int status;
		gettimeofday(&a7, NULL);
        waitpid(pid, &status, 0 );
		gettimeofday(&a8, NULL);
		ALOGE("time EXIST4: %lu", a8.tv_usec - a7.tv_usec);
    }
    return ret;
}


int32_t BnKeystoreService::seccomp_SAW(const String16& name, int uid, Vector<String16>* matches)
{

	int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

        int32_t retcode = saw(name, uid, matches);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet3(*matches, retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet3(matches, &ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;

}


int32_t BnKeystoreService::seccomp_RESET()
{
	int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = reset();
		
		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }	
	return ret;
}


int32_t BnKeystoreService::seccomp_PASSWORD(const String16& pass)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = password(pass);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");
        
		// wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}



int32_t BnKeystoreService::seccomp_LOCK()
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
    
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

	    int32_t retcode = lock();

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");
        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}


int32_t BnKeystoreService::seccomp_UNLOCK(const String16& password)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
        
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = unlock(password);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

int32_t BnKeystoreService::seccomp_ZERO()
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
        
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = zero();

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");
        
		// wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

int32_t BnKeystoreService::seccomp_GENERATE(const String16& name, int32_t uid, int32_t keyType, int32_t keySize, int32_t flags, Vector<sp<KeystoreArg> >* args)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
        
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);
		
		int32_t retcode = generate(name, uid, keyType, keySize, flags, args);

		seccomp_disconnect();			

        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode;
	
		retcode = seccomp_server();
        
		// get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");
        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

int32_t BnKeystoreService::seccomp_IMPORT(const String16& name, const uint8_t* data, size_t length, int uid, int32_t flags)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = import(name, data, length, uid, flags);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;

}



int32_t BnKeystoreService::seccomp_SIGN(const String16& name, const uint8_t* data, size_t length, uint8_t** out, size_t* outLength)
{
    int32_t ret = -1;
	// *** BUG ***
	uint8_t* mydata = (uint8_t *) malloc ( sizeof(uint8_t) * length);
	memcpy(mydata, data, length);

    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

        int32_t retcode = sign(name, mydata, length, out, outLength);

		seccomp_disconnect();
        // send back ret,  out, outsize to server

        int retcode2 = seccomp_sendRet0(*out, *outLength, retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet0(out, outLength, &ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}



int32_t BnKeystoreService::seccomp_VERIFY(const String16& name, const uint8_t* data, size_t dataLength, const uint8_t* signature, size_t signatureLength)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = verify(name, data, dataLength, signature, signatureLength);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}



int32_t BnKeystoreService::seccomp_GET_PUBKEY(const String16& name, unsigned char ** out, size_t * outSize)
{
	int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
		ALOGE("keystore fork error");
    }else if (pid == 0){
		
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = get_pubkey(name, out, outSize);
        
		seccomp_disconnect();
		// send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet1(*out, *outSize, retcode);
      	if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
	}else{
		// wait for client to request the file descriptor
		int retcode = seccomp_server();

		if (retcode == -1)
			ALOGE("keystore send the file descriptor failed");

		// get the return value
		retcode = seccomp_recvRet1(out, outSize, &ret);

		if(retcode == -1)
			ALOGE("keystore  recv the RET failed");

		// wait the return of child process
		int status;
        waitpid(pid, &status, 0 );
    }
	return ret;
}


int32_t BnKeystoreService::seccomp_DEL_KEY(const String16& name, int uid)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);

        int32_t retcode = del_key(name, uid);
		
		seccomp_disconnect();

        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

int32_t BnKeystoreService::seccomp_GRANT(const String16& name, int32_t granteeUid)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
        
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = grant(name, granteeUid);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

int32_t BnKeystoreService::seccomp_UNGRANT(const String16& name, int32_t granteeUid)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
        
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = ungrant(name, granteeUid);
        ALOGE("%d", retcode);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
		if (retcode2 == -1)
			ALOGE("keystore send ret failed");
        // exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

int64_t BnKeystoreService::seccomp_GETMTIME(const String16& name)
{
	int64_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){

		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int64_t retcode = getmtime(name);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet4(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet4(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}


int32_t BnKeystoreService::seccomp_DUPLICATE(const String16& srcKey, int32_t srcUid, const String16& destKey, int32_t destUid)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
        
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = duplicate(srcKey, srcUid, destKey, destUid);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

int32_t BnKeystoreService::seccomp_IS_HARDWARE_BACKED(const String16& keyType)
{   
	int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
        
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

		int32_t retcode = is_hardware_backed(keyType);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");

        // wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}


int32_t BnKeystoreService::seccomp_CLEAR_UID(int64_t uid)
{
    int32_t ret = -1;
    pid_t pid = fork();
    if (pid == -1){
        ALOGE("keystore fork error");
    }else if (pid == 0){
    
		scmp_filter_ctx ctx;
		ctx = seccomp_init(SCMP_ACT_ALLOW);
		seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
		seccomp_load(ctx);		

	    int32_t retcode = clear_uid(uid);

		seccomp_disconnect();
        // send back ret,  out, outsize to server
        int retcode2 = seccomp_sendRet2(retcode);
        if (retcode2 == -1)
			ALOGE("keystore send ret failed");
		// exit the child process
        _exit(0);
    }else{
        // wait for client to request the file descriptor
        int retcode = seccomp_server();

        if (retcode == -1)
            ALOGE("keystore send the file descriptor failed");

        // get the return value
        retcode = seccomp_recvRet2(&ret);

        if(retcode == -1)
            ALOGE("keystore  recv the RET failed");
        
		// wait the return of child process
        int status;
        waitpid(pid, &status, 0 );
    }
    return ret;
}

status_t BnKeystoreService::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{

	struct timeval stop, start;
	gettimeofday(&start, NULL);
	
	uid_t callingUid = IPCThreadState::self()->getCallingUid();
	ALOGE("CONGZHENG: CALL UID: %d  Code: %d\n", callingUid, code);
	
	//gettimeofday(&stop, NULL);
	//ALOGE("time %lu", stop.tv_usec - start.tv_usec);

	//prctl(PR_SET_NO_NEW_PRIVS, 1);
	//prctl(PR_SET_DUMPABLE, 0);	

	//scmp_filter_ctx ctx;
	//ctx = seccomp_init(SCMP_ACT_ALLOW);

	
	//10053_USRCERT_bb   10053_USRPKEY_bb

			
	//seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 2, SCMP_A0(SCMP_CMP_NE, CERT);
	//seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 2, SCMP_A0(SCMP_CMP_NE, PKEY);

	
	//if(callingUid > 10000) {
	//	seccomp.load(ctx);

	//}

    switch(code) {
        case TEST: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            int32_t ret = test();
            //int32_t ret = seccomp_TEST();
			reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("TEST time %lu", stop.tv_usec - start.tv_usec);
            return NO_ERROR;
        } break;
        case GET: {
			ALOGE("CONGZHENG %s  %d\n", "GET", code);
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            void* out = NULL;
            size_t outSize = 0;
            int32_t ret;
			//if(callingUid <= 1000)
			//	ret = get(name, (uint8_t**) &out, &outSize);
			//else
			ret = seccomp_GET(name, (uint8_t**) &out, &outSize);
			reply->writeNoException();
            if (ret == 1) {
                reply->writeInt32(outSize);
                void* buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                free(out);
            } else {
                reply->writeInt32(-1);
            }
			reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("GET time %lu", stop.tv_usec - start.tv_usec);

            return NO_ERROR;
        } break;
        case INSERT: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            ssize_t inSize = data.readInt32();
            const void* in;
            if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                in = data.readInplace(inSize);
            } else {
                in = NULL;
                inSize = 0;
            }
            int uid = data.readInt32();
            int32_t flags = data.readInt32();
            //int32_t ret = insert(name, (const uint8_t*) in, (size_t) inSize, uid, flags);
            int32_t ret = seccomp_INSERT(name, (const uint8_t*) in, (size_t) inSize, uid, flags); 
			reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("INSERT time %lu", stop.tv_usec - start.tv_usec);

			return NO_ERROR;
        } break;
        case DEL: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int uid = data.readInt32();
            //int32_t ret = del(name, uid);
			int32_t ret = seccomp_DEL(name, uid);
            reply->writeNoException();
			reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("DEL time %lu", stop.tv_usec - start.tv_usec);

            return NO_ERROR;
        } break;
        case EXIST: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int uid = data.readInt32();
            //int32_t ret = exist(name, uid);
			int32_t ret = seccomp_EXIST(name, uid);
            reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("EXIST time %lu", stop.tv_usec - start.tv_usec);

            return NO_ERROR;
        } break;
        case SAW: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int uid = data.readInt32();
            Vector<String16> matches;
            //int32_t ret = saw(name, uid, &matches);
			int32_t ret = seccomp_SAW(name, uid, &matches);		
            reply->writeNoException();
            reply->writeInt32(matches.size());
            Vector<String16>::const_iterator it = matches.begin();
            for (; it != matches.end(); ++it) {
                reply->writeString16(*it);
            }
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("SAW time %lu", stop.tv_usec - start.tv_usec);

			return NO_ERROR;
        } break;
        case RESET: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            //int32_t ret = reset();
            int32_t ret = seccomp_RESET();
			reply->writeNoException();
			reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("RESET time %lu", stop.tv_usec - start.tv_usec);

            return NO_ERROR;
        } break;
        case PASSWORD: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 pass = data.readString16();
            //int32_t ret = password(pass);
            int32_t ret = seccomp_PASSWORD(pass);
			reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("TEST time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case LOCK: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            //int32_t ret = lock();
			int32_t ret = seccomp_LOCK();
            reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("LOCK time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case UNLOCK: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 pass = data.readString16();
            //int32_t ret = unlock(pass); 
            int32_t ret = seccomp_UNLOCK(pass);
			reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("UNLOCK time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case ZERO: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            //int32_t ret = zero(); 
            int32_t ret = seccomp_ZERO();
			reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("ZERO time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case GENERATE: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int32_t uid = data.readInt32();
            int32_t keyType = data.readInt32();
            int32_t keySize = data.readInt32();
            int32_t flags = data.readInt32();
            Vector<sp<KeystoreArg> > args;
            ssize_t numArgs = data.readInt32();
            if (numArgs > 0) {
                for (size_t i = 0; i < (size_t) numArgs; i++) {
                    ssize_t inSize = data.readInt32();
                    if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                        sp<KeystoreArg> arg = new KeystoreArg(data.readInplace(inSize), inSize);
                        args.push_back(arg);
                    } else {
                        args.push_back(NULL);
                    }
                }
            }	
            //int32_t ret = generate(name, uid, keyType, keySize, flags, &args);
            int32_t ret = seccomp_GENERATE(name, uid, keyType, keySize, flags, &args);
            reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("GENERATE time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case IMPORT: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            ssize_t inSize = data.readInt32();
            const void* in;
            if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                in = data.readInplace(inSize);
            } else {
                in = NULL;
                inSize = 0;
            }
            int uid = data.readInt32();
            int32_t flags = data.readInt32();
            //int32_t ret = import(name, (const uint8_t*) in, (size_t) inSize, uid, flags);
            int32_t ret = seccomp_IMPORT(name, (const uint8_t*) in, (size_t) inSize, uid, flags);
			reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("IMPORT time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case SIGN: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            ssize_t inSize = data.readInt32();
            const void* in;
            if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                in = data.readInplace(inSize);
            } else {
                in = NULL;
                inSize = 0;
            }
            void* out = NULL;
            size_t outSize = 0;

			int32_t ret = seccomp_SIGN(name, (const uint8_t*) in, (size_t) inSize, (uint8_t**) &out, &outSize);
			reply->writeNoException();
            if (outSize > 0 && out != NULL) {
                reply->writeInt32(outSize);
                void* buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                free(out);
            } else {
                reply->writeInt32(-1);
            }
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("SIGN time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case VERIFY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            ssize_t inSize = data.readInt32();
            const void* in;
            if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                in = data.readInplace(inSize);
            } else {
                in = NULL;
                inSize = 0;
            }
            ssize_t sigSize = data.readInt32();
            const void* sig;
            if (sigSize >= 0 && (size_t) sigSize <= data.dataAvail()) {
                sig = data.readInplace(sigSize);
            } else {
                sig = NULL;
                sigSize = 0;
            }
            
			bool ret = seccomp_VERIFY(name, (const uint8_t*) in, (size_t) inSize, (const uint8_t*) sig, (size_t) sigSize);

            reply->writeNoException();
            reply->writeInt32(ret ? 1 : 0);
			gettimeofday(&stop, NULL);
			ALOGE("SIGN time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case GET_PUBKEY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            void* out = NULL;
            size_t outSize = 0;

			int32_t ret = seccomp_GET_PUBKEY(name, (unsigned char **) &out, &outSize);
        	//int32_t ret = get_pubkey(name, (unsigned char**) &out, &outSize);		
	
            reply->writeNoException();
            if (outSize > 0 && out != NULL) {
                reply->writeInt32(outSize);
                void* buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                free(out);
            } else {
                reply->writeInt32(-1);
            }
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("GET_PUBKEY time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case DEL_KEY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int uid = data.readInt32();
            //int32_t ret = del_key(name, uid);
            int32_t ret = seccomp_DEL_KEY(name, uid);
			reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("DEL_KEY time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case GRANT: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int32_t granteeUid = data.readInt32();
            //int32_t ret = grant(name, granteeUid);
            int32_t ret = seccomp_GRANT(name, granteeUid);
			reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("GRANT time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case UNGRANT: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int32_t granteeUid = data.readInt32();
            //int32_t ret = ungrant(name, granteeUid);
            int32_t ret = seccomp_UNGRANT(name, granteeUid);
            reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("UNGRANT time %lu", stop.tv_usec - start.tv_usec);
		
            return NO_ERROR;
        } break;
        case GETMTIME: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int64_t ret = seccomp_GETMTIME(name);
 			//int64_t ret = getmtime(name);
            reply->writeNoException();
            reply->writeInt64(ret);
			gettimeofday(&stop, NULL);
			ALOGE("GETMTIME time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        } break;
        case DUPLICATE: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 srcKey = data.readString16();
            int32_t srcUid = data.readInt32();
            String16 destKey = data.readString16();
            int32_t destUid = data.readInt32();
            //int32_t ret = duplicate(srcKey, srcUid, destKey, destUid);
            int32_t ret = seccomp_DUPLICATE(srcKey, srcUid, destKey, destUid);
            reply->writeNoException();
            reply->writeInt32(ret);
            gettimeofday(&stop, NULL);
			ALOGE("DUPLICATE time %lu", stop.tv_usec - start.tv_usec);
	
			return NO_ERROR;
        } break;
        case IS_HARDWARE_BACKED: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 keyType = data.readString16();
            //int32_t ret = is_hardware_backed(keyType);
            int32_t ret = seccomp_IS_HARDWARE_BACKED(keyType);
            reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("IS_HARDWARE_BACKED time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        }
        case CLEAR_UID: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            int64_t uid = data.readInt64();
            //int32_t ret = clear_uid(uid);
            int32_t ret = seccomp_CLEAR_UID(uid);
            reply->writeNoException();
            reply->writeInt32(ret);
			gettimeofday(&stop, NULL);
			ALOGE("CLEAR_UID time %lu", stop.tv_usec - start.tv_usec);
	
            return NO_ERROR;
        }
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

// ----------------------------------------------------------------------------

}; // namespace android
