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



#include <sys/un.h>
#include <unistd.h>
#include <string.h>



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

	//String8 usrcert = android::String8::format("%u%s", uid,  

	ALOGE("CONGZHENG:   KEY  %s", usrpkey.string());

	uid2keyname[0] = appuid();
	uid2keyname[0].uid = uid;
	uid2keyname[0].keynames[0] = usrpkey;	 
	return usrpkey;
}




int send_fd(int socket, int fd_to_send)
{
	struct msghdr socket_message;
  	struct iovec io_vector[1];
  	struct cmsghdr *control_message = NULL;
  	char message_buffer[1];
  	/* storage space needed for an ancillary element with a paylod of length is CMSG_SPACE(sizeof(length)) */
  	char ancillary_element_buffer[CMSG_SPACE(sizeof(int))];
  	int available_ancillary_element_buffer_space;

  	/* at least one vector of one byte must be sent */
  	message_buffer[0] = 'F';
  	io_vector[0].iov_base = message_buffer;
  	io_vector[0].iov_len = 1;

  	/* initialize socket message */
  	memset(&socket_message, 0, sizeof(struct msghdr));
  	socket_message.msg_iov = io_vector;
  	socket_message.msg_iovlen = 1;

  	/* provide space for the ancillary data */
  	available_ancillary_element_buffer_space = CMSG_SPACE(sizeof(int));
  	memset(ancillary_element_buffer, 0, available_ancillary_element_buffer_space);
  	socket_message.msg_control = ancillary_element_buffer;
  	socket_message.msg_controllen = available_ancillary_element_buffer_space;

  	/* initialize a single ancillary data element for fd passing */
  	control_message = CMSG_FIRSTHDR(&socket_message);
  	control_message->cmsg_level = SOL_SOCKET;
  	control_message->cmsg_type = SCM_RIGHTS;
  	control_message->cmsg_len = CMSG_LEN(sizeof(int));
  	*((int *) CMSG_DATA(control_message)) = fd_to_send;

  	return sendmsg(socket, &socket_message, 0);
}


int seccomp_server(){
	ALOGE("keystore run seccomp_server()");

	struct sockaddr_un address;
	int socket_fd, connection_fd;


	struct OpenFile{
		char filename[250];
		int flag;
	};

	unlink("/data/local/tmp/test");

	struct OpenFile myFile;
	memset(&myFile, 0, sizeof(struct OpenFile));

	socklen_t address_length;

	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(socket_fd < 0){
		ALOGE("keystore socket() server failed\n");
		return 1;
	}
	
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, "./demo_socket");

	ALOGE("keystore start to binder");
	if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
		ALOGE("bind() server failed\n");
		return 1;
	}

	ALOGE("keystore start to listen");

	// receive the filename
	if(listen(socket_fd, 5) != 0) {
		ALOGE("listen() failed\n");
		return 1;
	}	

	ALOGE("keystore  i am listening");
	
	connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length);

	if(connection_fd > -1){
		read(connection_fd, (char *)&myFile, sizeof(struct OpenFile));
		close(connection_fd);
	}


	// now, we get the filename and flag from the child process
	int fd = open(myFile.filename, myFile.flag);
	
	// send the file descriptor back to the child process	


	int retval = send_fd(socket_fd, fd);

	if(retval > -1){
		ALOGE("send_fd succeed");
	}

	close(socket_fd);
	return 0;
}

int seccomp_sendRet( unsigned char * out, size_t outSize, int32_t ret)
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


	
	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        ALOGE("socket() failed\n");
        return 1;
    }

	memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
	strcpy(address.sun_path, "./demo_socket");

    if (connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
        ALOGE("SendRet connect() failed\n");
        return 1;
    }

    write(socket_fd, (char *)&myRet, outSize + sizeof(size_t));

	close(socket_fd);
	return 0;
}


int seccomp_recvRet(unsigned char ** out, size_t* outSize, int* ret)
{

	struct sockaddr_un address;
    int socket_fd, connection_fd;

	struct RET{
		unsigned char out[1000];
		size_t outSize;
		int ret;
	};


	struct RET myRET;

	memset(&myRET.out, 0, sizeof(myRET.out));

    socklen_t address_length;

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0){
        ALOGE("socket() server failed\n");
        return 1;
    }

    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, "./demo_socket");

    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0){
        ALOGE("bind() server failed\n");
        return 1;
    }

    // receive the filename
    if(listen(socket_fd, 5) != 0) {
        ALOGE("listen() failed\n");
        return 1;
    }

    connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length);

    if(connection_fd > -1){
        read(connection_fd, (char *)&myRET, sizeof(struct RET));
        close(connection_fd);
    }

	close(socket_fd);

	memcpy(*out, myRET.out, 1000);
	*outSize = myRET.outSize;
	*ret = myRET.ret;	

	ALOGE("%s", *out);
	ALOGE("%d", *outSize);
	ALOGE("%d", *ret);

	return 0;	
}



status_t BnKeystoreService::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
	
	uid_t callingUid = IPCThreadState::self()->getCallingUid();
	ALOGE("CONGZHENG: CALL UID: %d  Code: %d\n", callingUid, code);
	
	
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
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case GET: {
			ALOGE("CONGZHENG %s  %d\n", "GET", code);
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            void* out = NULL;
            size_t outSize = 0;

            int32_t ret = get(name, (uint8_t**) &out, &outSize);
            reply->writeNoException();
            if (ret == 1) {
                reply->writeInt32(outSize);
                void* buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);

			//	ALOGE("CONGZHENG buf %s\n", (char*)buf); 
                free(out);
            } else {
                reply->writeInt32(-1);
            }


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
            int32_t ret = insert(name, (const uint8_t*) in, (size_t) inSize, uid, flags);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case DEL: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int uid = data.readInt32();
            int32_t ret = del(name, uid);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case EXIST: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int uid = data.readInt32();
            int32_t ret = exist(name, uid);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case SAW: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int uid = data.readInt32();
            Vector<String16> matches;
            int32_t ret = saw(name, uid, &matches);
            reply->writeNoException();
            reply->writeInt32(matches.size());
            Vector<String16>::const_iterator it = matches.begin();
            for (; it != matches.end(); ++it) {
                reply->writeString16(*it);
            }
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case RESET: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            int32_t ret = reset();
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case PASSWORD: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 pass = data.readString16();
            int32_t ret = password(pass);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case LOCK: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            int32_t ret = lock();
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case UNLOCK: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 pass = data.readString16();
            int32_t ret = unlock(pass);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case ZERO: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            int32_t ret = zero();
            reply->writeNoException();
            reply->writeInt32(ret);
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
		
			/*	
			String8 key = check(callingUid, name);
			ALOGE("CONGZHENG kdkk %s", key.string());

			//FILE * FD = fopen(key.string(), "wb");


			FILE *read_stream = fopen("/dev/zero", "r");

			ALOGE("%d", fileno(read_stream));

			pid_t pid = fork();

			if (pid == -1){

		
			}
			else if (pid == 0){

				prctl(PR_SET_NO_NEW_PRIVS, 1);
    			prctl(PR_SET_DUMPABLE, 0);

    			scmp_filter_ctx ctx;

				ctx = seccomp_init(SCMP_ACT_KILL);
				seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
				//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0));
				//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write),1, SCMP_A0(SCMP_CMP_EQ, 0));
				seccomp_load(ctx);	
		
				ALOGE("CONGZHENG HI I am child");	
				//_exit(EXIT_SUCCESS);

				int32_t ret = generate(name, uid, keyType, keySize, flags, &args);
				ALOGE("CONGZHENG child return %d\n", ret);			

				seccomp_release(ctx);
				exit(0);

			}
			else {

				if(waitpid(pid,NULL,0)!=pid)
					ALOGE("CONGZHENG waitpid error");
				ALOGE("CONGZHENG HI I AM parent");
			}

						
			ALOGE("CONGZHENG parent continue");
			//int32_t myret = dispatch(FD, name, uid, keyType, keySize, flags, &args); 	

			int32_t ret = 1;	
			*/
            int32_t ret = generate(name, uid, keyType, keySize, flags, &args);
            reply->writeNoException();
            reply->writeInt32(ret);
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
            int32_t ret = import(name, (const uint8_t*) in, (size_t) inSize, uid, flags);
            reply->writeNoException();
            reply->writeInt32(ret);
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
            int32_t ret = sign(name, (const uint8_t*) in, (size_t) inSize, (uint8_t**) &out, &outSize);
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
            bool ret = verify(name, (const uint8_t*) in, (size_t) inSize, (const uint8_t*) sig,
                    (size_t) sigSize);
            reply->writeNoException();
            reply->writeInt32(ret ? 1 : 0);
            return NO_ERROR;
        } break;
        case GET_PUBKEY: {
			ALOGE("CONGZHENG %s  %d\n","get_pubkey",code); 
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            void* out = NULL;
            size_t outSize = 0;



			int ret = 0;
        
            pid_t pid = fork();
            if (pid == -1){

            }else if (pid == 0){

                ALOGE("keystore I am child");
                int32_t ret = get_pubkey(name, (unsigned char**) &out, &outSize);        
                ALOGE("%d", ret);               
    
                // send back ret,  out, outsize to server

                int ret3 = seccomp_sendRet((unsigned char *)out, outSize, ret);
                ALOGE("%d", ret3);
                    
                
                // exit the child process
            	_exit(0);
            }else{

                // wait for client to request the file descriptor
        
                ALOGE("keystore I am parent");  
                int ret1 = seccomp_server();            
                ALOGE("RETURN of server : %d\n", ret1); 


                // get the return value
                seccomp_recvRet((unsigned char**) &out, &outSize, &ret);
                ALOGE("%d", ret);
            }       

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
            return NO_ERROR;
        } break;
        case DEL_KEY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int uid = data.readInt32();
            int32_t ret = del_key(name, uid);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case GRANT: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int32_t granteeUid = data.readInt32();
            int32_t ret = grant(name, granteeUid);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case UNGRANT: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int32_t granteeUid = data.readInt32();
            int32_t ret = ungrant(name, granteeUid);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case GETMTIME: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int64_t ret = getmtime(name);
            reply->writeNoException();
            reply->writeInt64(ret);
            return NO_ERROR;
        } break;
        case DUPLICATE: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 srcKey = data.readString16();
            int32_t srcUid = data.readInt32();
            String16 destKey = data.readString16();
            int32_t destUid = data.readInt32();
            int32_t ret = duplicate(srcKey, srcUid, destKey, destUid);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case IS_HARDWARE_BACKED: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 keyType = data.readString16();
            int32_t ret = is_hardware_backed(keyType);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        }
        case CLEAR_UID: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            int64_t uid = data.readInt64();
            int32_t ret = clear_uid(uid);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        }
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

// ----------------------------------------------------------------------------

}; // namespace android
