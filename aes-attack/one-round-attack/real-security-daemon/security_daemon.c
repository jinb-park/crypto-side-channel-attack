#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/des.h>

#include "ipc.h"

#define KEY_BIT 128
#define MAX_PLAIN_TEXTS 3000

typedef unsigned char U8;

/* Real Key */
static const U8 real_key[16] = {0xa2,0x98,0x18,0x98,0xc4,0x71,0x87,0x53,0x8c,0xde,0x17,0x09,0xdb,0xd9,0xab,0x40};

/* IPC */
int server_fd;
void *addr;
struct shm_msg *client_msg;
struct shm_msg *server_msg;
U8 enc[16] = {0,};
U8 msg[MSG_SIZE_MAX] = {0,};

static AES_KEY aes_key;
void set_aes_key(void)
{
	if(AES_set_encrypt_key(real_key, KEY_BIT, &aes_key) < 0) {
		printf("AES_set_encrypt_key error\n");
		return;
	}
}

/* Encrypt */
void aes_encrypt(U8 *in, U8 *out, const U8 *key)
{
	AES_KEY aes_key;

	if(AES_set_encrypt_key(key, KEY_BIT, &aes_key) < 0) {
		printf("AES_set_encrypt_key error\n");
		return;
	}
	AES_ecb_encrypt(in, out, &aes_key, AES_ENCRYPT);
}

void print_predict_result(void)
{
	int i;
	unsigned int real, cand, recovery;
	U8 *cand_key;
	
	cand_key = client_msg->msg + sizeof(END_MSG);
	recovery = 0;
	
	for(i=0; i<sizeof(real_key); i++) {
		real = (real_key[i] >> 4);
		cand = (cand_key[i] >> 4);
		
		if((real & (1<<0)) == (cand & (1<<0))) recovery++;
		if((real & (1<<1)) == (cand & (1<<1))) recovery++;
		if((real & (1<<2)) == (cand & (1<<2))) recovery++;
		if((real & (1<<3)) == (cand & (1<<3))) recovery++;
	}
	
	printf("real key : ");
	for(i=0; i<sizeof(real_key); i++)
		printf("%02x", real_key[i]);
	printf("\n");
	
	printf("predict key : ");
	for(i=0; i<sizeof(real_key); i++)
		printf("%02x", cand_key[i]);
	printf("\n");
	
	printf("Recover [%d] bits success!!\n", recovery);
}

int main(int argc, char **argv)
{
	int i;
	
	/* create shm */
    if((server_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, PERM_FILE)) == -1) {
        printf("shm_open error : %s\n", strerror(errno));
        return -1;
    }
	
	/* set size */
    if(ftruncate(server_fd, MSG_SIZE_MAX) == -1) {
        printf("ftruncate error : %s\n", strerror(errno));
        goto out;
    }
	
	/* mmap */
    addr = mmap(NULL, MSG_SIZE_MAX, PROT_READ | PROT_WRITE, MAP_SHARED, server_fd, 0);
    if(addr == MAP_FAILED) {
        printf("mmap error : %s\n", strerror(errno));
        goto out;
    }
    memset(addr, 0, MSG_SIZE_MAX);
	
	client_msg = (struct shm_msg *)((char*)addr + SHM_CLIENT_BUF_IDX);
    server_msg = (struct shm_msg *)((char*)addr + SHM_SERVER_BUF_IDX);
	
	printf("security_daemon is running...\n");
	printf("real key : ");
	for(i=0; i<sizeof(real_key); i++)
		printf("%02x", real_key[i]);
	printf("\n");
	
	while(1) {
		/* read msg */
		while(1) {
			if(client_msg->status == 1) {
                memcpy(msg, client_msg->msg, client_msg->len);
                client_msg->status = 0;
                break;
            }
			sleep(0);
		}
		
		if(client_msg->len == (sizeof(END_MSG) + sizeof(real_key))) {
            printf("end msg!!\n");
			print_predict_result();
            break;
        }
		
		/* prepare msg */
        server_msg->status = 0;
        server_msg->len = sizeof(enc);
		
		/* encryption */
		aes_encrypt(msg, enc, real_key);
		
		/* send encrypted msg to client, and state_full_te* for ideal environment */
		memcpy(server_msg->msg, enc, server_msg->len);
		server_msg->status = 1;
	}
	
	printf("security_daemon is closing...\n");

out:
	/* destroy shm */
    if(munmap(addr, MSG_SIZE_MAX) == -1) {
        printf("munmap error : %s\n", strerror(errno));
    }
	if(close(server_fd) == -1) {
        printf("close error : %s\n", strerror(errno));
    }
	if(shm_unlink(SHM_NAME) == -1) {
        printf("shm_unlink error : %s\n", strerror(errno));
    }
	return 0;
}
