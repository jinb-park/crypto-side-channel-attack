#ifndef _ONE_ROUND_ATTACK_H
#define _ONE_ROUND_ATTACK_H

#include <libflush/libflush.h>
#define AES128_KEY_LEN 16
#define KEYBYTES 256
#define MAX_BUF 1024
#define MAX_PLAIN_TEXTS 3000

typedef unsigned char U8;

struct one_round_attack_args {
	int plain_text_cnt;				/* plaintext count */
	int cache_attack_repeat_cnt;	/* repeat count for a plaintext */
	int cpu_cycle_threshold;		/* cpu cycle threshold */
	int cache_line_size;			/* cache line size. It's 64 byte for ARM generally */
	unsigned int off_te0;			/* offset for te0 */
	unsigned int off_te1;			/* offset for te0 */
	unsigned int off_te2;			/* offset for te0 */
	unsigned int off_te3;			/* offset for te0 */
	char crypto_lib[MAX_BUF];		/* filepath of crypto library */
	char plaintext_file[MAX_BUF];	/* filepath of plaintexts */
};

struct one_round_attack_cache_ctx {
	struct one_round_attack_args args;							/* arguments for one_round_attack */
	libflush_session_t* libflush_session;						/* libflush session */
	int crypto_lib_fd;											/* fd for crypto library */
	U8 *crypto_lib_addr;										/* mapped address for crypto library */
	unsigned int crypto_lib_size;								/* mapped size for crypto library */
	unsigned int *state_te0;									/* address of te0 */
	unsigned int *state_te1;									/* address of te1 */
	unsigned int *state_te2;									/* address of te2 */
	unsigned int *state_te3;									/* address of te3 */
	U8 plains[MAX_PLAIN_TEXTS][AES128_KEY_LEN];					/* plaintexts */
	double subset[MAX_PLAIN_TEXTS][AES128_KEY_LEN][KEYBYTES];	/* subsets. It means a cache hit ratio */
	double score[AES128_KEY_LEN][KEYBYTES];						/* candidate score */
};

struct one_round_attack_result {
	U8 predict_key[AES128_KEY_LEN];		/* result of attack. predicted aes key */
};

struct one_round_attack_ctx {
	struct one_round_attack_args args;
	struct one_round_attack_cache_ctx cache_ctx;
	struct one_round_attack_result result;
	int (*encrypt)(unsigned char *in, unsigned char *out, int size);	/* callback function to trigger encryption */
};

int one_round_attack_init(struct one_round_attack_ctx *ctx);
void one_round_attack_do_attack(struct one_round_attack_ctx *ctx);
void one_round_attack_finalize(struct one_round_attack_ctx *ctx);

#endif