#include <sys/types.h>
#include <io.h>
#include <sys/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <memory.h>
#include <errno.h>
#include <stdlib.h>
#include <iostream>
#include <assert.h>
#include <Windows.h>
#include <stdio.h>
#include <fstream>
#include <iterator>
#include <vector>
#include <stdio.h>
#include "../libs/src/blake2s-ref.c"
#include "../metadata.h"
#include <direct.h>
#include "../libs/src/libed25519/ed25519.c";

#define GetCurrentDir _getcwd


#define SRV_IP "127.0.0.1"
#define DEST_PORT 3005
#define SOURCE_PORT 3006
#define BUFLEN 10*4096
#define NPACK 1
#pragma comment(lib,"ws2_32.lib")

WSADATA wsaData;


void send(uint8_t *in, int in_size) {
	struct sockaddr_in si_other;
	int s, i, slen = sizeof(si_other);

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		printf("socket");

	memset((char *)&si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(DEST_PORT);
	if (inet_pton(AF_INET, SRV_IP, &si_other.sin_addr) == 0) {
		fprintf(stderr, "inet_aton() failed\n");
		closesocket(s);
		WSACleanup();
		exit(1);
	}

	printf("Sending packet\n");
	for (int i = 0; i<in_size; i++) printf("%02X-", in[i]);
	printf("\n");
	if (sendto(s, (char*)in, in_size, 0, (sockaddr*)&si_other, slen) == -1)
		printf("sendto()");

	//closesocket(s);
}

int recv(uint8_t* buf) {

	struct sockaddr_in si_me, si_other;
	int s;

	printf("recving\n");
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	assert(s != -1);

	int broadcast = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&broadcast, sizeof broadcast);

	memset(&si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(SOURCE_PORT);
	si_me.sin_addr.s_addr = INADDR_ANY;

	if (bind(s, (sockaddr *)&si_me, sizeof(sockaddr)) == -1) {
		fprintf(stderr, "bind() failed\n");
		exit(1);
	}

	int slen = sizeof(sockaddr);
	int recv_len = -1;
	while(recv_len == -1)	recv_len = recvfrom(s, (char*)buf, BUFLEN, 0, (sockaddr *)&si_other, &slen);

	printf("recv: recv_len %d\n", recv_len);
	for (int i = 0; i<recv_len; i++) printf("%02X-", buf[i]);
	printf("\n");

	closesocket(s);
	return recv_len;
}


#define SAMPLE_STR_SIZE 10100000
uint8_t* sample_string() {
	uint8_t *buf = (uint8_t*)malloc(SAMPLE_STR_SIZE);
	uint8_t base = 'a';
	int i;
	for (i = 0; i<SAMPLE_STR_SIZE; i++) {
		buf[i] = base + i % 26;
	}
	buf[SAMPLE_STR_SIZE - 1] = 'Z';
	int welcome_size = 157 * 10;
	char welcome[157 * 10+1] = "\\
============================================================================================================================================================ \\
                                                                                                                                                             \\
                                              db   d8b   db d88888b db       .o88b.  .d88b.  .88b  d88. d88888b                                              \\
                                              88   I8I   88 88'     88      d8P  Y8 .8P  Y8. 88'YbdP`88 88'                                                  \\
                                              88   I8I   88 88ooooo 88      8P      88    88 88  88  88 88ooooo                                              \\
                                              Y8   I8I   88 88~~~~~ 88      8b      88    88 88  88  88 88~~~~~                                              \\
                                              `8b d8'8b d8' 88.     88booo. Y8b  d8 `8b  d8' 88  88  88 88.                                                  \\
                                               `8b8' `8d8'  Y88888P Y88888P  `Y88P'  `Y88P'  YP  YP  YP Y88888P                                              \\
                                                                                                                                                             \\
_____________________________________________________________________________________________________________________________________________________________";


	for (i = SAMPLE_STR_SIZE - welcome_size; i<SAMPLE_STR_SIZE; i++) buf[i] = welcome[i - SAMPLE_STR_SIZE + welcome_size];
	return buf;
}

int allocate_fixed_key(uint8_t *key) {
	int size = 3;
	key = (uint8_t*)malloc(size);

	key[0] = (uint8_t)('k');
	key[1] = (uint8_t)('e');
	key[2] = (uint8_t)('y');

	return size;
}

void blake2_hash(uint8_t *buf, int buf_len,
	uint8_t *K, int K_size, uint8_t hash[BLAKE2S_OUTBYTES]) {

	assert(K_size <= BLAKE2S_KEYBYTES);

	uint8_t key[BLAKE2S_KEYBYTES] = { 0 };
	if (K == NULL) {
		key[0] = (uint8_t)('k');
		key[1] = (uint8_t)('e');
		key[2] = (uint8_t)('y');

		//allocate_fixed_key(key);
	}
	else {
		memcpy(key, K, K_size);
	}

	printf("key: ");
	for (int i = 0; i<BLAKE2S_KEYBYTES; i++) printf("%x-", key[i]);
	printf("\n\n");

	blake2s(hash, buf, key, BLAKE2S_OUTBYTES, buf_len, BLAKE2S_KEYBYTES);
}

void ntoha(const uint8_t *in, int len, uint8_t* out) {

	assert(len % 4 == 0);
	for (int i = 0; i<len; i += 4) {

		int tmp = ntohl(*(int*)(in + i));
		memcpy(out + i, &tmp, sizeof(int));
	}
	/*printf("in: ");
	for(int i=0; i<len; i++) printf("%d ", *(in+i));
	printf("\n\n");
	printf("out: ");
	for(int i=0; i<len; i++) printf("%d ", *(out+i));
	printf("\n\n");*/
}

void htona(const uint8_t *in, int len, uint8_t* out) {

	assert(len % 4 == 0);
	for (int i = 0; i<len; i += 4) {

		int tmp = htonl(*(int*)(in + i));
		memcpy(out + i, &tmp, sizeof(int));
	}
	/*printf("in: ");
	for(int i=0; i<len; i++) printf("%d ", *(in+i));
	printf("\n\n");
	printf("out: ");
	for(int i=0; i<len; i++) printf("%d ", *(out+i));
	printf("\n\n");*/
}


void handle_mac_compute() {

	uint8_t *buf = new uint8_t[BUFLEN];
	uint8_t *str = sample_string();
	while (true) {
		// first get attestation request
		int len = recv(buf);
		uint8_t *inv_buf = new uint8_t[len];
		ntoha(buf, len, inv_buf);

		int start_idx = ntohl(*(int*)(buf + 40));
		int str_len = ntohl(*(int*)(buf + 44));
		printf("LOC: %d - %d\n", start_idx, str_len);

		// compute MAC
		uint8_t hash[BLAKE2S_OUTBYTES];
		blake2_hash(inv_buf, len, NULL, 0, hash);

		// return MAC
		uint8_t inv_hash[BLAKE2S_OUTBYTES];
		htona(hash, BLAKE2S_OUTBYTES, inv_hash);
		send(inv_hash, BLAKE2S_OUTBYTES);

		printf("Attesting string: ");
		for (int i = 0; i < str_len; i++) {
			if (i % 157 == 0) printf("\n");
			printf("%c", *(char*)(str + SAMPLE_STR_SIZE - str_len - start_idx + i + 2152));
		}
		printf("\n\n");

		uint8_t *res = new uint8_t[len + str_len];

		memcpy(res, inv_buf, len);
		memcpy(res + len, str + SAMPLE_STR_SIZE - str_len - start_idx + 2152, str_len);

		/*printf("block: ");
		for(int i=0; i<str_len+len; i++) printf("%d ", *(res+i));
		printf("\n\n");

		printf("block in hex: ");
		for(int i=0; i<str_len+len; i++) printf("%x ", *(res+i));
		printf("\n\n");*/

		blake2_hash(res, len + str_len, NULL, 0, hash);

		printf("Sleeping Zzzz\n\n\n");
		Sleep(1000);
		htona(hash, BLAKE2S_OUTBYTES, inv_buf);
		send(hash, BLAKE2S_OUTBYTES);

		free(res);
		free(inv_buf);
	}
}

typedef struct test {
	uint64_t timestamp;
	uint8_t data[100];
	uint8_t sig[32];
} test_t;

const int BUFFERSIZE = 1000000;
void send_img_hash(char* s) {

	uint8_t buf[BUFFERSIZE];

	FILE * filp = fopen(s, "rb");
	assert(filp != NULL);
	printf("Opening file %s\n", s);
	int bytes_read = fread(buf, sizeof(char), BUFFERSIZE, filp);

	uint8_t *inv_buf = new uint8_t[bytes_read];
	ntoha(buf, bytes_read, inv_buf);

	uint8_t hash[BLAKE2S_OUTBYTES];
	blake2s(hash, inv_buf, NULL, BLAKE2S_OUTBYTES, bytes_read, 0);

	uint8_t inv_hash[BLAKE2S_OUTBYTES];
	htona(hash, BLAKE2S_OUTBYTES, inv_hash);
	send(inv_hash, BLAKE2S_OUTBYTES);
	free(inv_buf);

	int len = recv(buf);

}

void compute_blake2s_hash(void* key, int keyLen) {
	uint8_t *buf = new uint8_t[BUFLEN];
	uint8_t *str = sample_string();
	uint8_t hash[BLAKE2S_OUTBYTES];

	while (true) {
		// first get attestation request
		int len = recv(buf);
		printf("buf: ");
		for (int i = 0; i < len; i++) printf("%02x ", buf[i]);
		printf("\n");
		
		//uint8_t *inv_buf = new uint8_t[len];
		//ntoha(buf, len, inv_buf);

		blake2_hash(buf, len, NULL, 0, hash);

		//uint8_t inv_hash[BLAKE2S_OUTBYTES];
		//htona(hash, BLAKE2S_OUTBYTES, inv_hash);
		send(hash, BLAKE2S_OUTBYTES);
		//free(inv_buf);

	}
}

TimeStampRequest_t ts_req;
SnapshotRequest_t sh_req;
TargetRequest_t tg_req;
RootRequest_t root_req;
ServerKey_t server_keys[NUM_ROOT_KEYS];

const int IMG1_SIZE = 300000, IMG2_SIZE = 300000;
unsigned char img1[IMG1_SIZE];

void generate_root() {

	root_req.role_type = ROOT;
	root_req.timestamp = 123451;
	root_req.version = 1;
	for (int i = 0; i < NUM_ROOT_KEYS; i++) {
		server_keys[i].key_id = i;
		server_keys[i].type = ED25519;
		memset(server_keys[i].public_key, 0, 32);
		memset(server_keys[i].private_key, 0, 32);
		ed25519_create_keypair(server_keys[i].public_key, server_keys[i].private_key, (uint8_t*)(&server_keys[i].key_id));

		root_req.keys[i].key_id = server_keys[i].key_id;
		root_req.keys[i].type = server_keys[i].type;
		memcpy(root_req.keys[i].public_key, server_keys[i].public_key, 32);
		printf("key: %d\nPK: ", i);
		for (int j = 0; j < 32; j++) printf("%02x ", root_req.keys[i].public_key[j]);
		printf("\nSK: ");
		for (int j = 0; j < 32; j++) printf("%02x ", server_keys[i].private_key[j]);
		printf("\n");
	}
	ServerKey_t skey = server_keys[NUM_ROOT_KEYS - 1]; // targets, snapshot, timestamp, root
	root_req.signature.key_id = skey.key_id;
	root_req.signature.type = skey.type;
	uint64_t unused;
	ed25519_sign(root_req.signature.sig, (uint8_t*)(&root_req + sizeof(Signature_t)),
		sizeof(RootRequest_t) - sizeof(Signature_t), skey.public_key, skey.private_key, &unused);
	//TODO: fill in root_req.roles
}

void create_requests() {

	// Generate Root
	generate_root();

	// First construct targets
	tg_req.version = 2;
	tg_req.role_type = TARGET;
	tg_req.timestamp = 1223344;

	// Load images
	std::ifstream in1("../../images/fuel-level-app-v0", std::ios::binary);
	in1.read((char*)img1, IMG1_SIZE);
	uint64_t unused = 0;

	strcpy(tg_req.meta[0].name, "fuel");
	tg_req.meta[0].len = in1.gcount();
	tg_req.meta[0].hash_type = SHA512;
	sha512_benchmark(img1, in1.gcount(), tg_req.meta[0].hash);

	printf("Hash of img1: (%d) ", tg_req.meta[0].len);
	for (int j = 0; j < 64; j++) printf("%02x-", tg_req.meta[0].hash[j]);
	printf("\n");


	std::ifstream in2("../../images/speedometer-app-v0", std::ios::binary);
	in2.read((char*)img1, IMG1_SIZE);
	strcpy(tg_req.meta[1].name, "speed");

	tg_req.meta[1].len = in2.gcount();
	tg_req.meta[1].hash_type = SHA512;
	sha512_benchmark(img1, tg_req.meta[1].len, tg_req.meta[1].hash);
	printf("Hash of img2: (%d) ", tg_req.meta[1].len);
	for (int j = 0; j < 64; j++) printf("%02x-", tg_req.meta[1].hash[j]);
	printf("\n");

	// compute signature
	ServerKey_t skey = server_keys[0];
	tg_req.signature.key_id = skey.key_id;
	tg_req.signature.type = skey.type;
	ed25519_sign(tg_req.signature.sig, (uint8_t*)(&tg_req + sizeof(Signature_t)),
		sizeof(TargetRequest_t) - sizeof(Signature_t), skey.public_key, skey.private_key, &unused);

	if (ed25519_verify(tg_req.signature.sig, (uint8_t*)(&tg_req + sizeof(Signature_t)),
		sizeof(TargetRequest_t) - sizeof(Signature_t), skey.public_key, &unused) == 0)
		printf("FAILED\n");

	// Now snapshot
	sh_req.version = 2;
	sh_req.role_type = SNAPSHOT;
	sh_req.timestamp = 1122334;
	// TODO: Skip root ([0]) for now
	strcpy(sh_req.meta[1].name, "targets");
	sh_req.meta[1].len = sizeof(tg_req);
	sh_req.meta[1].hash_type = SHA512;
	sha512_benchmark((uint8_t*)(&tg_req), sizeof(tg_req), sh_req.meta[1].hash);

	skey = server_keys[1];
	sh_req.signature.key_id = skey.key_id;
	sh_req.signature.type = skey.type;
	ed25519_sign(sh_req.signature.sig, (uint8_t*)(&sh_req + sizeof(Signature_t)),
		sizeof(SnapshotRequest_t) - sizeof(Signature_t), skey.public_key, skey.private_key, &unused);

	// Now timestamp
	ts_req.version = 3;
	ts_req.timestamp = 1234567;
	ts_req.role_type = TIMESTAMP;
	strcpy(ts_req.meta.name, "snapshot");
	ts_req.meta.len = sizeof(ts_req);
	ts_req.meta.hash_type = SHA512;
	sha512_benchmark((uint8_t*)(&sh_req), sizeof(sh_req), ts_req.meta.hash);

	skey = server_keys[2];
	ts_req.signature.key_id = skey.key_id;
	ts_req.signature.type = skey.type;
	ed25519_sign(ts_req.signature.sig, (uint8_t*)(&ts_req + sizeof(Signature_t)),
		sizeof(TimeStampRequest_t) - sizeof(Signature_t), skey.public_key, skey.private_key, &unused);
}



void send_update_request() {
	create_requests();
	uint8_t *buf = new uint8_t[BUFLEN];
	while (true) {
		int id = recv(buf);
		if(id != -1) printf("Identifier: %d\n", id);
		switch (id) {
		case 0: // TimestampRequest
			send((uint8_t*)&ts_req, sizeof(TimeStampRequest_t));
			break;
		case 1: // SnapshotRequest
			send((uint8_t*)&sh_req, sizeof(SnapshotRequest_t));
			break;
		case 2: // TargetRequest
			send((uint8_t*)&tg_req, sizeof(TargetRequest_t));
			break;
		case 3: // RootRequest
			send((uint8_t*)&root_req, sizeof(RootRequest_t));
			break;
		}
	}
	exit(1);
}

int main(void)
{
	printf("sizeof(Key_t) : %d\n", sizeof(Key_t));
	printf("Size : %d, %d, %d, %d\n", sizeof(TargetRequest_t), sizeof(RootRequest_t), sizeof(SnapshotRequest_t), sizeof(TimeStampRequest_t));
	uint8_t digest[64] = { 0 };
	sha512_benchmark(NULL, 0, digest);
	printf("digest: ");
	int i;
	for (i = 0; i < 64; i++) printf("%02x ", digest[i]);
	printf("\n");
	uint8_t pk[64] = { 0 }, sk[64] = { 0 };
	uint64_t unused;
	ed25519_sign(digest, NULL, 0, pk, sk, &unused);
	printf("Sig: ");
	for (i = 0; i < 64; i++) printf("%02x ", digest[i]);
	printf("\n");
	WSAStartup(MAKEWORD(2, 2), &wsaData); // 2.2 version
	//handle_mac_compute();
	send_update_request();
	compute_blake2s_hash(NULL, 0);
	//send_img_hash("C:\\Users\\norrathep\\Documents\\GitHub\\sel4_verifier\\windows_verifier\\windows_verifier\\sdcard-image-arm-imx6");
	return 0;
}