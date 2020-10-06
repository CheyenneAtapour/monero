/*
	Note that this code uses a modified Paillierlib that includes the random value 'r' with each ciphertext.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <gmp.h>
#include "paillier.c" 


void get_rand_file( void* buf, int len, char* file )
{
	FILE* fp;
	void* p;

	fp = fopen(file, "r");

	p = buf;
	while( len )
	{
		size_t s;
		s = fread(p, 1, len, fp);
		p += s;
		len -= s;
	}

	fclose(fp);
}

void get_rand_devurandom( void* buf, int len )
{
	get_rand_file(buf, len, "/dev/urandom");
}

void print_hash(char * d)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	printf("\n");
}


int main(int argc, char *argv[])
{
	// Security parameter (number of bits of the modulus)
	mpz_t n;
	mpz_init(n);
	mpz_set_ui(n, 256);  
    
	// Generate keys
	paillier_pubkey_t* pubKey;
	paillier_prvkey_t* secKey;
	paillier_keygen(256, &pubKey, &secKey, paillier_get_rand_devurandom);

	// Plaintexts initialization
	paillier_plaintext_t* m;
	m = paillier_plaintext_from_ui(100);
	gmp_printf("Plaintext created: %Zd\n", m);	

	// Encrypt the messages
	paillier_ciphertext_t* c;
	c = paillier_enc(NULL, pubKey, m, paillier_get_rand_devurandom);
	gmp_printf("Ciphertext created: %Zd\n", c);
	printf("\n");

	uint64_t test;
	test = mpz_get_ui(c->c);

	printf("test: %llu\n", test);
	
	// Now verify that ctxt1 is a valid message
	// Following https://paillier.daylightingsociety.org/Paillier_Zero_Knowledge_Proof.pdf
	// Declare variables
	mpz_t u_1;
	mpz_t u_2;
	mpz_t u_3;	
	
	mpz_t m1;
	mpz_t m2;
	mpz_t m3;

	mpz_t g_m1;
	mpz_t g_m2;
	mpz_t g_m3;

	// Init variables
	mpz_init(u_1);
	mpz_init(u_2);
	mpz_init(u_3);

	mpz_init(g_m1);
	mpz_init(g_m2);
	mpz_init(g_m3);

	mpz_init(m1);
	mpz_init(m2);
	mpz_init(m3);

	// Assign values of valid votes to m_k's
	mpz_set_ui(m1, 1);
	mpz_set_ui(m2, 100);
	mpz_set_ui(m3, 10000);

	// Assign values for g_k
	mpz_powm(g_m1, pubKey->n_plusone, m1, pubKey->n_squared);
	mpz_powm(g_m2, pubKey->n_plusone, m2, pubKey->n_squared);
	mpz_powm(g_m3, pubKey->n_plusone, m3, pubKey->n_squared);
	
	// Calculate u_k's	
	mpz_invert(u_1, g_m1, pubKey->n_squared);
	mpz_mul(u_1, c->c, u_1);
	mpz_mod(u_1, u_1, pubKey->n_squared);

	mpz_invert(u_2, g_m2, pubKey->n_squared);
	mpz_mul(u_2, c->c, u_2);
	mpz_mod(u_2, u_2, pubKey->n_squared);

	mpz_invert(u_3, g_m3, pubKey->n_squared);
	mpz_mul(u_3, c->c, u_3);
	mpz_mod(u_3, u_3, pubKey->n_squared);
	
/*
	PASSED	
	// Test that the following holds: u_2 = r^n mod n^2
	// divide c by u_2 and I should get g^m:
	//mpz_div(u_3, c->c, u_2);
	//mpz_mod(u_3, u_3, pubKey->n_squared);
	mpz_invert(u_3, u_2, pubKey->n_squared);
	mpz_mul(u_3, c->c, u_3);
	mpz_mod(u_3, u_3, pubKey->n_squared);
	gmp_printf("c divided by u2 should be g^m: %Zd\n", u_3); 
	gmp_printf("g^m: %Zd\n", g_m2);
	// Try g^m * u_2 and see if we get c
	mpz_mul(u_3, g_m2, u_2);
	mpz_mod(u_3, u_3, pubKey->n_squared);
	gmp_printf("c: %Zd\n", c->c);	
	gmp_printf("gm * u2: %Zd\n", u_3);
*/
	
	// Select 2 random e_k, z_k, and a random w_k
	// TODO: use better random number generation
	mpz_t e_1;
	mpz_t e_3;
	mpz_t z_1;
	mpz_t z_3;
	mpz_t w;
	mpz_t res;
		
	mpz_init(e_1);
	mpz_init(e_3);
	mpz_init(z_1);
	mpz_init(z_3);
	mpz_init(w);
	mpz_init(res);
	
	// Initialize random state for rng
	void* buf;
	mpz_t s;
	
	buf = malloc(16);
	get_rand_devurandom(buf, 16);
	mpz_init(s);
	mpz_import(s, 16, 1, 1, 0, 0, buf);
	gmp_randstate_t rand_state;
	gmp_randinit_mt(rand_state);
	srand(time(0));
	gmp_randseed(rand_state, s);

	mpz_clear(s);
	free(buf);
	
	// Generate e_1 and e_3
	// p and q are 256/2 bits each, so our b is 1 less bit than that to ensure 2^b < p,q
	mpz_urandomb(e_1, rand_state, 256 / 2 - 1);
	mpz_urandomb(e_3, rand_state, 256 / 2 - 1); 
	
	// Generate z_1 and z_3
	// since n = pq, every number smaller than n that is not p or q is coprime to n
	mpz_urandomb(z_1, rand_state, 255);
	mpz_gcd(res, z_1, pubKey->n);
	while (mpz_cmp_ui(res, 1) != 0)
	{
		mpz_urandomb(z_1, rand_state, 255);
		mpz_gcd(res, z_1, pubKey->n);
	}
	mpz_set_ui(res, 2);
	mpz_urandomb(z_3, rand_state, 255);
	mpz_gcd(res, z_3, pubKey->n);
	while (mpz_cmp_ui(res, 1) != 0)
	{
		mpz_urandomb(z_3, rand_state, 255);
		mpz_gcd(res, z_3, pubKey->n);
	}
	
	// Generate omega
	mpz_set_ui(res, 2);
	mpz_urandomb(w, rand_state, 255);
	mpz_gcd(res, w, pubKey->n);
	while (mpz_cmp_ui(res, 1) != 0)
	{
		mpz_urandomb(w, rand_state, 255);
		mpz_gcd(res, w, pubKey->n);
	}
	
	// Calculate a_k's
	mpz_t a_1;
	mpz_t a_2;
	mpz_t a_3;
	
	mpz_t z_n;
	mpz_t u_e; 

	mpz_init(a_1);
	mpz_init(a_2);
	mpz_init(a_3);
	
	mpz_init(z_n);
	mpz_init(u_e);
	
	// Calculate a_1
	mpz_powm(z_n, z_1, pubKey->n, pubKey->n_squared);
	mpz_powm(u_e, u_1, e_1, pubKey->n_squared);
	mpz_invert(a_1, u_e, pubKey->n_squared);
	mpz_mul(a_1, z_n, a_1);
	mpz_mod(a_1, a_1, pubKey->n_squared);

	// Calculate a_3
	mpz_powm(z_n, z_3, pubKey->n, pubKey->n_squared);
	mpz_powm(u_e, u_3, e_3, pubKey->n_squared);
	mpz_invert(a_3, u_e, pubKey->n_squared);
	mpz_mul(a_3, z_n, a_3);
	mpz_mod(a_3, a_3, pubKey->n_squared);
	
	// Calculate a_2 (for case m_i = m)
	mpz_powm(a_2, w, pubKey->n, pubKey->n_squared);

	// Concatenate a_k's and hash, making challenge string e_c
	mpz_t e_c;
	mpz_init(e_c);
	
	char * a_1s = mpz_get_str(NULL, 10, a_1);
	char * a_2s = mpz_get_str(NULL, 10, a_2);	
	char * a_3s = mpz_get_str(NULL, 10, a_3);
	char * str = malloc(sizeof(a_1s)/sizeof(a_1s[0]) + sizeof(a_2s)/sizeof(a_2s[0]) + sizeof(a_3s)/sizeof(a_3s[0]) + 1);	
	
	snprintf(str, sizeof(a_1s)/sizeof(a_1s[0]) + sizeof(a_2s)/sizeof(a_2s[0]) + sizeof(a_3s)/sizeof(a_3s[0]) + 1, "%s%s%s", a_1s, a_2s, a_3s);

	char * d = SHA256(str, strlen(str), 0);
	
	free(str);
	free(a_1s);
	free(a_2s);
	free(a_3s);
	
	char * encrypted;
	encrypted = malloc(65);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(encrypted + (i*2), "%02x", d[i]);
	}
	encrypted[64] = 0;
	mpz_set_str(e_c, encrypted, 16);
	
	free(encrypted);

	// Calculate e_2 (for m_i == m)
	mpz_t e_2;
	mpz_t two_raised_b;
	
	mpz_init(e_2);
	mpz_init(two_raised_b);	

	mpz_set_ui(two_raised_b, 2);
	mpz_pow_ui(two_raised_b, two_raised_b, 256 / 2 - 1);

	mpz_mod(e_c, e_c, two_raised_b);
	mpz_sub(e_2, e_c, e_1);
	mpz_sub(e_2, e_2, e_3);
	mpz_mod(e_2, e_2, two_raised_b);

	// Calculate z_2 (for m_i == m)
	mpz_t z_2;
	mpz_init(z_2);

	mpz_powm(z_2, c->r, e_2, pubKey->n);
	mpz_mul(z_2, w, z_2);
	mpz_mod(z_2, z_2, pubKey->n);

	// Voter's commit
	printf("Voter (prover) commits the following values to the verifier\n");
	gmp_printf("z_1: %Zd\n", z_1);
	gmp_printf("z_2: %Zd\n", z_2);
	gmp_printf("z_3: %Zd\n", z_3);
	gmp_printf("a_1: %Zd\n", a_1);
	gmp_printf("a_2: %Zd\n", a_2);
	gmp_printf("a_3: %Zd\n", a_3);
	gmp_printf("e_1: %Zd\n", e_1);
	gmp_printf("e_2: %Zd\n", e_2);
	gmp_printf("e_3: %Zd\n", e_3);
	gmp_printf("e_c: %Zd\n", e_c);
	printf("\n");

	// Now we verify
	// Sum up all e_k and confirm it equals e_c
	mpz_t sum;
	mpz_init(sum);
	
	mpz_add(sum, e_1, e_2);
	mpz_add(sum, sum, e_3);
	mpz_mod(sum, sum, two_raised_b);

	mpz_mod(e_c, e_c, two_raised_b);

	if (mpz_cmp(e_c, sum) == 0)
	{
		printf("Verified sum of e_k equals challenge string!\n"); 
		gmp_printf("sum: %Zd\n", sum);
		gmp_printf("e_c: %Zd\n", e_c);
	}
	else
	{
		printf("Prover failed the challenge. CHEATER!\n");
		gmp_printf("sum: %Zd\n", sum);
		gmp_printf("e_c: %Zd\n", e_c);
	}
	printf("\n");

	// Verify z_k^n = a_k * u_k^e_k mod n^2
	// use res for right side, z_n for left side
	mpz_powm(z_n, z_1, pubKey->n, pubKey->n_squared);
	mpz_powm(res, u_1, e_1, pubKey->n_squared);
	mpz_mul(res, a_1, res);
	mpz_mod(res, res, pubKey->n_squared);
	
	int verified = 1;

	if (mpz_cmp(z_n, res) == 0)
	{
		printf("Verified z_1 = a_1 * u_1!\n");
		gmp_printf("z_n: %Zd\n", z_n);
		gmp_printf("a_k * u_k: %Zd\n", res);
	}
	else
	{
		printf("Prover failed the challenge. CHEATER!\n");
		gmp_printf("z_n: %Zd\n", z_n);
		gmp_printf("a_k * u_k: %Zd\n", res);
		verified = 0;
	}	
	printf("\n");

	mpz_powm(z_n, z_2, pubKey->n, pubKey->n_squared);
	mpz_powm(res, u_2, e_2, pubKey->n_squared);
	mpz_mul(res, a_2, res);
	mpz_mod(res, res, pubKey->n_squared);
	
	if (mpz_cmp(z_n, res) == 0)
	{
		printf("Verified z_2 = a_2 * u_2!\n");
		gmp_printf("z_n: %Zd\n", z_n);
		gmp_printf("a_k * u_k: %Zd\n", res);
	}
	else
	{
		printf("Prover failed the challenge. CHEATER!\n");
		gmp_printf("z_n: %Zd\n", z_n);
		gmp_printf("a_k * u_k: %Zd\n", res);
		verified = 0;
	}
	printf("\n");

	mpz_powm(z_n, z_3, pubKey->n, pubKey->n_squared);
	mpz_powm(res, u_3, e_3, pubKey->n_squared);
	mpz_mul(res, a_3, res);
	mpz_mod(res, res, pubKey->n_squared);
	
	if (mpz_cmp(z_n, res) == 0)
	{
		printf("Verified z_3 = a_3 * u_3!\n");
		gmp_printf("z_n: %Zd\n", z_n);
		gmp_printf("a_k * u_k: %Zd\n", res);
	}
	else
	{
		printf("Prover failed the challenge. CHEATER!\n");
		gmp_printf("z_n: %Zd\n", z_n);
		gmp_printf("a_k * u_k: %Zd\n", res);
		verified = 0;
	}
	printf("\n");
	
	if (verified == 1)
		printf("This voter voted responsibly. Accept block\n");
	else
		printf("This voter cheated! Reject block\n");
	
	// Create an invalid ctxt2 and prove it's invalid
    
	// Cleaning up	
	paillier_freepubkey(pubKey);
	paillier_freeprvkey(secKey);
	paillier_freeplaintext(m);
	paillier_freeciphertext(c);
    
	return 0;
}
