#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <gmp.h>
#include "paillier.hpp"


int max(int a, int b)
{
	if (a < b)
		return b;
	else
		return a;
}

int max3(int a, int b, int c)
{
	return max(a, max(b, c));
}

int main(int argc, char **argv) 
{
	// Generate Keys
	paillier_pubkey_t* pubKey;
	paillier_prvkey_t* secKey;
	paillier_keygen(256, &pubKey, &secKey, paillier_get_rand_devurandom);

	printf("Public key generated:\n%s\n", paillier_pubkey_to_hex(pubKey));

	// Initialize random seed
	srand(time(0));

	// Generate a random plaintext
	int random = pow(100, rand() % 3);	
	printf("random number generated for vote: %d\n", random);
	paillier_plaintext_t* vote;	
	vote = paillier_plaintext_from_ui(random);	
	gmp_printf("Plaintext created: %Zd\n", vote);

	// Encrypt the first random plaintext
	paillier_ciphertext_t* enc_vote;
	enc_vote = paillier_enc(NULL, pubKey, vote, paillier_get_rand_devurandom);
	gmp_printf("Ciphertext created: %Zd\n", enc_vote);

	// Decrypt the first random plaintext
	paillier_plaintext_t* decrypted;
	decrypted = paillier_dec(NULL, pubKey, secKey, enc_vote);
	gmp_printf("Ciphertext decrypted: %Zd\n", decrypted);
	printf("\n");

	// Initialize the ciphertext that will hold the sum with an encryption of zero
    	paillier_ciphertext_t* encrypted_sum = paillier_create_enc_zero();

	// Sum the first vote
	paillier_mul(pubKey, encrypted_sum, encrypted_sum, enc_vote);
    	gmp_printf("Sum's ciphertext: %Zd\n", encrypted_sum);

	// Make 100 random valid votes 
	for (int i = 0; i < 99; i++)
	{
		random = pow(100, rand() % 3);
		printf("random number generated for vote: %d\n", random);
		vote = paillier_plaintext_from_ui(random);
		enc_vote = paillier_enc(NULL, pubKey, vote, paillier_get_rand_devurandom);
		gmp_printf("encrypted vote: %Zd\n", enc_vote);
		paillier_mul(pubKey, encrypted_sum, encrypted_sum, enc_vote);
		gmp_printf("running encrypted sum: %Zd\n", encrypted_sum); 
		printf("\n");
	}
	
	// Decrypt the sum of votes
	paillier_plaintext_t* dec;
    	dec = paillier_dec(NULL, pubKey, secKey, encrypted_sum);
    	gmp_printf("Decrypted sum of votes: %Zd\n", dec);
	
	// Convert decrypted plaintext to int
	int result = mpz_get_ui(dec->m);
	
	// Handle special cases
	if (result == 1000000)
		printf("Unanimous vote for increasing block size!\n");
	else if (result == 10000)
		printf("Unanimous vote for unchanging block size!\n");
	else if (result == 100)
		printf("Unanimous vote for decreasing block size!\n");
	else
	{
		// Print the result of the election
		int inc_votes = result / 10000;
		int unc_votes = (result % 10000) / 100;
		int dec_votes = result % 100;
	
		// Majority will default to unchange if maximal
		int majority = max3(unc_votes, inc_votes, dec_votes);

		// If tied, default to unchange
		if (inc_votes == dec_votes && inc_votes > unc_votes || 
		    dec_votes == unc_votes && dec_votes > inc_votes ||
		    inc_votes == unc_votes && inc_votes > dec_votes)
			printf("Consensus not reached -> unchanged block size!\n");
		else if (majority == unc_votes)
			printf("Majority voted to unchange block size!\n");		
		else if (majority == inc_votes)
			printf("Majority voted to increase block size!\n");
		else
			printf("Majority voted to decrease block size!\n");
	}

	// TODO: Show that a vote can't be invalid invoking zkps

	// Free memory
	paillier_freepubkey(pubKey);
	paillier_freeprvkey(secKey);
	paillier_freeplaintext(vote);
	paillier_freeplaintext(decrypted);
	paillier_freeciphertext(enc_vote);
	paillier_freeciphertext(encrypted_sum);

	return 0;
}
