# include <stdio.h>
# include <openssl/bn.h>

// # define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
	char *number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main() {

	/*
	Generate public key (e, n) and private key (d)
	from the given values of p, q and e

	n = p*q
	d = modular inverse of totient ((p-1)*(q-1))

	*/

	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *p = BN_new();
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");

	BIGNUM *q = BN_new();
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");

	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "0D88C3");

	BIGNUM *n = BN_new();
	BN_mul(n, p, q, ctx);

	printBN("n = p * q = ", n);
		
	BIGNUM *totient = BN_new();
	BIGNUM *p_minus_one = BN_new();
	BIGNUM *q_minus_one = BN_new();
	BIGNUM *one = BN_new();

	BN_hex2bn(&one, "1");

	BN_sub(p_minus_one, p, one);
	BN_sub(q_minus_one, q, one);

	BN_mul(totient, p_minus_one, q_minus_one, ctx);
	printBN("Totient = (p-1) * (q-1) = ", totient);

	BIGNUM *d = BN_new();

	BN_mod_inverse(d, e, totient, ctx);
	printBN("Private key (e) = ", d);

	
	return 0;
}