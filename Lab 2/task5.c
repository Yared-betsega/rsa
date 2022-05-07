# include <stdio.h>
# include <openssl/bn.h>


void printBN(char *msg, BIGNUM * a)
{
	char *number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main() {

	/*

	Verifying a signature

	verification (msg) = sign ^ e mod n

	*/

	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *n = BN_new();
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

	BIGNUM *d = BN_new();
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "10001");

	BIGNUM *msg = BN_new();
	
	BIGNUM *sign = BN_new();
	BN_hex2bn(&sign, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

	// Verify sign
	BN_mod_exp(msg, sign, e, n, ctx);
	printBN("Message = ", msg);

	return 0;

}