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

	Encrypt and decrypt a message 

	enc = msg ^ e mod n
	dec = enc ^ d mod n

	*/

	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *n = BN_new();
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

	BIGNUM *d = BN_new();
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "010001");

	BIGNUM *msg = BN_new();
	BN_hex2bn(&msg, "4120746f7020736563726574"); // "A top secret!" in hexcode
	
	BIGNUM *enc = BN_new();
	BIGNUM *dec = BN_new();


	// Encryption
	BN_mod_exp(enc, msg, e, n, ctx);
	printBN("Encrypted Message = ", enc);

	// Decryption
	BN_mod_exp(dec, enc, d, n, ctx);
	printBN("Decrypted Message = ", dec);

	return 0;

}