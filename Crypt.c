#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define ROTL16(x,y) ((uint16_t)((((uint16_t)(x))<<((y)&15)) | (((uint16_t)(x))>>(16-((y)&15)))))
#define ROTR16(x,y) ((uint16_t)((((uint16_t)(x))>>((y)&15)) | (((uint16_t)(x))<<(16-((y)&15)))))
#define ROTL32(x,y) ((uint32_t)((((uint32_t)(x))<<((y)&31)) | (((uint32_t)(x))>>(32-((y)&31)))))
#define ROTR32(x,y) ((uint32_t)((((uint32_t)(x))>>((y)&31)) | (((uint32_t)(x))<<(32-((y)&31)))))

struct Crypt
{
	uint32_t RC5S[26];
	uint32_t RC6S[84];
	uint32_t UserKey;
};

void RC5KeySetup(struct Crypt* crypt)
{
	unsigned char K[16] = { 0x3d, 0x63, 0xc5, 0xa3, 0x6d, 0x9a, 0xdb, 0xa5, 0xd1, 0xb2, 0x7a, 0x17, 0xb6, 0x56, 0x2c, 0xba };
	uint32_t A, B, L[4];
	int i, j, k, l = 0;
	char UserKeyBytes[4];
	UserKeyBytes[0] = crypt->UserKey & 0xFF;
	UserKeyBytes[1] = crypt->UserKey >> 8 & 0xFF;
	UserKeyBytes[2] = crypt->UserKey >> 16 & 0xFF;
	UserKeyBytes[3] = crypt->UserKey >> 24 & 0xFF;
	for (i = 15, L[3] = 0; i >= 0; i--)
	{
		L[i / 4] = (L[i / 4] << 8) + K[i] + UserKeyBytes[l];
		if (++l > 3) l = 0;
	}
	for (crypt->RC5S[0] = 0x5163, i = 1; i < 26; i++)
		crypt->RC5S[i] = crypt->RC5S[i - 1] + 0x79b9;
	for (A = B = i = j = k = 0; k < 26 * 3; k++, i = (i + 26 / 2) % 26, j = (j + 1) % 4)
	{
		A = crypt->RC5S[i] = ROTL32(crypt->RC5S[i] + (A + B), 3);
		B = L[j] = ROTL32(L[j] + (A + B), (A + B));
	}
}

void RC6KeySetup(struct Crypt* crypt)
{
	unsigned char K[32] = { 0x76, 0xb7, 0x4b, 0x98, 0x4c, 0x5b, 0xd5, 0xe3, 0xc1, 0x92, 0x33, 0x6a, 0x7b, 0xe6, 0xcc, 0xeb, 0x17, 0x9a, 0x77, 0xbc, 0x31, 0x5d, 0xe7, 0x39, 0xa9, 0x32, 0x54, 0x88, 0x66, 0xd3, 0xce, 0x43 };
	uint32_t A, B, L[8];
	int i, j, k, l = 0;
	char UserKeyBytes[4];
	UserKeyBytes[0] = crypt->UserKey & 0xFF;
	UserKeyBytes[1] = crypt->UserKey >> 8 & 0xFF;
	UserKeyBytes[2] = crypt->UserKey >> 16 & 0xFF;
	UserKeyBytes[3] = crypt->UserKey >> 24 & 0xFF;
	for (i = 31, L[7] = 0; i >= 0; i--)
	{
		L[i / 4] = (L[i / 4] << 8) + K[i] + UserKeyBytes[l];
		if (++l > 3) l = 0;
	}
	for (crypt->RC6S[0] = 0xb7e15163, i = 1; i < 84; i++)
		crypt->RC6S[i] = crypt->RC6S[i - 1] + 0x9e3779b9;
	for (A = B = i = j = k = 0; k < 84 * 3; k++, i = (i + 1) % 84, j = (j + 1) % 8)
	{
		A = crypt->RC6S[i] = ROTL32(crypt->RC6S[i] + A + B, 3);
		B = L[j] = ROTL32(L[j] + A + B, A + B);
	}
}

void KeySetup(struct Crypt* crypt, uint32_t key) {
	crypt->UserKey = key;
	RC5KeySetup(crypt);
	RC6KeySetup(crypt);
}

struct Crypt* CreateCryptHandle(uint32_t key)
{
	struct Crypt* crypt = (struct Crypt*)malloc(sizeof(struct Crypt));
	if (crypt == 0)
		return 0;
	KeySetup(crypt, key);
	return crypt;
}

void DestroyCryptHandle(struct Crypt* crypt)
{
	free(crypt);
}

void RC5Encrypt32(struct Crypt* crypt, const void* source, void* destination, int size)
{
	uint16_t A, B, * src = (uint16_t*)source, * dst = (uint16_t*)destination;
	int i, j;
	if (source != destination && size % 4) memcpy((char*)destination + size - size % 4, (char*)source + size - size % 4, size % 4);
	for (j = size / 4; j > 0; j--, src += 2, dst += 2)
	{
		A = src[0] + crypt->RC5S[0];
		B = src[1] + crypt->RC5S[1];
		for (i = 1; i <= 12; i++)
		{
			A = ROTL16(A ^ B, B) + crypt->RC5S[2 * i];
			B = ROTL16(B ^ A, A) + crypt->RC5S[2 * i + 1];
		}
		dst[0] = A ^ crypt->UserKey;
		dst[1] = B ^ crypt->UserKey;
	}
}

void RC5Decrypt32(struct Crypt* crypt, const void* source, void* destination, int size)
{
	uint16_t A, B, * src = (uint16_t*)source, * dst = (uint16_t*)destination;
	int i, j;
	if (source != destination && size % 4) memcpy((char*)destination + size - size % 4, (char*)source + size - size % 4, size % 4);
	for (j = size / 4; j > 0; j--, src += 2, dst += 2)
	{
		A = src[0] ^ crypt->UserKey;
		B = src[1] ^ crypt->UserKey;
		for (i = 12; i > 0; i--)
		{
			B = ROTR16(B - crypt->RC5S[2 * i + 1], A) ^ A;
			A = ROTR16(A - crypt->RC5S[2 * i], B) ^ B;
		}
		dst[0] = A - crypt->RC5S[0];
		dst[1] = B - crypt->RC5S[1];
	}
}

void RC5Encrypt64(struct Crypt* crypt, const void* source, void* destination, int size)
{
	uint32_t A, B, * src = (uint32_t*)source, * dst = (uint32_t*)destination;
	int i, j;
	for (j = size / 8; j > 0; j--, src += 2, dst += 2)
	{
		A = src[0] + crypt->RC5S[0];
		B = src[1] + crypt->RC5S[1];
		for (i = 1; i <= 12; i++)
		{
			A = ROTL32(A ^ B, B) + crypt->RC5S[2 * i];
			B = ROTL32(B ^ A, A) + crypt->RC5S[2 * i + 1];
		}
		dst[0] = A ^ crypt->UserKey;
		dst[1] = B ^ crypt->UserKey;
	}
	RC5Encrypt32(crypt, (uint32_t*)source + (size - size % 8) / 4, (uint32_t*)destination + (size - size % 8) / 4, size % 8);
}

void RC5Decrypt64(struct Crypt* crypt, const void* source, void* destination, int size)
{
	uint32_t A, B, * src = (uint32_t*)source, * dst = (uint32_t*)destination;
	int i, j;
	for (j = size / 8; j > 0; j--, src += 2, dst += 2)
	{
		A = src[0] ^ crypt->UserKey;
		B = src[1] ^ crypt->UserKey;
		for (i = 12; i > 0; i--)
		{
			B = ROTR32(B - crypt->RC5S[2 * i + 1], A) ^ A;
			A = ROTR32(A - crypt->RC5S[2 * i], B) ^ B;
		}
		dst[0] = A - crypt->RC5S[0];
		dst[1] = B - crypt->RC5S[1];
	}
	RC5Decrypt32(crypt, (uint32_t*)source + (size - size % 8) / 4, (uint32_t*)destination + (size - size % 8) / 4, size % 8);
}

void RC6Encrypt128(struct Crypt* crypt, const void* source, void* destination, int size)
{
	uint32_t A, B, C, D, t, u, x, * src = (uint32_t*)source, * dst = (uint32_t*)destination;
	int i, j;
	for (j = size / 16; j > 0; j--, src += 4, dst += 4)
	{
		A = src[0];
		B = src[1] + crypt->RC6S[0];
		C = src[2];
		D = src[3] + crypt->RC6S[1];
		for (i = 2; i <= 2 * 40; i += 2)
		{
			t = ROTL32(B * (2 * B + 1), 5);
			u = ROTL32(D * (2 * D + 1), 5);
			A = ROTL32(A ^ t, u) + crypt->RC6S[i];
			C = ROTL32(C ^ u, t) + crypt->RC6S[i + 1];
			x = A;
			A = B;
			B = C;
			C = D;
			D = x;
		}
		dst[0] = (A + crypt->RC6S[2 * 40 + 2]) ^ crypt->UserKey;
		dst[1] = B ^ crypt->UserKey;
		dst[2] = (C + crypt->RC6S[2 * 40 + 3]) ^ crypt->UserKey;
		dst[3] = D ^ crypt->UserKey;
	}
	RC5Encrypt64(crypt, (uint32_t*)source + (size - size % 16) / 4, (uint32_t*)destination + (size - size % 16) / 4, size % 16);
}

void RC6Decrypt128(struct Crypt* crypt, const void* source, void* destination, int size)
{
	uint32_t A, B, C, D, t, u, x, * src = (uint32_t*)source, * dst = (uint32_t*)destination;
	int i, j;
	for (j = size / 16; j > 0; j--, src += 4, dst += 4)
	{
		A = (src[0] ^ crypt->UserKey) - crypt->RC6S[2 * 40 + 2];
		B = src[1] ^ crypt->UserKey;
		C = (src[2] ^ crypt->UserKey) - crypt->RC6S[2 * 40 + 3];
		D = src[3] ^ crypt->UserKey;
		for (i = 2 * 40; i >= 2; i -= 2)
		{
			x = D;
			D = C;
			C = B;
			B = A;
			A = x;
			u = ROTL32(D * (2 * D + 1), 5);
			t = ROTL32(B * (2 * B + 1), 5);
			C = ROTR32(C - crypt->RC6S[i + 1], t) ^ u;
			A = ROTR32(A - crypt->RC6S[i], u) ^ t;
		}
		dst[0] = A;
		dst[1] = B - crypt->RC6S[0];
		dst[2] = C;
		dst[3] = D - crypt->RC6S[1];
	}
	RC5Decrypt64(crypt, (uint32_t*)source + (size - size % 16) / 4, (uint32_t*)destination + (size - size % 16) / 4, size % 16);
}
