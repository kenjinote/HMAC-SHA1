#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "shlwapi")
#pragma comment(lib, "crypt32")

#include <windows.h>
#include <shlwapi.h>

TCHAR szClassName[] = TEXT("Window");

BOOL GetHMACSHA1(LPCSTR basestring, LPCSTR key, LPSTR output, DWORD size)
{
	BOOL bRet = FALSE;

	DWORD keylen = lstrlenA(key);
	if (keylen >= 1024) {
		return FALSE;
	}

	struct {
		BLOBHEADER hdr;
		DWORD      len;
		BYTE       key[1024];
	} key_blob;

	HCRYPTPROV  hProv = NULL;
	HCRYPTHASH  hHash = NULL;
	HCRYPTKEY   hKey = NULL;
	HCRYPTHASH  hHmacHash = NULL;
	PBYTE       pbHash = NULL;
	DWORD       dwDataLen = 0;
	HMAC_INFO   HmacInfo;

	ZeroMemory(&HmacInfo, sizeof(HmacInfo));
	HmacInfo.HashAlgid = CALG_SHA1;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		goto ErrorExit;
	}

	ZeroMemory(&key_blob, sizeof(key_blob));

	key_blob.hdr.bType = PLAINTEXTKEYBLOB;
	key_blob.hdr.bVersion = CUR_BLOB_VERSION;
	key_blob.hdr.reserved = 0;
	key_blob.hdr.aiKeyAlg = CALG_RC2;
	key_blob.len = keylen;
	memcpy(key_blob.key, key, keylen);

	if (!CryptImportKey(hProv, (BYTE*)&key_blob, sizeof(key_blob), 0, CRYPT_IPSEC_HMAC_KEY, &hKey)) {
		goto ErrorExit;
	}

	if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHmacHash)) {
		goto ErrorExit;
	}

	if (!CryptSetHashParam(hHmacHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0)) {
		goto ErrorExit;
	}

	if (!CryptHashData(hHmacHash, (LPCBYTE)basestring, lstrlenA(basestring), 0)) {
		goto ErrorExit;
	}

	if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, NULL, &dwDataLen, 0)) {
		goto ErrorExit;
	}

	pbHash = (BYTE*)malloc(dwDataLen);
	if (NULL == pbHash) {
		goto ErrorExit;
	}

	if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0)) {
		goto ErrorExit;
	}

	DWORD dwSize = 0;
	CryptBinaryToStringA(pbHash, dwDataLen, CRYPT_STRING_BASE64, NULL, &dwSize);

	LPSTR lpszText = (LPSTR)GlobalAlloc(GPTR, dwSize);
	if (!lpszText) {
		goto ErrorExit;
	}

	CryptBinaryToStringA(pbHash, dwDataLen, CRYPT_STRING_BASE64, lpszText, &dwSize);
	LPSTR p = 0, q = 0;
	for (p = lpszText, q = lpszText; *p; p++) {
		if (*p != '\r' && *p != '\n') {
			*q++ = *p;
		}
	}
	*q = 0;
	(void)lstrcpynA(output, lpszText, size);
	GlobalFree(lpszText);
	bRet = TRUE;

ErrorExit:
	if (hHmacHash)
		CryptDestroyHash(hHmacHash);
	if (hKey)
		CryptDestroyKey(hKey);
	if (hHash)
		CryptDestroyHash(hHash);
	if (hProv)
		CryptReleaseContext(hProv, 0);
	if (pbHash)
		free(pbHash);

	return bRet;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hEdit1;
	static HWND hEdit2;
	static HWND hButton;
	static HWND hEdit3;
	switch (msg)
	{
	case WM_CREATE:
		hEdit1 = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit2 = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hButton = CreateWindow(TEXT("BUTTON"), TEXT("HMAC-SHA1"), WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hWnd, (HMENU)IDOK, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit3 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), 0, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hWnd, WM_DPICHANGED, 0, 0);
		break;
	case WM_SIZE:
		MoveWindow(hEdit1, 10, 10, 256, 32, TRUE);
		MoveWindow(hEdit2, 10, 50, 256, 32, TRUE);
		MoveWindow(hButton, 10, 90, 256, 32, TRUE);
		MoveWindow(hEdit3, 10, 130, 256, 32, TRUE);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK)
		{
			CHAR szText1[1024];
			CHAR szText2[1024];
			GetWindowTextA(hEdit1, szText1, _countof(szText1));
			GetWindowTextA(hEdit2, szText2, _countof(szText2));

			CHAR szText3[1024];

			GetHMACSHA1(szText1, szText2, szText3, _countof(szText3));

			SetWindowTextA(hEdit3, szText3);
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		0,
		hInstance,
		0,
		LoadCursor(0,IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClass(&wndclass);
	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("HMAC-SHA1"),
		WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
	);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}
