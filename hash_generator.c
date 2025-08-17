#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "sha256.h"

// 중요: 이 Salt 값은 반드시 main.c의 것과 동일해야 합니다.
const char* SECRET_SALT = "a1eph_nu11_is_running_n0w";

// Wide Character 용 텍스트 정규화 함수
void normalize_text_wide(wchar_t* text) {
    wchar_t* write_ptr = text;
    wchar_t* read_ptr = text;
    while (*read_ptr) {
        wchar_t c = *read_ptr;
        if (iswalnum(c)) {
            *write_ptr++ = towlower(c);
        }
        read_ptr++;
    }
    *write_ptr = L'\0';
}

// [추가됨] WinMain 함수가 main 함수를 호출하도록 하여 링크 오류를 해결
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    return main();
}


int main() {
    // 한글 입출력을 위한 로케일 설정
    _wsetlocale(LC_ALL, L"");

    wchar_t input_string_wide[256];
    
    wprintf(L"해시를 생성할 정답을 입력하세요: ");
    fgetws(input_string_wide, sizeof(input_string_wide) / sizeof(wchar_t), stdin);
    input_string_wide[wcscspn(input_string_wide, L"\r\n")] = 0; // 개행 문자 제거

    // 1. 정규화
    normalize_text_wide(input_string_wide);

    // 2. UTF-8로 변환
    char input_string_utf8[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, input_string_wide, -1, input_string_utf8, sizeof(input_string_utf8), NULL, NULL);

    // 3. Salt 추가
    char salted_string[1024];
    snprintf(salted_string, sizeof(salted_string), "%s%s", input_string_utf8, SECRET_SALT);

    // 4. SHA-256 해시 계산
    BYTE hash_result[32];
    char hash_hex_string[65];
    sha256_string(salted_string, hash_result);

    for(int i = 0; i < 32; i++) {
        sprintf(hash_hex_string + (i * 2), "%02x", hash_result[i]);
    }

    wprintf(L"\n--- 생성된 해시 값 ---\n");
    printf("%s\n", hash_hex_string);
    wprintf(L"-------------------------\n");
    wprintf(L"이 값을 main.c의 QUIZ_DATABASE에 복사하세요.\n");

    system("pause"); // 결과 확인을 위해 잠시 대기

    return 0;
}
