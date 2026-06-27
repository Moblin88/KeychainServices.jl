#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Helper to create a CFString from a C string
static CFStringRef cfstr(const char *s) {
    return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}

// Helper to read a line from stdin
static char* read_line() {
    char *line = NULL;
    size_t len = 0;
    if (getline(&line, &len, stdin) == -1) {
        if (line) free(line);
        return NULL;
    }
    // Trim newline
    len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
    }
    return line;
}

// Stubs for future commands
void handle_query() {
    char *service_c = read_line();
    char *account_c = read_line();

    if (!service_c || !account_c) {
        if (service_c) free(service_c);
        if (account_c) free(account_c);
        fprintf(stdout, "%d\n", (int)errSecParam);
        fflush(stdout);
        return;
    }

    CFStringRef service = cfstr(service_c);
    CFStringRef account = cfstr(account_c);

    free(service_c);
    free(account_c);

    if (!service || !account) {
        if (service) CFRelease(service);
        if (account) CFRelease(account);
        fprintf(stdout, "%d\n", (int)errSecParam);
        fflush(stdout);
        return;
    }

    const void *query_keys[] = {
        kSecClass,
        kSecAttrService,
        kSecAttrAccount,
        kSecUseDataProtectionKeychain,
        kSecReturnData,
        kSecReturnAttributes,
    };
    const void *query_vals[] = {
        kSecClassGenericPassword,
        service,
        account,
        kCFBooleanTrue,
        kCFBooleanTrue,
        kCFBooleanTrue,
    };

    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault,
        query_keys,
        query_vals,
        (CFIndex)(sizeof(query_keys) / sizeof(query_keys[0])),
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    fprintf(stdout, "%d\n", (int)status);

    if (status == errSecSuccess) {
        CFDataRef secret_data = (CFDataRef)CFDictionaryGetValue((CFDictionaryRef)result, kSecValueData);
        if (secret_data) {
            CFIndex len = CFDataGetLength(secret_data);
            const UInt8 *bytes = CFDataGetBytePtr(secret_data);
            // Write length and then data, both base64 encoded for safety
            // For now, just print the secret directly for simplicity
            fwrite(bytes, 1, len, stdout);
        }
    }
    fprintf(stdout, "\n");
    fflush(stdout);

    if (result) CFRelease(result);
    if (query) CFRelease(query);
    CFRelease(account);
    CFRelease(service);
}

void handle_delete() {
    char *service_c = read_line();
    char *account_c = read_line();

    if (!service_c || !account_c) {
        if (service_c) free(service_c);
        if (account_c) free(account_c);
        fprintf(stdout, "%d\n", (int)errSecParam);
        fflush(stdout);
        return;
    }

    CFStringRef service = cfstr(service_c);
    CFStringRef account = cfstr(account_c);

    free(service_c);
    free(account_c);

    if (!service || !account) {
        if (service) CFRelease(service);
        if (account) CFRelease(account);
        fprintf(stdout, "%d\n", (int)errSecParam);
        fflush(stdout);
        return;
    }

    const void *del_keys[] = {
        kSecClass,
        kSecAttrService,
        kSecAttrAccount,
        kSecUseDataProtectionKeychain,
    };
    const void *del_vals[] = {
        kSecClassGenericPassword,
        service,
        account,
        kCFBooleanTrue,
    };

    CFDictionaryRef del_query = CFDictionaryCreate(
        kCFAllocatorDefault,
        del_keys,
        del_vals,
        (CFIndex)(sizeof(del_keys) / sizeof(del_keys[0])),
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemDelete(del_query);
    fprintf(stdout, "%d\n", (int)status);
    fflush(stdout);

    if (del_query) CFRelease(del_query);
    CFRelease(account);
    CFRelease(service);
}

void handle_add() {
    char *service_c = read_line();
    char *account_c = read_line();
    char *secret_c = read_line(); // For now, we read the secret as a simple string

    if (!service_c || !account_c || !secret_c) {
        if (service_c) free(service_c);
        if (account_c) free(account_c);
        if (secret_c) free(secret_c);
        fprintf(stdout, "%d\n", (int)errSecParam);
        fflush(stdout);
        return;
    }

    CFStringRef service = cfstr(service_c);
    CFStringRef account = cfstr(account_c);
    CFDataRef secret = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)secret_c, strlen(secret_c));

    free(service_c);
    free(account_c);
    free(secret_c);

    if (!service || !account || !secret) {
        if (service) CFRelease(service);
        if (account) CFRelease(account);
        if (secret) CFRelease(secret);
        fprintf(stdout, "%d\n", (int)errSecParam);
        fflush(stdout);
        return;
    }

    const void *add_keys[] = {
        kSecClass,
        kSecAttrService,
        kSecAttrAccount,
        kSecValueData,
        kSecUseDataProtectionKeychain,
    };
    const void *add_vals[] = {
        kSecClassGenericPassword,
        service,
        account,
        secret,
        kCFBooleanTrue,
    };

    CFDictionaryRef add_query = CFDictionaryCreate(
        kCFAllocatorDefault,
        add_keys,
        add_vals,
        (CFIndex)(sizeof(add_keys) / sizeof(add_keys[0])),
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemAdd(add_query, NULL);
    fprintf(stdout, "%d\n", (int)status);
    fflush(stdout);

    if (add_query) CFRelease(add_query);
    CFRelease(secret);
    CFRelease(account);
    CFRelease(service);
}


int main(void) {
    // Set line buffering for stdout to ensure timely communication
    setvbuf(stdout, NULL, _IOLBF, 0);

    while (1) {
        char *command = read_line();
        if (command == NULL || strcmp(command, "EXIT") == 0) {
            if (command) free(command);
            break;
        }

        if (strcmp(command, "ADD") == 0) {
            handle_add();
        } else if (strcmp(command, "QUERY") == 0) {
            handle_query();
        } else if (strcmp(command, "DELETE") == 0) {
            handle_delete();
        } else {
            // Unrecognized command
            fprintf(stdout, "%d\n", (int)errSecUnimplemented);
            fflush(stdout);
        }
        free(command);
    }

    return 0;
}