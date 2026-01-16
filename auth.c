#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <process.h>   // for _getpid() on Windows

#define OTP_ATTEMPTS 3
#define OTP_VALID_TIME 30

struct User {
    char username[50];
    char password[64]; // hashed password (hex string)
    char role[10];
};

/* ---------- ONE-WAY HASH (DJB2) ---------- */
void hash_password(const char *input, char *output) {
    unsigned long hash = 5381;
    int c;

    while ((c = *input++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    sprintf(output, "%lx", hash); // store as hex string
}

/* ---------- INPUT VALIDATION ---------- */
int is_valid_username(const char *u) {
    for (int i = 0; u[i]; i++) {
        if (!isalnum(u[i]) && u[i] != '_')
            return 0;
    }
    return 1;
}

/* ---------- LOGGING ---------- */
void log_event(const char *username, const char *status, const char *reason) {
    FILE *fp = fopen("logs.txt", "a");
    if (!fp) return;

    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strlen(ts) - 1] = '\0';

    fprintf(fp, "%s | %s | %s | %s\n",
            ts, username, status, reason);

    fclose(fp);
}

/* ---------- USER MANAGEMENT ---------- */
int user_exists(const char *username) {
    FILE *fp = fopen("users.txt", "r");
    if (!fp) return 0;

    struct User u;
    while (fscanf(fp, "%49s %63s %9s", u.username, u.password, u.role) == 3) {
        if (strcmp(u.username, username) == 0) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int register_user(const char *username, const char *password) {
    if (!is_valid_username(username)) return -2;
    if (strchr(password, ' ')) return -3;  // 🚨 prevent DB corruption
    if (user_exists(username)) return 0;

    char hashed[64];
    hash_password(password, hashed);

    FILE *fp = fopen("users.txt", "a");
    if (!fp) return -1;

    fprintf(fp, "%s %s user\n", username, hashed);
    fclose(fp);

    log_event(username, "SUCCESS", "ACCOUNT_CREATED");
    return 1;
}

int authenticate(const char *username, const char *password, struct User *out) {
    FILE *fp = fopen("users.txt", "r");
    if (!fp) return 0;

    char hashed[64];
    hash_password(password, hashed);

    struct User u;
    while (fscanf(fp, "%49s %63s %9s", u.username, u.password, u.role) == 3) {
        if (strcmp(u.username, username) == 0 &&
            strcmp(u.password, hashed) == 0) {
            *out = u;
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

/* ---------- OTP ---------- */
int generate_otp() {
    return rand() % 900000 + 100000;
}

void send_otp_to_file(int otp) {
    FILE *fp = fopen("simulated_email.txt", "w");
    if (!fp) return;
    fprintf(fp, "Your OTP is: %d\n", otp);
    fclose(fp);
}

/* ---------- MAIN ---------- */
int main() {
    char mode[20], username[50], password[50];
    struct User current;

    scanf("%19s", mode);

    /* REGISTER */
    if (strcmp(mode, "REGISTER") == 0) {
        scanf("%49s %49s", username, password);
        int r = register_user(username, password);

        if (r == 1)
            printf("STATUS:SUCCESS\n");
        else if (r == 0)
            printf("STATUS:FAIL\nREASON:USER_EXISTS\n");
        else if (r == -2)
            printf("STATUS:FAIL\nREASON:INVALID_USERNAME\n");
        else if (r == -3)
            printf("STATUS:FAIL\nREASON:INVALID_PASSWORD\n");
        else
            printf("STATUS:ERROR\n");

        return 0;
    }

    /* LOGIN */
    if (strcmp(mode, "LOGIN") != 0) {
        printf("STATUS:ERROR\n");
        return 0;
    }

    scanf("%49s %49s", username, password);

    if (!authenticate(username, password, &current)) {
        log_event(username, "FAIL", "BAD_CREDENTIALS");
        printf("STATUS:FAIL\n");
        return 0;
    }

    /* 🔐 Stronger RNG seed */
    srand((unsigned)time(NULL) ^ _getpid());

    int otp = generate_otp();
    send_otp_to_file(otp);

    printf("STATUS:OTP_REQUIRED\nROLE:%s\n", current.role);
    fflush(stdout);

    time_t start = time(NULL);
    int tries = 0, entered;

    while (tries < OTP_ATTEMPTS) {
        scanf("%d", &entered);

        if (time(NULL) - start > OTP_VALID_TIME) {
            log_event(username, "FAIL", "OTP_EXPIRED");
            printf("STATUS:FAIL\n");
            return 0;
        }

        if (entered == otp) {
            log_event(username, "SUCCESS", "LOGIN_SUCCESS");
            printf("STATUS:SUCCESS\nROLE:%s\n", current.role);
            return 0;
        }

        tries++;
        log_event(username, "RETRY", "WRONG_OTP");
        printf("STATUS:RETRY\n");
        fflush(stdout);
    }

    log_event(username, "FAIL", "OTP_ATTEMPTS_EXCEEDED");
    printf("STATUS:FAIL\n");
    return 0;
}
