#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

static int set_appdir_path(const char *name, const char *appdir, const char *suffix) {
    char value[8192];
    int length = snprintf(value, sizeof(value), "%s/%s", appdir, suffix);
    if (length < 0 || (size_t)length >= sizeof(value)) {
        fprintf(stderr, "ClamGuardian launcher: %s path is too long\n", name);
        return -1;
    }
    if (setenv(name, value, 1) != 0) {
        perror("ClamGuardian launcher: setenv");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *appdir = getenv("APPDIR");
    if (appdir == NULL || appdir[0] == '\0') {
        fprintf(stderr, "ClamGuardian launcher: APPDIR is not set\n");
        return 1;
    }

    struct utsname system_info;
    if (uname(&system_info) != 0) {
        perror("ClamGuardian launcher: uname");
        return 1;
    }

    const char *multiarch;
    if (strcmp(system_info.machine, "x86_64") == 0) {
        multiarch = "x86_64-linux-gnu";
    } else if (strcmp(system_info.machine, "aarch64") == 0) {
        multiarch = "aarch64-linux-gnu";
    } else {
        fprintf(stderr, "ClamGuardian launcher: unsupported architecture: %s\n",
                system_info.machine);
        return 1;
    }

    if (setenv("PYTHONHOME", appdir, 1) != 0) {
        perror("ClamGuardian launcher: setenv PYTHONHOME");
        return 1;
    }

    char pythonpath[8192];
    int length = snprintf(pythonpath, sizeof(pythonpath),
                          "%s/opt/python:%s/usr/lib/python3/dist-packages",
                          appdir, appdir);
    if (length < 0 || (size_t)length >= sizeof(pythonpath) ||
        setenv("PYTHONPATH", pythonpath, 1) != 0) {
        fprintf(stderr, "ClamGuardian launcher: cannot configure PYTHONPATH\n");
        return 1;
    }

    char gi_typelib_path[8192];
    length = snprintf(gi_typelib_path, sizeof(gi_typelib_path),
                      "%s/usr/lib/girepository-1.0:%s/usr/lib/%s/girepository-1.0",
                      appdir, appdir, multiarch);
    if (length < 0 || (size_t)length >= sizeof(gi_typelib_path) ||
        setenv("GI_TYPELIB_PATH", gi_typelib_path, 1) != 0) {
        fprintf(stderr, "ClamGuardian launcher: cannot configure GI_TYPELIB_PATH\n");
        return 1;
    }

    char library_path[8192];
    const char *existing_library_path = getenv("LD_LIBRARY_PATH");
    length = snprintf(library_path, sizeof(library_path),
                      "%s/usr/lib:%s/usr/lib/%s%s%s",
                      appdir, appdir, multiarch,
                      existing_library_path != NULL && existing_library_path[0] != '\0' ? ":" : "",
                      existing_library_path != NULL ? existing_library_path : "");
    if (length < 0 || (size_t)length >= sizeof(library_path) ||
        setenv("LD_LIBRARY_PATH", library_path, 1) != 0) {
        fprintf(stderr, "ClamGuardian launcher: cannot configure LD_LIBRARY_PATH\n");
        return 1;
    }

    if (set_appdir_path("GSETTINGS_SCHEMA_DIR", appdir,
                        "usr/share/glib-2.0/schemas") != 0) {
        return 1;
    }

    char xdg_data_dirs[8192];
    const char *existing_xdg_data_dirs = getenv("XDG_DATA_DIRS");
    length = snprintf(xdg_data_dirs, sizeof(xdg_data_dirs), "%s/usr/share%s%s",
                      appdir,
                      existing_xdg_data_dirs != NULL && existing_xdg_data_dirs[0] != '\0' ? ":" : "",
                      existing_xdg_data_dirs != NULL ? existing_xdg_data_dirs : "");
    if (length < 0 || (size_t)length >= sizeof(xdg_data_dirs) ||
        setenv("XDG_DATA_DIRS", xdg_data_dirs, 1) != 0) {
        fprintf(stderr, "ClamGuardian launcher: cannot configure XDG_DATA_DIRS\n");
        return 1;
    }

    char python[8192];
    length = snprintf(python, sizeof(python), "%s/usr/bin/python3", appdir);
    if (length < 0 || (size_t)length >= sizeof(python)) {
        fprintf(stderr, "ClamGuardian launcher: Python path is too long\n");
        return 1;
    }

    char **python_argv = calloc((size_t)argc + 3, sizeof(char *));
    if (python_argv == NULL) {
        perror("ClamGuardian launcher: calloc");
        return 1;
    }
    python_argv[0] = python;
    python_argv[1] = "-c";
    python_argv[2] = "from clamguardian.cli.main import main; raise SystemExit(main())";
    for (int index = 1; index < argc; index++) {
        python_argv[index + 2] = argv[index];
    }
    python_argv[argc + 2] = NULL;

    execv(python, python_argv);
    fprintf(stderr, "ClamGuardian launcher: cannot execute bundled Python: %s\n",
            strerror(errno));
    free(python_argv);
    return 1;
}
