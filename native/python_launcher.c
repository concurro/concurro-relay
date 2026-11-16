/* Start the bundled, upstream-signed Python framework by its relative path. */
#include <dlfcn.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char executable[PATH_MAX];
    char library[PATH_MAX];
    if (!realpath(argv[0], executable)) {
        perror("realpath");
        return 1;
    }
    snprintf(library, sizeof(library), "%s/../Python.framework/Versions/3.13/Python",
             dirname(executable));
    void *python = dlopen(library, RTLD_NOW | RTLD_GLOBAL);
    if (!python) {
        fputs(dlerror(), stderr);
        return 1;
    }
    int (*run)(int, char **) = dlsym(python, "Py_BytesMain");
    if (!run) {
        fputs(dlerror(), stderr);
        return 1;
    }
    return run(argc, argv);
}
