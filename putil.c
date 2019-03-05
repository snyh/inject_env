#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int do_wait(const char *name) {
  int status;
  if (wait(&status) == -1) {
    perror("wait");
    return -1;
  }
  if (WIFSTOPPED(status)) {
    if (WSTOPSIG(status) == SIGTRAP) {
      return 0;
    }
    printf("%s unexpectedly got status %s\n", name, strsignal(status));
    return -1;
  }
  printf("%s got unexpected status %d\n", name, status);
  return -1;
}

int singlestep(pid_t pid) {
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
    perror("PTRACE_SINGLESTEP");
    return -1;
  }
  return do_wait("PTRACE_SINGLESTEP");
}

// Update the text area of pid at the area starting at where. The data copied
// should be in the new_text buffer whose size is given by len. If old_text is
// not null, the original text data will be copied into it. Therefore old_text
// must have the same size as new_text.
int poke_text(pid_t pid, void *where, void *new_text, void *old_text,
              size_t len) {
  if (len % sizeof(void *) != 0) {
    printf("invalid len, not a multiple of %zd\n", sizeof(void *));
    return -1;
  }

  long poke_data;
  for (size_t copied = 0; copied < len; copied += sizeof(poke_data)) {
    memmove(&poke_data, new_text + copied, sizeof(poke_data));
    if (old_text != NULL) {
      errno = 0;
      long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
      if (peek_data == -1 && errno) {
        perror("PTRACE_PEEKTEXT");
        return -1;
      }
      memmove(old_text + copied, &peek_data, sizeof(peek_data));
    }
    if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
      perror("PTRACE_POKETEXT");
      return -1;
    }
  }
  return 0;
}

int attach_and_save_process(pid_t pid, struct user_regs_struct *old) {
  // attach to the process
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
    perror("PTRACE_ATTACH");
    return 1;
  }
  // wait for the process to actually stop
  if (waitpid(pid, 0, WSTOPPED) == -1) {
    perror("wait");
    return 1;
  }
  // save the register state of the remote process
  if (ptrace(PTRACE_GETREGS, pid, NULL, old)) {
    perror("PTRACE_GETREGS");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
  }
  return 0;
}
