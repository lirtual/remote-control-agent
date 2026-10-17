#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open __NR_pidfd_open
#endif

#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal __NR_pidfd_send_signal
#endif

/* Linux 6.9 added this pidfd_send_signal flag. */
#ifndef PIDFD_SIGNAL_PROCESS_GROUP
#define PIDFD_SIGNAL_PROCESS_GROUP (1U << 2)
#endif

static volatile sig_atomic_t signal_seen = 0;

static void handle_term(int signal_number) {
  (void)signal_number;
  signal_seen = 1;
}

static int signal_group(int pidfd, int signal_number) {
  return (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL,
                      PIDFD_SIGNAL_PROCESS_GROUP);
}

static int write_byte(int fd, char value) {
  ssize_t result;
  do {
    result = write(fd, &value, 1);
  } while (result < 0 && errno == EINTR);
  return result == 1 ? 0 : -1;
}

static int child_exit_code(int status) {
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 1;
}

int main(int argc, char **argv) {
  /* A detached, isolated process group checks the exact required syscall.
   * Signal 0 only checks permission/existence; it never delivers a signal. */
  const int probe = argc == 2 && strcmp(argv[1], "--probe") == 0;
  if ((!probe && argc != 3) || getpid() != getpgrp()) return 125;

  int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
  if (pidfd < 0 || signal_group(pidfd, 0) < 0) {
    if (pidfd >= 0) close(pidfd);
    if (!probe) write_byte(4, 'E');
    return 125;
  }
  if (probe) {
    close(pidfd);
    return 0;
  }

  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
    close(pidfd);
    write_byte(4, 'E');
    return 125;
  }

  struct sigaction term_action;
  memset(&term_action, 0, sizeof(term_action));
  term_action.sa_handler = handle_term;
  sigemptyset(&term_action.sa_mask);
  if (sigaction(SIGTERM, &term_action, NULL) < 0) {
    close(pidfd);
    write_byte(4, 'E');
    return 125;
  }

  int control_flags = fcntl(3, F_GETFD);
  if (control_flags < 0 || fcntl(3, F_SETFD, control_flags | FD_CLOEXEC) < 0) {
    close(pidfd);
    write_byte(4, 'E');
    return 125;
  }

  pid_t shell_pid = fork();
  if (shell_pid < 0) {
    close(pidfd);
    write_byte(4, 'E');
    return 125;
  }
  if (shell_pid == 0) {
    close(pidfd);
    close(3);
    close(4);
    char *const shell_argv[] = {argv[1], (char *)"-c", argv[2], NULL};
    execv(argv[1], shell_argv);
    _exit(127);
  }

  if (write_byte(4, 'R') < 0) {
    signal_group(pidfd, SIGKILL);
  }

  int child_exited = 0;
  int child_status = 0;
  for (;;) {
    if (!child_exited) {
      pid_t waited = waitpid(shell_pid, &child_status, WNOHANG);
      if (waited == shell_pid) child_exited = 1;
      else if (waited < 0 && errno != EINTR) child_exited = 1;
    }

    if (child_exited) {
      int descendants_remain = 0;
      for (;;) {
        int descendant_status = 0;
        pid_t waited = waitpid(-1, &descendant_status, WNOHANG);
        if (waited > 0) continue;
        if (waited < 0 && errno == EINTR) continue;
        if (waited == 0) descendants_remain = 1;
        else if (errno != ECHILD) descendants_remain = 1;
        break;
      }
      if (!descendants_remain) {
        close(pidfd);
        return child_exit_code(child_status);
      }
    }

    struct pollfd control = {.fd = 3, .events = POLLIN | POLLHUP};
    int polled = poll(&control, 1, 50);
    if (polled < 0 && errno == EINTR) continue;
    if (polled < 0) break;
    if (polled == 0) continue;
    if (control.revents & POLLIN) {
      char request = 0;
      ssize_t count;
      do {
        count = read(3, &request, 1);
      } while (count < 0 && errno == EINTR);
      if (count == 1 && request == 'T') {
        write_byte(4, signal_group(pidfd, SIGTERM) == 0 ? 'O' : 'E');
      } else if (count == 1 && request == 'K') {
        if (signal_group(pidfd, SIGKILL) < 0) write_byte(4, 'E');
      }
    }
    if (control.revents & (POLLHUP | POLLERR | POLLNVAL)) {
      /* The Agent cannot reattach after restart, so do not orphan the command. */
      if (signal_group(pidfd, SIGKILL) < 0) poll(NULL, 0, 50);
      continue;
    }
    if (signal_seen) signal_seen = 0;
  }

  close(pidfd);
  return 125;
}
