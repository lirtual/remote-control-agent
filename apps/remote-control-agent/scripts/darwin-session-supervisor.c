/*
 * #659 Darwin only: parent monitor + self-anchored private session/group.
 * A numeric PGID is NEVER signalled by the Node parent or the monitor.
 * Only the live anchor, whose own PID == SID == PGID, may signal its group.
 * An anchor whose owner pipe closes kills its group rather than orphaning it.
 * Detached/setsid descendants can escape the group: never promise their stop.
 */
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int byte(int fd, char c) {
  ssize_t n;
  do { n=write(fd,&c,1); } while (n<0 && errno==EINTR);
  return n==1 ? 0 : -1;
}
static int cloexec(int fd) {
  int flags=fcntl(fd,F_GETFD);
  return flags>=0 && fcntl(fd,F_SETFD,flags|FD_CLOEXEC)>=0 ? 0 : -1;
}
static int group_signal(int sig) {
  /* While anchor is alive, this PGID cannot be recycled. No stale PID kill. */
  if (getpid()!=getpgrp() || getsid(0)!=getpid()) return -1;
  return kill(-getpgrp(),sig);
}
static void group_kill(void) {
  if (group_signal(SIGKILL)<0) _exit(125);
  _exit(125); /* SIGKILL normally kills the anchor itself. */
}
static char result(int status) {
  if (WIFEXITED(status)) return (char)WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return (char)(128+WTERMSIG(status));
  return (char)125;
}
/* Runs in a fresh setsid child, which stays in its group until final cleanup. */
static void anchor(int requests, int responses, char **argv) {
  if (setsid()<0 || getpid()!=getpgrp() || getsid(0)!=getpid()) _exit(125);
  int exec_status[2];
  if (pipe(exec_status)<0 || cloexec(exec_status[1])<0) _exit(125);
  pid_t shell=fork();
  if (shell<0) _exit(125);
  if (shell==0) {
    close(exec_status[0]); close(requests); close(responses);
    /* A shell must be able to respond to TERM even though anchor ignores it. */
    struct sigaction action={0};
    action.sa_handler=SIG_DFL;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM,&action,NULL);
    char *const args[]={argv[1],(char*)"-c",argv[2],NULL};
    execv(argv[1],args);
    byte(exec_status[1],'E');
    _exit(127);
  }
  close(exec_status[1]);
  struct sigaction ignore={0};
  ignore.sa_handler=SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  if (sigaction(SIGTERM,&ignore,NULL)<0) group_kill();
  char exec_error=0;
  ssize_t n;
  do { n=read(exec_status[0],&exec_error,1); } while (n<0 && errno==EINTR);
  close(exec_status[0]);
  if (n!=0) { byte(responses,'E'); group_kill(); }
  if (byte(responses,'R')<0) group_kill();
  for (;;) {
    int status=0;
    pid_t waited=waitpid(shell,&status,WNOHANG);
    if (waited==shell) {
      char message[2]={'X',result(status)};
      /* The group is still anchored even if the shell exited. It is safe
       * to fence any same-group grandchildren before claiming exit. */
      if (write(responses,message,sizeof(message))!=(ssize_t)sizeof(message)) group_kill();
      group_kill();
    }
    if (waited<0 && errno!=EINTR) group_kill();
    fd_set ready;
    FD_ZERO(&ready); FD_SET(requests,&ready);
    struct timeval timeout={.tv_sec=0,.tv_usec=50000};
    int available=select(requests+1,&ready,NULL,NULL,&timeout);
    if (available<0 && errno==EINTR) continue;
    if (available<0) group_kill();
    if (available>0 && FD_ISSET(requests,&ready)) {
      char request=0;
      do { n=read(requests,&request,1); } while (n<0 && errno==EINTR);
      if (n!=1) group_kill(); /* EOF / lost monitor authority */
      if (request=='T') {
        if (byte(responses,group_signal(SIGTERM)==0?'O':'E')<0) group_kill();
      } else if (request=='K') group_kill();
      else group_kill();
    }
  }
}

int main(int argc,char **argv) {
  if (argc!=3 || getpid()!=getpgrp() || geteuid()==0 ||
      (strcmp(argv[1],"/bin/sh")!=0 && strcmp(argv[1],"/bin/zsh")!=0))
    return 125;
  int requests[2],responses[2];
  if (pipe(requests)<0 || pipe(responses)<0 ||
      cloexec(requests[0])<0 || cloexec(requests[1])<0 ||
      cloexec(responses[0])<0 || cloexec(responses[1])<0) return 125;
  pid_t child=fork();
  if (child<0) return 125;
  if (child==0) {
    close(requests[1]);close(responses[0]);
    close(3);close(4);
    anchor(requests[0],responses[1],argv);
    _exit(125);
  }
  close(requests[0]);close(responses[1]);
  /* Do not retain the shell's stdio pipes in the monitor. */
  close(0);close(1);close(2);
  int ready=0, have_exit=0, anchor_exited=0, anchor_status=0, response_closed=0;
  unsigned char exit_status=125;
  int awaiting_code=0;
  int channel_error=0;
  for (;;) {
    if (!anchor_exited) {
      pid_t exited=waitpid(child,&anchor_status,WNOHANG);
      if (exited==child) anchor_exited=1;
      else if (exited<0 && errno!=EINTR) return 125;
    }
    /* Drain the anchor's response pipe even AFTER waitpid reports its exit:
     * a short-lived shell may send X and die before the monitor polls. */
    if (anchor_exited && (have_exit || response_closed)) {
      if (ready && have_exit && WIFSIGNALED(anchor_status) &&
          WTERMSIG(anchor_status)==SIGKILL) return exit_status;
      return 125;
    }
    fd_set ready_fds;
    FD_ZERO(&ready_fds); FD_SET(3,&ready_fds); FD_SET(responses[0],&ready_fds);
    struct timeval timeout={.tv_sec=0,.tv_usec=50000};
    int biggest=3>responses[0]?3:responses[0];
    int count=select(biggest+1,&ready_fds,NULL,NULL,&timeout);
    if (count<0 && errno==EINTR) continue;
    if (count<0) {channel_error=1; response_closed=1;}
    if (count>0 && FD_ISSET(3,&ready_fds)) {
      char value=0;
      ssize_t n=read(3,&value,1);
      if (n!=1 || (value!='T' && value!='K') ||
          requests[1]<0 || byte(requests[1],value)<0) {
        if (requests[1]>=0) close(requests[1]);
        requests[1]=-1;channel_error=1;
      }
    }
    if (count>0 && FD_ISSET(responses[0],&ready_fds)) {
      char value=0;
      ssize_t n=read(responses[0],&value,1);
      if (n==0) response_closed=1;
      else if (n==1) {
        if (awaiting_code) {exit_status=(unsigned char)value;awaiting_code=0;have_exit=1;}
        else if (value=='X') awaiting_code=1;
        else if (value=='R' && !ready) {ready=1;if (byte(4,'R')<0) channel_error=1;}
        else if (value=='O' && ready) {if(byte(4,'O')<0) channel_error=1;}
        else {if(byte(4,'E')<0) channel_error=1;}
      } else if (n<0 && errno!=EINTR) response_closed=1;
    }
    /* Never substitute a PID-based kill when the owner's pipe broke.
     * Closing our anchor control is sufficient: anchor self-kills its group.
     */
    if (channel_error && requests[1]>=0) {
      close(requests[1]);requests[1]=-1;
    }
  }
}
