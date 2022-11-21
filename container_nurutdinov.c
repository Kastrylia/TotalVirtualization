#include <iostream>
#include <sys/mman.h>
#include <sys/mount.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <fstream>
#include <fcntl.h>



void write_rule(const char* path, const char* value) {
  int fp = open(path, O_WRONLY | O_APPEND );
  write(fp, value, strlen(value));
  close(fp);
} 

#define CGROUP_FOLDER "/sys/fs/cgroup/pids/container/" 
#define concat(a,b) (a"" b)
void limit_process_creation() {
  mkdir( CGROUP_FOLDER, S_IRUSR | S_IWUSR);
  const char* pid  = std::to_string(getpid()).c_str();

  write_rule(concat(CGROUP_FOLDER, "pids.max"), "5"); 
  write_rule(concat(CGROUP_FOLDER, "notify_on_release"), "1"); 
  write_rule(concat(CGROUP_FOLDER, "cgroup.procs"), pid);
}

char* stack_memory() {
  const int stackSize = 65536;
  auto *stack = new (std::nothrow) char[stackSize];

  return stack+stackSize; 
}


void setup_variables() {
  clearenv();
  setenv("TERM", "xterm-256color", 0);
  setenv("PATH", "/bin/:/sbin/:usr/bin:/usr/sbin", 0);
}

template <typename Function>
void clone_process(Function&& function, int flags){
 clone(function, stack_memory(), flags, 0);

 wait(nullptr); 
} 

#define lambda(fn_body) [](void *args) ->int { fn_body; };
 
char *concat2(char *first, char *second)
{
   int firstSize = strlen(first);
   int secondSize = strlen(second);
   char *res = (char *)malloc(firstSize + secondSize + 1);
   strcpy(res, first);
   strcat(res, second);
   return res;
}

char *concat3(char *first, char *second, char *third)
{
   int firstSize = strlen(first);
   int secondSize = strlen(second);
   int thirdSize = strlen(second);
   char *res = (char *)malloc(firstSize + secondSize + thirdSize + 1);
   strcpy(res, first);
   strcat(res, second);
   strcat(res, third);
   return res;
}

int run_sh(){
  char *_args[] = {"/bin/sh", (char *)0 };
  execvp("/bin/sh", _args);
  return EXIT_SUCCESS;
}
 
int jail(void *args) {
  limit_process_creation();
  printf("child pid: %d\n", getpid());
  setup_variables();
  chroot("./root");
  chdir("/mnt");
  system("dd if=/dev/zero of=/image.img bs=512M count=10");
  fclose(fopen("loop_path", "w"));
  system("losetup --find --show /image.img >> loop_path");
  system("truncate -s-1 loop_path");
  int directory = open("loop_path", O_RDONLY); 
  int length = lseek(directory, 0, SEEK_END) - 1;
  char* loopPath = (char *)mmap(0, length, PROT_READ, MAP_PRIVATE, directory, 0);
  system(concat2("mkfs -t ext4 ", loopPath));
  system(concat3("mount ", loopPath, " /mnt"));
  mount("proc", "/proc", "proc", 0, 0); 
  auto runnable = lambda(run_sh()) clone_process(runnable, SIGCHLD);
  directory = open("loop_path", O_RDONLY); 
  length = lseek(directory, 0, SEEK_END) - 1;
  loopPath = (char *)mmap(0, length, PROT_READ, MAP_PRIVATE, directory, 0);
  system(concat2("umount ", loopPath));
  system(concat2("losetup --detach ", loopPath));
  umount("/proc");
  return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
  printf("parent pid: %d\n", getpid());
  clone_process(jail, CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD | CLONE_NEWNET);
  return EXIT_SUCCESS;
}