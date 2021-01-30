#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>
#include <stdint.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>

#define NBUCKETS 8

int leftBounds[NBUCKETS + 1] = {0, 1, 3, 7, 15, 31, 63, 127, 257};
int global_headroom[6400];
static s32 shmid;
int *str;
int flag = 0;
int queue_index = 0;
int non_interesting_flag;
int files = 0;
int bufferaccess;
int leastBucket;
int pos;
int headroomForLeastBucket;
int crashFlag;
int non_retained = 0;
double time_spent = 0.0;
int leastHeadroom;
/*queue initilisation*/
int ch, k, x;
int f, r;
int size = 6400;
f = -1;
r = -1;
int f1 = -1;
int r1 = -1;
struct queue
{
	char testcase[164];
	int interesting_afl;
	int softDelete;
};
struct queue *afl_to_driver;

struct queue_driver_to_afl
{
	char testcase_name[164];
	int retained;
	int softDelete;
	int leastBucket;
	int leastHeadroom;
	int position;
	int bufferAccesses;
	int isCrash;
};
struct queue_driver_to_afl *driver_to_afl;

FILE *log;
FILE *log1;

int asan_invoke_counter = 0;

int main()
{
	int i;
	afl_to_driver = malloc(6400 * sizeof(struct queue));
	driver_to_afl = malloc(6400 * sizeof(struct queue_driver_to_afl));
	for (i = 0; i < 6400; i++)
	{
		global_headroom[i] = 255;
	}

	afl_startup();
}

void asan_startup(char testcase[164])
{

	crashFlag = 0;
	asan_invoke_counter++;
	char asan_command[264] = "./libxml2-v2.9.2-asan < ";
	strcat(asan_command, testcase);
	clock_t start = clock();
	int status = system(asan_command);
	clock_t end = clock();
	time_spent += (double)(end - start) / CLOCKS_PER_SEC;
	log1 = fopen("/home/temp/AFL/driver1.log", "a+");
	fprintf(log1, testcase);
	fprintf(log1, ":TIME:");
	char s[50];
	sprintf(s, "%f", (double)(end - start) / CLOCKS_PER_SEC);
	fprintf(log1, s);
	fprintf(log1, "\n");
	fprintf(log1, "ASAN INVOKED:");
	char asan_invoke[20];
	sprintf(asan_invoke, "%d", asan_invoke_counter);
	fprintf(log1, asan_invoke);
	fprintf(log1, "\n");
	fprintf(log1, "TOTAL TIME SPENT BY ASAN:");
	char total[20];
	sprintf(total, "%f", time_spent);
	fprintf(log1, total);
	fprintf(log1, "\n");
	fclose(log1);
	if (WEXITSTATUS(status) != 0)
	{
		crashFlag = 1;
	}
	flag = 0;
	setup_shm_asan(testcase);
}

void *afl_start(void *vargp)
{
	system("./afl-fuzz -i /home/temp/AFL/input/ -o /home/temp/AFL/sync_dir/ -M fuzzer01 /home/temp/AFL/./libxml2-v2.9.2-afl");
}

void *driver_continue(void *vargp)
{
	setup_shm_afl_to_driver();
}

void afl_startup()
{
	chdir("/home/temp/AFL/");
	pthread_t thread_id;
	pthread_t thread_id1;
	pthread_create(&thread_id, NULL, afl_start, NULL);
	pthread_create(&thread_id1, NULL, driver_continue, NULL);
	pthread_exit(NULL);
}

static void remove_shm(void)
{

	shmctl(shmid, IPC_RMID, NULL);
}

void setup_shm_asan(char testcase[164])
{

	key_t key = ftok("/home/temp", 65);
	shmid = shmget(key, 25600, 0666 | IPC_CREAT);
	str = (int *)shmat(shmid, (void *)0, 0);
	int j;

	//comparing headrooms with global headroom
	int i;
	int globalHeadroom;
	int programHeadroom;
	leastHeadroom = 255;
	bufferaccess = 0;
	leastBucket = 8;
	pos = 6400;
	for (i = 0; i < 6400; i++)
	{
		globalHeadroom = global_headroom[i];
		programHeadroom = *(str + i);

		if (globalHeadroom > programHeadroom)
		{
			int globalBucket = findBucket(globalHeadroom, leftBounds, 0, NBUCKETS);
			int programBucket = findBucket(programHeadroom, leftBounds, 0, NBUCKETS);
			if (!non_interesting_flag)
			{
				global_headroom[i] = programHeadroom;
			}
			if (globalBucket != programBucket)
			{
				if (!crashFlag)
				{
					flag = 1;
					bufferaccess = bufferaccess + 1;
					if (programBucket < leastBucket)
					{
						leastBucket = programBucket;
						if (leastHeadroom > programHeadroom)
						{
							pos = i;
							leastHeadroom = programHeadroom;
						}
					}
				}
			}
		}
	}

	if (!non_interesting_flag)
	{
		if (crashFlag)
		{
			char command2[300] = "cp ";
			strcat(strcat(command2, testcase), " /home/temp/AFL/crashes/");
			system(command2);
		}
		if (strstr(testcase, "sync:fuzzer02") != NULL)
		{
			flag = 2;
		}
		insert(testcase, driver_to_afl, &f1, &r1, size, flag);
	}
	else
	{
		if (flag)
		{
			char command[300] = "cp ";
			strcat(strcat(command, testcase), " /home/temp/AFL/sync_dir/fuzzer02/queue/");
			system(command);
			non_retained = non_retained + 1;
		}
		if (crashFlag)
		{
			char command1[300] = "cp ";
			strcat(strcat(command1, testcase), " /home/temp/AFL/crashes/");
			system(command1);
		}
	}
	//detach from shared memory
	shmdt(str);
	// destroy the shared memory
	shmctl(shmid, IPC_RMID, NULL);
}

void setup_shm_afl_to_driver()
{
	key_t key = ftok("/home/temp/IISC", 65);
	s32 shmid = shmget(key, 1100800, 0666 | IPC_CREAT);
	// shmat to attach to shared memory
	afl_to_driver = shmat(shmid, 0, 0);
	int j;
	setup_shm_driver_to_afl();
	send_to_asan(afl_to_driver, f, r, size);
}

void setup_shm_driver_to_afl()
{
	key_t key = ftok("/home/temp/IISC/llvm/projects", 65);
	int shmid = shmget(key, 1228800, 0666 | IPC_CREAT);
	driver_to_afl = shmat(shmid, (void *)0, 0);
}

/*insert into circular queue*/
int insert(char x[164], struct queue_driver_to_afl *q, int *f, int *r, int size, int retained)
{

	if (*f == (*r + 1) % size) //check for qfull
	{
		if ((q + *f)->softDelete)
		{
			goto COND;
		}
		else
		{
			return -1;
		}
	}
	else
	{
	COND:
		*r = (*r + 1) % size;
		strcpy((q + *r)->testcase_name, x);
		(q + *r)->retained = retained;
		(q + *r)->softDelete = 0;
		(q + *r)->leastBucket = leastBucket + 1;
		(q + *r)->position = pos;
		(q + *r)->bufferAccesses = bufferaccess;
		(q + *r)->isCrash = crashFlag;
		(q + *r)->leastHeadroom = leastHeadroom;
		if (retained)
		{
			log = fopen("/home/temp/AFL/driver.log", "a+");
			fprintf(log, x);
			fprintf(log, "\n");
			fclose(log);
		}

		if (*f == -1)
			*f = 0;
		return 1;
	}
}

/*pass testcase name to asan for headroom computation*/
void send_to_asan(struct queue *q, int f, int r, int size)
{

	int i;
	int non_interesting_counter = 0;
	while (queue_index < 6400)
	{
		if (strcmp((q + queue_index)->testcase, "") != 0)
		{
			asan_startup((q + queue_index)->testcase);
			queue_index = (queue_index + 1) % size;
			if ((queue_index % 20) == 0)
				non_interesting();
		}
		else
		{
			if (non_interesting_counter % 20 == 0)
				non_interesting();
			non_interesting_counter = non_interesting_counter + 1;
		}
	}
}

void non_interesting()
{

	DIR *folder;
	struct dirent *entry;
	folder = opendir("/home/temp/AFL/sample_dir/queue/");
	if (folder == NULL)
	{
		perror("Unable to read directory");
		return (1);
	}

	while ((entry = readdir(folder)))
	{
		if (!strncmp(entry->d_name, ".", 1))
			continue;
		files = files + 1;
		char file_path[164] = "/home/temp/AFL/sample_dir/queue/";
		strcat(file_path, entry->d_name);
		non_interesting_flag = 1;
		asan_startup(file_path);
		remove(file_path);
		if (files % 10 == 0)
			break;
	}

	closedir(folder);
	non_interesting_flag = 0;
}

// ~ Binary search. Should be O(log n)
int findBucket(int aNumber, int *leftBounds, int left, int right)
{
	int middle;

	if (aNumber < leftBounds[left] || leftBounds[right] <= aNumber) // cannot find
		return -1;
	if (left + 1 == right) // found
		return left;

	middle = left + (right - left) / 2;

	if (leftBounds[left] <= aNumber && aNumber < leftBounds[middle])
		return findBucket(aNumber, leftBounds, left, middle);
	else
		return findBucket(aNumber, leftBounds, middle, right);
}