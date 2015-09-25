#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "driver/memory_cache.h"
#include "driver/wr/wr.h"
#include "driver/wr/wr_private.h"


enum request_type {
    SK_TYPE_DISCONNECT,
    SK_TYPE_READ,
    SK_TYPE_WRITE,
    SK_TYPE_IDREQ,
    SK_TYPE_VCPU,
};


struct request {
    uint8_t type;       // 0 quit, 1 read, 2 write, ... rest reserved
    uint64_t address;   // address to read from OR write to
    uint64_t length;    // number of bytes to read OR write
} __attribute__((packed));

struct wr_vcpu {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t msr_efer;
} __attribute__((packed));

status_t
wr_test(
    uint64_t id,
    const char *name)
{
    /* TODO */
    return VMI_SUCCESS;
}

static status_t
init_socket(
    wr_instance_t *wr)
{
    struct sockaddr_in address;
    int socket_fd;
    int ret;

    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        dbprint(VMI_DEBUG_WR, "--wr: socket() failed\n");
        return VMI_FAILURE;
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(WR_SK_INET_PORT);
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); //inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    if ((ret = connect(socket_fd, (struct sockaddr *)&address, sizeof(address))) != 0) {
        dbprint(VMI_DEBUG_WR, "--wr: connect() failed: ret=%d\n", ret);
        perror("connect failed. Error");
        return VMI_FAILURE;
    }

    wr->socket_fd = socket_fd;
    return VMI_SUCCESS;
}

static void
destroy_socket(
    wr_instance_t *wr)
{
    if (wr->socket_fd) {
        struct request req;

        req.type = 0;   // quit
        req.address = 0;
        req.length = 0;

        write(wr->socket_fd, &req, sizeof(struct request));
    }
}

void *
wr_get_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    // allocate one byte more than requested: we adopt the functionality of kvm
    // by letting the wr set the last byte of the buf to a value not equal to 0
    // if everything is fine.
    char *buf = safe_malloc(length + 1);
    struct request req;
    int nbytes = 0;
    wr_instance_t *wr = wr_get_instance(vmi);

    /**
     * TODO: must be implemented to acquire memory from guest
     */

    req.type = SK_TYPE_READ;
    req.address = (uint64_t) paddr;
    req.length = (uint64_t) length + 1;

    // request data
    dbprint(VMI_DEBUG_WR, "--wr: get_memory - requesting data.\n");
    nbytes = write(wr->socket_fd, &req, sizeof(struct request));
    if (nbytes != sizeof(struct request)) {
        goto error_exit;
    }

    // get the requested data from the wr
    dbprint(VMI_DEBUG_WR, "--wr: get_memory - reading data (size=%d).\n", (length+1));
    nbytes = read(wr->socket_fd, buf, length + 1);
    dbprint(VMI_DEBUG_WR, "--wr: get_memory - read %d bytes.\n", nbytes);
    if (nbytes != (length + 1)) {
        goto error_exit;
    }

    // the last byte represents the status of the operation - if the last byte
    // in the buffer is set, everything is fine.
    if (buf[length]) {
        return buf;
    }

error_exit:
    if (buf) {
        free(buf);
    }

    return NULL;
}

void
wr_release_memory(
    void *memory,
    size_t length)
{
    if (memory) {
        free(memory);
    }
}

status_t
wr_setup_live_mode(
    vmi_instance_t vmi)
{
    wr_instance_t *wr = wr_get_instance(vmi);
    dbprint(VMI_DEBUG_WR, "--wr: setup live mode\n");

    memory_cache_destroy(vmi);
    memory_cache_init(vmi, wr_get_memory, wr_release_memory, 0);

    return init_socket(wr);
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t
wr_init(
    vmi_instance_t vmi)
{
    wr_instance_t *wr = g_malloc0(sizeof(wr_instance_t));

    vmi->driver.driver_data = (void *)wr;

    return VMI_SUCCESS;
}

status_t
wr_init_vmi(
    vmi_instance_t vmi)
{
    wr_instance_t *wr = wr_get_instance(vmi);

    wr->socket_fd = 0;

    /**
     * TODO: request nr of vcpu's from WR
     */
    vmi->num_vcpus = 1;

    return wr_setup_live_mode(vmi);
}

void
wr_destroy(
    vmi_instance_t vmi)
{
    wr_instance_t *wr = wr_get_instance(vmi);

    destroy_socket(wr);
    free(wr);
}

uint64_t
wr_get_id(
    vmi_instance_t vmi)
{
    return wr_get_instance(vmi)->id;
}

void
wr_set_id(
    vmi_instance_t vmi,
    uint64_t domainid)
{
    wr_get_instance(vmi)->id = domainid;
}

status_t
wr_get_name(
    vmi_instance_t vmi,
    char **name)
{
    int nbytes;
    struct request req = {0};
    char *tmpname = NULL;
    wr_instance_t *wr = wr_get_instance(vmi);

    dbprint(VMI_DEBUG_WR, "--wr: wr_get_name.\n");

    tmpname = safe_malloc(42);
    if (tmpname == NULL) {
        return VMI_FAILURE;
    }

    memset((void *)tmpname, 0, 42);

    req.type = SK_TYPE_IDREQ;
    req.address = 0;
    req.length = 42;

    nbytes = write(wr->socket_fd, &req, sizeof(struct request));
    if (nbytes <= 0) {
        goto error_exit;
    }

    nbytes = read(wr->socket_fd, tmpname, 42);
    if (nbytes <= 0) {
        goto error_exit;
    }

    dbprint(VMI_DEBUG_WR, "--wr: wr_get_name name=%s.\n", tmpname);

    *name = strdup(tmpname);

    if (tmpname != NULL) {
        free(tmpname);
    }

    return VMI_SUCCESS;

error_exit:
    if (tmpname != NULL) {
        free(tmpname);
    }

    return VMI_FAILURE;
}

void
wr_set_name(
    vmi_instance_t vmi,
    const char *name)
{
    wr_get_instance(vmi)->name = strndup(name, 42);
}

status_t
wr_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address)
{
    /**
     * TODO: implementation missing...
     */
    *allocated_ram_size = 0x20000000; // fixed to 512MB for now
    *maximum_physical_address = *allocated_ram_size;
}

void *
wr_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;
    return memory_cache_insert(vmi, paddr);
}

status_t
wr_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu_id)
{
    status_t ret;
    int nbytes;
    struct wr_vcpu vcpu = {0};
    struct request req = {0};
    wr_instance_t *wr = wr_get_instance(vmi);

    ret = VMI_SUCCESS;

    dbprint(VMI_DEBUG_WR, "--wr: wr_get_vcpureg - reg=%d.\n", reg);

    req.type = SK_TYPE_VCPU;
    req.address = 0;
    req.length = sizeof(struct wr_vcpu);

    nbytes = write(wr->socket_fd, &req, sizeof(struct request));
    if (nbytes <= 0) {
        ret = VMI_FAILURE;
        goto exit;
    }

    nbytes = read(wr->socket_fd, &vcpu, sizeof(struct wr_vcpu));
    if (nbytes <= 0) {
        ret = VMI_FAILURE;
        goto exit;
    }

    switch(reg) {
    case RAX:
        *value = vcpu.rax;
        break;
    case RBX:
        *value = vcpu.rbx;
        break;
    case RCX:
        *value = vcpu.rcx;
        break;
    case RDX:
        *value = vcpu.rdx;
        break;
    case RBP:
        *value = vcpu.rbp;
        break;
    case RSI:
        *value = vcpu.rsi;
        break;
    case RDI:
        *value = vcpu.rdi;
        break;
    case RSP:
        *value = vcpu.rsp;
        break;
    case R8:
        *value = vcpu.r8;
        break;
    case R9:
        *value = vcpu.r9;
        break;
    case R10:
        *value = vcpu.r10;
        break;
    case R11:
        *value = vcpu.r11;
        break;
    case R12:
        *value = vcpu.r12;
        break;
    case R13:
        *value = vcpu.r13;
        break;
    case R14:
        *value = vcpu.r14;
        break;
    case R15:
        *value = vcpu.r15;
        break;
    case RIP:
        *value = vcpu.rip;
        break;
    case RFLAGS:
        *value = vcpu.rflags;
        break;
    case CR0:
        *value = vcpu.cr0;
        break;
    case CR2:
        *value = vcpu.cr2;
        break;
    case CR3:
        *value = vcpu.cr3;
        break;
    case CR4:
        *value = vcpu.cr4;
        break;
    case DR0:
        *value = vcpu.dr0;
        break;
    case DR1:
        *value = vcpu.dr1;
        break;
    case DR2:
        *value = vcpu.dr2;
        break;
    case DR3:
        *value = vcpu.dr3;
        break;
    case DR6:
        *value = vcpu.dr6;
        break;
    case DR7:
        *value = vcpu.dr7;
        break;
    case MSR_EFER:
        *value = vcpu.msr_efer;
        break;
    default:
        ret = VMI_FAILURE;
        break;
    }

exit:
    return ret;
}

int
wr_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}
